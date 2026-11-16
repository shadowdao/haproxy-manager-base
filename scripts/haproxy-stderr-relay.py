#!/usr/bin/env python3
"""Forward HAProxy's own stderr to the container's stderr, and bound the file.

Why
---
HAProxy's master stderr carries what the access log never will: `[ALERT]`
lines, "Current worker (N) exited with code 134", and the complete
ha_panic()/watchdog thread dump of a crash. haproxy_manager.spawn_haproxy_master()
launches `haproxy -W -db` with that stderr appended to HAPROXY_STDERR_LOG (in the
haproxy-logs volume, so it survives a container recreate). This process tails the
file and re-emits each line on ITS stderr, prefixed, which is the container's
stderr: `docker logs`, and through the docker logging driver the host journal
and Graylog.

Properties
----------
* Rare by nature: HAProxy only writes here on start/reload/server state
  changes/crashes. The per-request access log is NOT here (it goes to the
  receiver socket), so this does not feed the WHP AI monitor a firehose.
* Crash evidence bypasses the rate limit: lines that match the ANCHORED CRASH_RE
  ("[ALERT]    (PID) :", "Current worker (N) exited with code N", "Thread N is
  about to kill the process", "Thread N : id=0x..."; a keyword inside a URL/Host/
  server name never matches) and every line of a dump block (from a panic/watchdog header to
  the master's "All workers exited" line, bounded by
  DUMP_MAX_LINES / DUMP_MAX_SECONDS, then a DUMP_COOLDOWN before another block
  can open; blocks open only on the anchored "Thread N is about to kill" header)
  are forwarded in full even when the bucket is empty, within a total budget of
  CRASH_BUDGET lines per CRASH_WINDOW (after that they take the normal limiter
  and are counted in the suppressed summary). They go to STDERR.
* Routine reload noise (ROUTINE_RE: "Proxy X stopped (cumulated conns ...)",
  config "parsing [...]" warnings, "Former worker (N) exited with code 0",
  "Initializing new worker", "Loading success", ...) never touches the bucket:
  it is counted and collapsed into ONE "[relay] reload/start ok: N routine
  lines collapsed" line per reload (plus one on the minute tick for the late
  "Proxy stopped" lines). The full text stays in the stderr file.
* Everything else is rate-limited (token bucket, HAPROXY_STDERR_RELAY_BURST
  lines burst, HAPROXY_STDERR_RELAY_PER_MIN refill) with a per-minute
  "[relay] suppressed N lines" summary.
* Priority: the docker journald driver maps stdout -> PRIORITY 6 (info) and
  stderr -> PRIORITY 3 (err) and does NOT parse "<N>" prefixes. So benign
  lines (routine, rate-limited remainder, relay summaries) are written to
  STDOUT and crash evidence to STDERR: Graylog/journal can alert on priority.
* Bounded file: copy-truncate rotation at HAPROXY_STDERR_LOG_MAX_BYTES
  (default 20 MiB), HAPROXY_STDERR_LOG_BACKUPS generations (default 3).
  Truncating is safe because HAProxy's fd is O_APPEND.
* Never blocks or affects HAProxy: it only reads a file.

Environment
-----------
  HAPROXY_STDERR_LOG, HAPROXY_STDERR_RELAY_BURST (400), HAPROXY_STDERR_RELAY_PER_MIN (120),
  HAPROXY_STDERR_LOG_MAX_BYTES (20971520), HAPROXY_STDERR_LOG_BACKUPS (3),
  HAPROXY_STDERR_RELAY_POLL (0.5 s)
"""
import os
import re
import shutil
import sys
import time

PREFIX = 'haproxy-stderr: '
MAX_LINE = 2000          # longer lines are truncated (hostile / runaway output)
MAX_PENDING = 65536      # an unterminated line is force-emitted past this size
DUMP_MAX_LINES = 500     # a dump block never bypasses the limiter longer than this
DUMP_MAX_SECONDS = 30.0
SUMMARY_EVERY = 60.0

# Every pattern is ANCHORED to HAProxy's own message structure (captured from
# real 3.2 crashes): a keyword inside a request path / Host header / server
# name that HAProxy echoes into a warning can never match, because the line
# prefix "[ALERT]    (PID) :" is written by HAProxy itself.
# Crash evidence: forwarded (to stderr) without the bucket, within CRASH_BUDGET.
CRASH_RE = re.compile(
    r'^(?:'
    r'\[ALERT\]\s+\(\d+\)\s*:'                                         # any HAProxy alert
    r'|\[(?:NOTICE|WARNING)\]\s+\(\d+\)\s*:\s*(?:Current|Former) worker \(\d+\) exited with code (?!0\b)\d+'
    r'|\[(?:NOTICE|WARNING)\]\s+\(\d+\)\s*:\s*A worker process unexpectedly died'
    r'|\[(?:NOTICE|WARNING)\]\s+\(\d+\)\s*:\s*All workers exited\b'
    r'|Thread \d+ is about to kill the process'
    r'|\s*\*?\s*Thread \d+ : id=0x[0-9a-f]+ '
    r')')
# A dump block opens ONLY on the watchdog/panic header, and runs until DUMP_END_RE.
DUMP_START_RE = re.compile(r'^Thread \d+ is about to kill the process')
DUMP_END_RE = re.compile(r'^\[(?:NOTICE|WARNING)\]\s+\(\d+\)\s*:\s*All workers exited\b')
# A new start/reload cycle also closes a dump block.
CYCLE_RE = re.compile(r'^\[(?:NOTICE|WARNING)\]\s+\(\d+\)\s*:\s*(?:Reloading HAProxy|Initializing new worker|Loading success)')
# Routine per-start/reload noise: counted and collapsed, never rate-limited.
ROUTINE_RE = re.compile(
    r'^\[(?:NOTICE|WARNING)\]\s+\(\d+\)\s*:\s*(?:'
    r'Proxy \S+ stopped \(cumulated conns'
    r'|config\s*:\s*parsing \[[^\]]*\]\s*:'
    r'|Former worker \(\d+\) exited with code 0\b'
    r'|Reloading HAProxy|Initializing new worker|Loading success'
    r'|path to executable is|haproxy version is'
    r"|config: Can't load stats-file|'option forwardfor' ignored)")
LOADED_RE = re.compile(r'^\[(?:NOTICE|WARNING)\]\s+\(\d+\)\s*:\s*Loading success')
# Total exemption budget: even real-looking evidence cannot flood without bound.
CRASH_BUDGET = 1000        # exempt lines per window (a 4-thread dump is ~70)
CRASH_WINDOW = 600.0       # seconds
DUMP_COOLDOWN = 60.0       # after a BOUND closes a block, no new block opens for this long


def _env_num(name, default, cast=int):
    try:
        v = cast(os.environ.get(name, default))
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


class Relay:
    def __init__(self, path, out, burst, per_min, max_bytes, backups, clock=time.monotonic, err=None):
        self.path = path
        self.out = out                      # benign lines  (docker journald: PRIORITY 6)
        self.err = err if err is not None else out   # crash lines (PRIORITY 3)
        self.burst, self.per_min = burst, per_min
        self.max_bytes, self.backups = max_bytes, backups
        self.clock = clock
        self.tokens = float(burst)
        self.last = clock()
        self.suppressed = 0
        self.routine = 0                    # collapsed routine lines since the last summary
        self.summary_at = clock()
        self.in_dump = False
        self.dump_lines = 0
        self.dump_since = 0.0
        self.cooldown_until = 0.0
        self.budget_left = CRASH_BUDGET
        self.window_start = clock()
        self.offset = None  # None = first pass: start at EOF (do not replay history)
        self.pending = ''
        self._last_stream = None

    def _take(self):
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.per_min / 60.0)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    def _write(self, stream, text):
        # keep the two streams in emission order: flush the other one first
        if self._last_stream is not None and self._last_stream is not stream:
            self._last_stream.flush()
        stream.write(PREFIX + text + '\n')
        self._last_stream = stream

    def _flush_all(self):
        for st in {id(self.out): self.out, id(self.err): self.err}.values():
            try:
                st.flush()
            except Exception:
                pass

    def _summaries(self, force=False):
        """Per-minute summary of what the limiter / collapse withheld."""
        now = self.clock()
        if not force and now - self.summary_at < SUMMARY_EVERY:
            return
        self.summary_at = now
        if self.routine:
            self._write(self.out, '[relay] %d routine reload/start lines collapsed (full text in the stderr file)'
                        % self.routine)
            self.routine = 0
        if self.suppressed:
            self._write(self.out, '[relay] suppressed %d lines (rate limit; full text in the stderr file)'
                        % self.suppressed)
            self.suppressed = 0

    def _budget(self, now):
        """Take one unit of the crash-evidence budget; False once the window's budget is spent."""
        if now - self.window_start >= CRASH_WINDOW:
            self.window_start, self.budget_left = now, CRASH_BUDGET
        if self.budget_left > 0:
            self.budget_left -= 1
            return True
        return False

    def _end_dump(self, now, why=None):
        self.in_dump = False
        if why:   # closed by a bound, not by the master's end line: no re-arming for a while
            self.cooldown_until = now + DUMP_COOLDOWN
            self._write(self.err, '[relay] dump block closed: %s; rate limit applies again' % why)

    def _emit(self, line):
        now = self.clock()
        if self.in_dump:
            if (self.dump_lines >= DUMP_MAX_LINES) or (now - self.dump_since > DUMP_MAX_SECONDS):
                self._end_dump(now, 'bound reached (%d lines / %.0fs)' % (self.dump_lines, now - self.dump_since))
            elif CYCLE_RE.match(line):
                self._end_dump(now)
        if self.in_dump or CRASH_RE.match(line):
            if self._budget(now):
                # crash evidence: bypasses the bucket, the collapse and the summary
                if not self.in_dump and DUMP_START_RE.match(line) and now >= self.cooldown_until:
                    self.in_dump, self.dump_lines, self.dump_since = True, 0, now
                if self.in_dump:
                    self.dump_lines += 1
                self._write(self.err, line)
                if self.in_dump and DUMP_END_RE.match(line):
                    self._end_dump(now)
                return
            if self.in_dump:   # budget spent mid-block: the normal limiter takes over
                self._end_dump(now, 'crash-evidence budget (%d lines/%.0fs) spent' % (CRASH_BUDGET, CRASH_WINDOW))
        if ROUTINE_RE.match(line):
            self.routine += 1
            if LOADED_RE.match(line):   # one summary per start/reload
                self._write(self.out, '[relay] reload/start ok: %d routine lines collapsed (full text in the stderr file)'
                            % self.routine)
                self.routine = 0
            self._summaries()
            return
        if self._take():
            self._write(self.out, line)
        else:
            self.suppressed += 1
        self._summaries()

    @staticmethod
    def _clean(line):
        line = ''.join(c if c >= ' ' or c == '\t' else ' ' for c in line).rstrip()
        if len(line) > MAX_LINE:
            line = line[:MAX_LINE] + ' [relay: line truncated, %d chars]' % len(line)
        return line

    def rotate_if_needed(self):
        try:
            if os.path.getsize(self.path) <= self.max_bytes:
                return
            for i in range(self.backups, 1, -1):
                src = '%s.%d' % (self.path, i - 1)
                if os.path.exists(src):
                    os.replace(src, '%s.%d' % (self.path, i))
            shutil.copyfile(self.path, self.path + '.1')
            with open(self.path, 'r+b') as fh:
                fh.truncate(0)
            self.offset = 0
        except OSError as exc:
            sys.stderr.write('haproxy-stderr-relay: rotate failed: %s\n' % exc)

    def poll_once(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            if self.offset is None:
                self.offset = 0  # file not created yet: whatever appears is new
            return
        if self.offset is None:
            self.offset = size
            return
        if size < self.offset:  # truncated by someone else
            self.offset = 0
        if size == self.offset:
            return
        with open(self.path, 'rb') as fh:
            fh.seek(self.offset)
            chunk = fh.read(1 << 20)
        self.offset += len(chunk)
        text = self.pending + chunk.decode('utf-8', 'replace')
        lines = text.split('\n')
        self.pending = lines.pop()  # incomplete trailing line stays buffered
        if len(self.pending) > MAX_PENDING:  # hostile / runaway unterminated line
            lines.append(self.pending)
            self.pending = ''
        for line in lines:
            line = self._clean(line)
            if line:
                self._emit(line)
        self._summaries()
        self._flush_all()

    def tick(self):
        """Idle-time housekeeping: emit the per-minute summaries even when no line arrives."""
        self._summaries()
        self._flush_all()


def main():
    path = os.environ.get('HAPROXY_STDERR_LOG', '/var/log/haproxy/haproxy-stderr.log')
    relay = Relay(path, sys.stdout,
                  _env_num('HAPROXY_STDERR_RELAY_BURST', 400),
                  _env_num('HAPROXY_STDERR_RELAY_PER_MIN', 120),
                  _env_num('HAPROXY_STDERR_LOG_MAX_BYTES', 20 * 1024 * 1024),
                  _env_num('HAPROXY_STDERR_LOG_BACKUPS', 3),
                  err=sys.stderr)
    poll = _env_num('HAPROXY_STDERR_RELAY_POLL', 0.5, float)
    sys.stdout.write('haproxy-stderr-relay: following %s\n' % path)
    sys.stdout.flush()
    ticks = 0
    while True:
        try:
            relay.poll_once()
            relay.tick()
            ticks += 1
            if ticks % 120 == 0:
                relay.rotate_if_needed()
        except Exception as exc:  # never die: the supervisor loop restarts us anyway
            sys.stderr.write('haproxy-stderr-relay: %r\n' % exc)
        time.sleep(poll)


if __name__ == '__main__':
    main()
