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
* Crash evidence is NEVER rate-limited and NEVER summarised away: lines that
  match CRASH_RE (ha_panic, "Thread N is about to kill", "Current worker ...
  exited with code N", [ALERT], watchdog, "Thread N : id=", FATAL, SIGSEGV,
  SIGABRT, ...) and every line of a dump block (from a panic/watchdog header to
  the master's "All workers exited" line, bounded by
  DUMP_MAX_LINES and DUMP_MAX_SECONDS so a never-closed block cannot disable
  the limiter) are forwarded in full even when the bucket is empty. They go to
  STDERR.
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
DUMP_MAX_LINES = 3000    # a dump block never bypasses the limiter longer than this
DUMP_MAX_SECONDS = 30.0
SUMMARY_EVERY = 60.0

# Crash evidence: forwarded unconditionally (to stderr). Deliberately broad.
CRASH_RE = re.compile(
    r'ha_panic|is about to kill|Current worker|exited with code (?!0\b)|\[ALERT\]'
    r'|watchdog|^\s*\*?\s*Thread\s+\d+\s*:\s*id=|\bFATAL\b|segfault|SIGSEGV|SIGABRT'
    r'|unexpectedly died|bug in haproxy|exit-on-failure|All workers exited|^Hint: when reporting this bug',
    re.I)
# A dump block starts at one of these and runs until DUMP_END_RE (or a bound).
DUMP_START_RE = re.compile(
    r'ha_panic|is about to kill|watchdog|^\s*\*?\s*Thread\s+\d+\s*:\s*id=', re.I)
DUMP_END_RE = re.compile(r'All workers exited')
# A new start/reload cycle also closes a dump block.
CYCLE_RE = re.compile(r'Reloading HAProxy|Initializing new worker|Loading success')
# Routine per-start/reload noise: counted and collapsed, never rate-limited.
ROUTINE_RE = re.compile(
    r'Proxy \S+ stopped \(cumulated conns'
    r'|config\s*:\s*parsing \[[^\]]*\]\s*:'
    r"|Former worker \(\d+\) exited with code 0\b"
    r'|Reloading HAProxy|Initializing new worker|Loading success'
    r'|path to executable is|haproxy version is'
    r"|Can't load stats-file|'option forwardfor' ignored")


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

    def _end_dump(self, why=None):
        self.in_dump = False
        if why:
            self._write(self.err, '[relay] dump block closed: %s; rate limit applies again' % why)

    def _emit(self, line):
        now = self.clock()
        if self.in_dump:
            if (self.dump_lines >= DUMP_MAX_LINES) or (now - self.dump_since > DUMP_MAX_SECONDS):
                self._end_dump('bound reached (%d lines / %.0fs)' % (self.dump_lines, now - self.dump_since))
            elif CYCLE_RE.search(line) and not CRASH_RE.search(line):
                self._end_dump()
        if CRASH_RE.search(line) or self.in_dump:
            # crash evidence: bypasses the bucket, the collapse and the summary
            if not self.in_dump and DUMP_START_RE.search(line):
                self.in_dump, self.dump_lines, self.dump_since = True, 0, now
            if self.in_dump:
                self.dump_lines += 1
            self._write(self.err, line)
            if self.in_dump and DUMP_END_RE.search(line):
                self._end_dump()
            return
        if ROUTINE_RE.search(line):
            self.routine += 1
            if 'Loading success' in line:   # one summary per start/reload
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
