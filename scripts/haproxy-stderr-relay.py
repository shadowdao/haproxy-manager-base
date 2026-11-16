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
* Rate-limited (token bucket, HAPROXY_STDERR_RELAY_BURST lines burst,
  HAPROXY_STDERR_RELAY_PER_MIN refill): a full thread dump (~150 lines) passes,
  a flapping-health-check storm is summarised ("N lines suppressed").
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
import shutil
import sys
import time

PREFIX = 'haproxy-stderr: '


def _env_num(name, default, cast=int):
    try:
        v = cast(os.environ.get(name, default))
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


class Relay:
    def __init__(self, path, out, burst, per_min, max_bytes, backups, clock=time.monotonic):
        self.path, self.out = path, out
        self.burst, self.per_min = burst, per_min
        self.max_bytes, self.backups = max_bytes, backups
        self.clock = clock
        self.tokens = float(burst)
        self.last = clock()
        self.suppressed = 0
        self.offset = None  # None = first pass: start at EOF (do not replay history)
        self.pending = ''

    def _take(self):
        now = self.clock()
        self.tokens = min(self.burst, self.tokens + (now - self.last) * self.per_min / 60.0)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    def _emit(self, line):
        if self._take():
            if self.suppressed:
                self.out.write(PREFIX + '[relay] %d line(s) suppressed by rate limit\n' % self.suppressed)
                self.suppressed = 0
            self.out.write(PREFIX + line + '\n')
        else:
            self.suppressed += 1

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
        for line in lines:
            line = ''.join(c if c >= ' ' or c == '\t' else ' ' for c in line).rstrip()
            if line:
                self._emit(line)
        self.out.flush()


def main():
    path = os.environ.get('HAPROXY_STDERR_LOG', '/var/log/haproxy/haproxy-stderr.log')
    relay = Relay(path, sys.stderr,
                  _env_num('HAPROXY_STDERR_RELAY_BURST', 400),
                  _env_num('HAPROXY_STDERR_RELAY_PER_MIN', 120),
                  _env_num('HAPROXY_STDERR_LOG_MAX_BYTES', 20 * 1024 * 1024),
                  _env_num('HAPROXY_STDERR_LOG_BACKUPS', 3),
                  )
    poll = _env_num('HAPROXY_STDERR_RELAY_POLL', 0.5, float)
    sys.stderr.write('haproxy-stderr-relay: following %s\n' % path)
    sys.stderr.flush()
    ticks = 0
    while True:
        try:
            relay.poll_once()
            ticks += 1
            if ticks % 120 == 0:
                relay.rotate_if_needed()
        except Exception as exc:  # never die: the supervisor loop restarts us anyway
            sys.stderr.write('haproxy-stderr-relay: %r\n' % exc)
        time.sleep(poll)


if __name__ == '__main__':
    main()
