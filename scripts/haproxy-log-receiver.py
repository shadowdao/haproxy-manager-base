#!/usr/bin/env python3
"""In-container receiver for the HAProxy access log.

HAProxy sends its access log (`log <socket> ... format rfc5424`, hap_header.tpl)
as datagrams to a UNIX socket inside this container. This process is the only
reader: it writes one line per datagram to a size-capped, rotating file in the
haproxy-logs volume (default /var/log/haproxy/access.log).

Why it looks the way it does
----------------------------
* UNIX DATAGRAM socket, no network listener. Nothing is exposed on the host
  or on client-net (the old target was the host's rsyslog on the docker
  bridge, 172.18.0.1:514, which had no listener on the fleet).
* HAProxy never waits for us. Its log sends are non-blocking: a dead receiver
  (ECONNREFUSED/ENOENT) or a full socket buffer (EAGAIN) drops that line and
  HAProxy carries on. So a crash, a stall or a full disk here can only lose
  log lines, never slow or fail a request. That is the intended direction.
* Bounded on disk: the live file is rotated at MAX_BYTES and BACKUPS gzip
  generations are kept, so the worst case (incompressible data) is
  (1 + BACKUPS) * MAX_BYTES -- 5 * 40 MB = 200 MB by default. Compression runs
  in a thread so a rotation does not stall reading.
* A full disk (ENOSPC) or any write error drops lines and is reported at most
  once a minute; the file is reopened on the next attempt.
* Lines go to the FILE ONLY, never stdout: `docker logs haproxy-manager` is a
  source of WHP's AI log monitor, and a per-request firehose there would storm
  it (see the WHP note on audit/firehose sources). Our own status messages are
  rare and go to stderr.
* Control characters inside a datagram are replaced so one datagram is always
  exactly one line (a crafted header cannot forge extra log lines).

Supervised by start-up.sh (restart loop), started before HAProxy.

Environment
-----------
  HAPROXY_LOG_SOCKET       socket path   (default /var/lib/haproxy/log.sock)
  HAPROXY_ACCESS_LOG       file path     (default /var/log/haproxy/access.log)
  HAPROXY_ACCESS_LOG_MAX_BYTES  rotate size (default 41943040 = 40 MiB)
  HAPROXY_ACCESS_LOG_BACKUPS    gzip generations kept (default 4)
"""

import gzip
import os
import shutil
import socket
import sys
import threading
import time

# HAProxy sends at most `len` (2048) bytes per line; leave headroom.
MAX_DATAGRAM = 65535
FLUSH_INTERVAL = 1.0
ERROR_REPORT_INTERVAL = 60.0
# Kernel receive buffer to absorb bursts while a write is slow.
RCVBUF = 4 * 1024 * 1024

_CTRL = {c: ' ' for c in range(0x20) if c != 0x09}
_CTRL[0x7f] = ' '


def _env_int(name, default, minimum):
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        value = default
    return max(minimum, value)


def clean_line(datagram):
    """One datagram -> one log line (str, no trailing newline).

    Drops the RFC 5424 `<PRI>` prefix (constant for our single facility) and
    replaces any control character so the datagram cannot span lines.
    """
    text = datagram.decode('utf-8', 'replace').rstrip('\r\n\x00')
    if text.startswith('<'):
        end = text.find('>', 1, 6)
        if end > 0 and text[1:end].isdigit():
            text = text[end + 1:]
    return text.translate(_CTRL)


class RotatingWriter:
    """Size-capped writer: live file + `backups` gzip generations."""

    def __init__(self, path, max_bytes, backups, report=None):
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups
        self.report = report or (lambda msg: None)
        self.fh = None
        self.size = 0
        self.dirty = False
        self.dropped = 0
        self._compressor = None
        self._last_error = 0.0

    # -- file handling --------------------------------------------------
    def _open(self):
        os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
        self.fh = open(self.path, 'a', encoding='utf-8', buffering=65536)
        os.chmod(self.path, 0o640)
        self.size = self.fh.tell()

    def _error(self, what, exc):
        self.dropped += 1
        try:
            if self.fh:
                self.fh.close()
        except OSError:
            pass
        self.fh = None
        now = time.monotonic()
        if now - self._last_error >= ERROR_REPORT_INTERVAL:
            self._last_error = now
            self.report(f'{what} failed ({exc}); dropping access-log lines '
                        f'(dropped so far: {self.dropped})')

    def _gen(self, n):
        return f'{self.path}.{n}.gz'

    def _compress(self, src, dst):
        tmp = dst + '.tmp'
        try:
            with open(src, 'rb') as fin, gzip.open(tmp, 'wb', compresslevel=6) as fout:
                shutil.copyfileobj(fin, fout, 1024 * 1024)
            os.replace(tmp, dst)
            os.chmod(dst, 0o640)
        except OSError as exc:
            self.report(f'compressing {src} failed ({exc}); removing it to keep the size cap')
            for leftover in (tmp,):
                try:
                    os.unlink(leftover)
                except OSError:
                    pass
        finally:
            try:
                os.unlink(src)
            except OSError:
                pass

    def rotate(self):
        if self._compressor is not None:
            self._compressor.join()
            self._compressor = None
        if self.fh:
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None
        if self.backups <= 0:
            try:
                os.unlink(self.path)
            except OSError:
                pass
        else:
            try:
                os.unlink(self._gen(self.backups))
            except OSError:
                pass
            for n in range(self.backups - 1, 0, -1):
                if os.path.exists(self._gen(n)):
                    os.replace(self._gen(n), self._gen(n + 1))
            staged = f'{self.path}.1'
            if os.path.exists(self.path):
                os.replace(self.path, staged)
                self._compressor = threading.Thread(
                    target=self._compress, args=(staged, self._gen(1)), daemon=True)
                self._compressor.start()
        self.size = 0

    # -- public ---------------------------------------------------------
    def write(self, line):
        data = line + '\n'
        try:
            if self.fh is None:
                self._open()
            if self.size and self.size + len(data) > self.max_bytes:
                self.rotate()
                self._open()
            self.fh.write(data)
            self.size += len(data.encode('utf-8'))
            self.dirty = True
        except OSError as exc:
            self._error('writing ' + self.path, exc)

    def flush(self):
        if self.fh and self.dirty:
            try:
                self.fh.flush()
                self.dirty = False
            except OSError as exc:
                self._error('flushing ' + self.path, exc)

    def close(self):
        self.flush()
        if self._compressor is not None:
            self._compressor.join()
        if self.fh:
            try:
                self.fh.close()
            except OSError:
                pass


def bind_socket(path):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    except OSError:
        pass
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    try:
        os.unlink(path)  # stale socket from a previous (crashed) receiver
    except FileNotFoundError:
        pass
    sock.bind(path)
    # HAProxy's workers run as user haproxy (hap_header.tpl `user haproxy`).
    os.chmod(path, 0o666)
    sock.settimeout(FLUSH_INTERVAL)
    return sock


def serve(sock, writer, stop=None):
    last_flush = time.monotonic()
    while stop is None or not stop.is_set():
        try:
            datagram = sock.recv(MAX_DATAGRAM)
        except socket.timeout:
            datagram = None
        except OSError:
            if stop is not None and stop.is_set():
                break
            raise
        if datagram:
            writer.write(clean_line(datagram))
        now = time.monotonic()
        if now - last_flush >= FLUSH_INTERVAL:
            writer.flush()
            last_flush = now


def main():
    sock_path = os.environ.get('HAPROXY_LOG_SOCKET', '/var/lib/haproxy/log.sock')
    log_path = os.environ.get('HAPROXY_ACCESS_LOG', '/var/log/haproxy/access.log')
    max_bytes = _env_int('HAPROXY_ACCESS_LOG_MAX_BYTES', 40 * 1024 * 1024, 64 * 1024)
    backups = _env_int('HAPROXY_ACCESS_LOG_BACKUPS', 4, 0)

    def report(msg):
        sys.stderr.write(f'haproxy-log-receiver: {msg}\n')
        sys.stderr.flush()

    writer = RotatingWriter(log_path, max_bytes, backups, report)
    sock = bind_socket(sock_path)
    report(f'listening on {sock_path} -> {log_path} '
           f'(rotate at {max_bytes} bytes, keep {backups} gz)')
    try:
        serve(sock, writer)
    finally:
        writer.close()


if __name__ == '__main__':
    main()
