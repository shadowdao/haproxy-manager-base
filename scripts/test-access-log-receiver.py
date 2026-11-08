#!/usr/bin/env python3
"""Tests for scripts/haproxy-log-receiver.py (in-container access log).

Pins: one datagram == one line (PRI stripped, control chars neutralised),
the size cap (live file + N gzip generations, oldest dropped), a write error
(full disk / unwritable dir) drops lines without raising, and an end-to-end
datagram path through a real UNIX socket.

Running
-------
    python3 scripts/test-access-log-receiver.py
"""

import gzip
import importlib.util
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'haproxy_log_receiver', os.path.join(HERE, 'haproxy-log-receiver.py'))
rx = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rx)


class CleanLine(unittest.TestCase):

    def test_strips_pri_and_trailing_newline(self):
        self.assertEqual(rx.clean_line(b'<150>1 2026-11-08T00:00:00Z h haproxy 7 - - GET /\n'),
                         '1 2026-11-08T00:00:00Z h haproxy 7 - - GET /')

    def test_embedded_newlines_cannot_forge_lines(self):
        out = rx.clean_line(b'<150>1 x ua=evil\r\nFAKE 200 line\x1b[2J')
        self.assertNotIn('\n', out)
        self.assertNotIn('\r', out)
        self.assertNotIn('\x1b', out)
        self.assertIn('FAKE 200 line', out)

    def test_invalid_utf8_does_not_raise(self):
        self.assertIn('�', rx.clean_line(b'<150>1 \xff\xfe'))

    def test_non_pri_angle_bracket_kept(self):
        self.assertEqual(rx.clean_line(b'<html> x'), '<html> x')


class Rotation(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='hlr-test-')
        self.path = os.path.join(self.dir, 'access.log')

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _files(self):
        return sorted(os.listdir(self.dir))

    def test_size_cap_and_generations(self):
        max_bytes, backups = 4096, 3
        w = rx.RotatingWriter(self.path, max_bytes, backups)
        line = 'x' * 99  # 100 bytes with newline
        for i in range(1000):  # ~100 KB -> ~24 rotations
            w.write(f'{i:05d}' + line[5:])
        w.close()
        files = self._files()
        self.assertEqual(files, ['access.log', 'access.log.1.gz',
                                 'access.log.2.gz', 'access.log.3.gz'], files)
        self.assertLessEqual(os.path.getsize(self.path), max_bytes)
        total = sum(os.path.getsize(os.path.join(self.dir, f)) for f in files)
        self.assertLessEqual(total, (1 + backups) * max_bytes)
        # newest generation holds the lines written just before the live file
        with gzip.open(os.path.join(self.dir, 'access.log.1.gz'), 'rt') as fh:
            gen1 = fh.read().splitlines()
        with open(self.path) as fh:
            live = fh.read().splitlines()
        self.assertEqual(int(gen1[-1][:5]) + 1, int(live[0][:5]))
        self.assertEqual(live[-1][:5], '00999')
        for l in gen1:
            self.assertEqual(len(l), 99)

    def test_zero_backups_keeps_only_live_file(self):
        w = rx.RotatingWriter(self.path, 1024, 0)
        for _ in range(100):
            w.write('y' * 63)
        w.close()
        self.assertEqual(self._files(), ['access.log'])
        self.assertLessEqual(os.path.getsize(self.path), 1024)

    def test_reopens_existing_file_and_counts_its_size(self):
        with open(self.path, 'w') as fh:
            fh.write('z' * 1000 + '\n')
        w = rx.RotatingWriter(self.path, 1500, 2)
        w.write('a' * 600)  # 1001 + 601 > 1500 -> rotate first
        w.close()
        self.assertIn('access.log.1.gz', self._files())
        with open(self.path) as fh:
            self.assertEqual(fh.read(), 'a' * 600 + '\n')

    def test_write_error_drops_and_never_raises(self):
        blocker = os.path.join(self.dir, 'not-a-dir')
        with open(blocker, 'w') as fh:
            fh.write('')
        msgs = []
        w = rx.RotatingWriter(os.path.join(blocker, 'access.log'), 4096, 2, msgs.append)
        for _ in range(50):
            w.write('line')
        w.flush()
        w.close()
        self.assertEqual(w.dropped, 50)
        self.assertEqual(len(msgs), 1, msgs)  # rate-limited report


class EndToEnd(unittest.TestCase):

    def test_datagrams_become_lines(self):
        d = tempfile.mkdtemp(prefix='hlr-e2e-')
        try:
            sock_path = os.path.join(d, 'log.sock')
            log_path = os.path.join(d, 'logs', 'access.log')
            sock = rx.bind_socket(sock_path)
            self.assertEqual(os.stat(sock_path).st_mode & 0o777, 0o666)
            w = rx.RotatingWriter(log_path, 1 << 20, 2)
            stop = threading.Event()
            t = threading.Thread(target=rx.serve, args=(sock, w, stop), daemon=True)
            t.start()
            cl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            cl.setblocking(False)
            for i in range(20):
                msg = f'<150>1 t h haproxy 1 - - req {i} host=a.example cip=192.0.2.1'.encode()
                # The default net.unix.max_dgram_qlen is 10 per netns: a full
                # queue is EAGAIN (HAProxy drops the line); here, retry.
                for _ in range(100):
                    try:
                        cl.sendto(msg, sock_path)
                        break
                    except BlockingIOError:
                        time.sleep(0.01)
            deadline = time.time() + 5
            lines = []
            while time.time() < deadline:
                time.sleep(0.2)
                w.flush()
                if os.path.exists(log_path):
                    with open(log_path) as fh:
                        lines = fh.read().splitlines()
                if len(lines) == 20:
                    break
            stop.set()
            t.join(3)
            sock.close()
            w.close()
            self.assertEqual(len(lines), 20, lines)
            self.assertTrue(lines[0].startswith('1 t h haproxy 1 - - req 0 host=a.example'))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_sender_to_dead_receiver_fails_fast_nonblocking(self):
        """What HAProxy sees when the receiver is down: an immediate error,
        never a block (HAProxy then just counts a dropped log line)."""
        d = tempfile.mkdtemp(prefix='hlr-dead-')
        try:
            cl = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            cl.setblocking(False)
            start = time.monotonic()
            with self.assertRaises(OSError):
                cl.sendto(b'x', os.path.join(d, 'log.sock'))
            self.assertLess(time.monotonic() - start, 0.5)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
