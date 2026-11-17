#!/usr/bin/env python3
"""Tests: gunicorn access logging must not flood the container's stdout.

Context: with the journald docker log driver every stdout line is a journal
entry (default rate limit 10000 msgs/30 s per service could suppress crash-dump
lines) and, via Graylog, a stored message. start-up.sh therefore gives :8080 no
access log and sends :8000's to a bounded FILE; gunicorn errors stay on stderr.

Pins (static, from start-up.sh):
  * no gunicorn invocation uses `--access-logfile -`;
  * the :8080 invocation has no --access-logfile at all;
  * the :8000 invocation logs access to ${API_ACCESS_LOG}, errors to `-`.
Pins (live, REAL gunicorn, same flag shapes):
  * a burst of default-page requests (no access log) writes ZERO lines to
    stdout and none to stderr;
  * a burst of API requests writes ZERO stdout lines, the access file receives
    them, and a handler exception still reaches STDERR (error logging intact);
  * scripts/gunicorn-access-rotate.py keeps the file bounded (copy-truncate,
    backups capped, rotated copy mode 0640).
Runs in the Docker build gate.
"""
import importlib.util
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    import gunicorn  # noqa: F401
except ImportError:
    sys.stderr.write('SKIP: gunicorn not installed\n')
    raise SystemExit(77)

spec = importlib.util.spec_from_file_location('rot', os.path.join(HERE, 'gunicorn-access-rotate.py'))
rot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rot)

APP = textwrap.dedent('''\
    def app(environ, start_response):
        if environ['PATH_INFO'] == '/boom':
            raise RuntimeError('handler-exploded')
        start_response('200 OK', [('Content-Type', 'text/plain'), ('Content-Length', '2')])
        return [b'ok']
''')


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start_script():
    with open(os.path.join(HERE, 'start-up.sh')) as fh:
        return fh.read()


class StaticFlags(unittest.TestCase):
    def setUp(self):
        self.src = start_script()
        # Each invocation = from "gunicorn \" to its app target line.
        self.inv = re.findall(r'^(?:exec )?gunicorn \\\n(?:.*\\\n)*?.*haproxy_manager:\w+.*$', self.src, re.M)

    def test_two_invocations(self):
        self.assertEqual(len(self.inv), 2, self.inv)

    def test_no_stdout_access_log(self):
        for i in self.inv:
            self.assertNotRegex(i, r'--access-logfile\s+-(\s|$)')

    def test_default_page_has_no_access_log(self):
        d = [i for i in self.inv if '0.0.0.0:8080' in i]
        self.assertEqual(len(d), 1)
        self.assertNotIn('--access-logfile', d[0])
        self.assertIn('--error-logfile -', d[0])

    def test_api_access_log_is_a_file(self):
        a = [i for i in self.inv if '0.0.0.0:8000' in i]
        self.assertEqual(len(a), 1)
        self.assertIn('--access-logfile "${API_ACCESS_LOG}"', a[0])
        self.assertIn('--error-logfile -', a[0])

    def test_rotator_started(self):
        self.assertIn('gunicorn-access-rotate.py', self.src)


class Live(unittest.TestCase):
    N_DEFAULT = 300
    N_API = 100

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='gunicorn-access-')
        with open(os.path.join(self.dir, 'tapp.py'), 'w') as fh:
            fh.write(APP)

    def run_gunicorn(self, extra, n, boom=False):
        port = free_port()
        out = open(os.path.join(self.dir, 'out-%d' % port), 'w+')
        err = open(os.path.join(self.dir, 'err-%d' % port), 'w+')
        p = subprocess.Popen(
            [sys.executable, '-m', 'gunicorn', '--bind', '127.0.0.1:%d' % port,
             '--workers', '1', '--threads', '4', '--error-logfile', '-', '--log-level', 'info',
             '--pythonpath', self.dir] + extra + ['tapp:app'],
            stdout=out, stderr=err)
        try:
            for _ in range(100):
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/' % port, timeout=2).read()
                    break
                except Exception:
                    time.sleep(0.2)
            for _ in range(n):
                urllib.request.urlopen('http://127.0.0.1:%d/x' % port, timeout=5).read()
            if boom:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/boom' % port, timeout=5).read()
                except Exception:
                    pass
            time.sleep(0.5)
        finally:
            p.terminate()
            p.wait(10)
        out.seek(0)
        err.seek(0)
        o, e = out.read(), err.read()
        out.close()
        err.close()
        return o, e

    def test_default_page_burst_is_silent(self):
        out, err = self.run_gunicorn([], self.N_DEFAULT)
        self.assertEqual(out, '', 'access logging leaked to stdout: %r' % out[:200])
        self.assertNotIn('GET /x', err)

    def test_api_burst_goes_to_file_not_stdout_and_errors_stay_on_stderr(self):
        path = os.path.join(self.dir, 'api-access.log')
        open(path, 'w').close()
        out, err = self.run_gunicorn(['--access-logfile', path], self.N_API, boom=True)
        self.assertEqual(out, '', 'access logging leaked to stdout: %r' % out[:200])
        self.assertNotIn('GET /x', err)
        with open(path) as fh:
            lines = fh.read().splitlines()
        self.assertGreaterEqual(len([l for l in lines if 'GET /x' in l]), self.N_API)
        self.assertIn('handler-exploded', err)  # error logging intact


class Rotation(unittest.TestCase):
    def test_bounded_and_mode(self):
        d = tempfile.mkdtemp(prefix='gunicorn-rot-')
        path = os.path.join(d, 'api-access.log')
        for _ in range(12):
            with open(path, 'ab') as fh:
                fh.write(b'x' * 1000 + b'\n')
            rot.rotate_if_needed(path, 4000, 3)
        files = sorted(os.listdir(d))
        self.assertLessEqual(len(files), 4, files)  # live + 3 backups
        self.assertLessEqual(os.path.getsize(path), 4000 + 1001)
        self.assertEqual(stat.S_IMODE(os.stat(path + '.1').st_mode), 0o640)
        self.assertFalse(os.path.exists(path + '.4'))

    def test_missing_file_is_not_fatal(self):
        self.assertFalse(rot.rotate_if_needed('/nonexistent/api-access.log', 10, 3))


if __name__ == '__main__':
    unittest.main()
