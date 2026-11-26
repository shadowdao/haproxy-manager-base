#!/usr/bin/env python3
"""Real-haproxy test for the supervisor's FAST relaunch path.

Starts a real `haproxy -W -db` master with a minimal config, runs the REAL
scripts/haproxy-supervisor.sh next to it (python is stubbed on PATH so any
fallback to ensure_haproxy.py is detected), then kills the worker with SIGABRT
(exactly the 2026-11-19/25/26 failure: the master logs exit-on-failure and
exits 134). Asserts:

  * the master really exits (the premise of the bug),
  * a NEW master is serving within 3 s of that exit (it was 16 s on whp02),
  * it was started directly from bash (the python stub never ran),
  * the recovery marker existed during the restart and is gone afterwards,
  * the supervisor log lines carry timestamps for each step,
  * a second master is never started while one is running,
  * an invalid on-disk config falls back to ensure_haproxy.py (python stub).

Needs a real `haproxy`, `pidof`, `bash`, `timeout`. Skips (exit 0, loudly)
when haproxy is not installed, so it is meaningful in the image build (where
validate-rendered-config.py also needs the binary) and on a dev box with haproxy.
"""
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SUPERVISOR = os.path.join(HERE, 'haproxy-supervisor.sh')
HAPROXY = shutil.which('haproxy')

PYTHON_STUB = """#!/bin/sh
date +%s.%N >> "$STATE/python-ran"
exit 1
"""


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _all_pids():
    r = subprocess.run(['pidof', 'haproxy'], stdout=subprocess.PIPE, text=True)
    return sorted(int(x) for x in r.stdout.split())


def _master_pids():
    """haproxy processes whose parent is not itself haproxy (workers share the name)."""
    pids = _all_pids()
    out = []
    for pid in pids:
        try:
            with open('/proc/%d/stat' % pid) as fh:
                ppid = int(fh.read().rsplit(')', 1)[1].split()[1])
        except (OSError, ValueError, IndexError):
            continue
        if ppid not in pids:
            out.append(pid)
    return out


def _worker_of(master):
    r = subprocess.run(['pgrep', '-P', str(master)], stdout=subprocess.PIPE, text=True)
    return [int(x) for x in r.stdout.split()]


@unittest.skipUnless(HAPROXY, 'haproxy binary not installed')
class RelaunchTests(unittest.TestCase):
    def setUp(self):
        if _all_pids():
            self.skipTest('another haproxy is already running on this host')
        self.d = tempfile.mkdtemp(prefix='hap-relaunch-')
        self.state = os.path.join(self.d, 'state')
        os.mkdir(self.state)
        self.port = _free_port()
        self.cfg = os.path.join(self.d, 'haproxy.cfg')
        self.write_cfg(valid=True)
        self.log = os.path.join(self.d, 'stderr.log')
        self.marker = os.path.join(self.d, 'restarting')
        self.sock = os.path.join(self.d, 'cli')
        py = os.path.join(self.d, 'python')
        with open(py, 'w') as fh:
            fh.write(PYTHON_STUB)
        os.chmod(py, os.stat(py).st_mode | stat.S_IXUSR)
        self.env = dict(os.environ, PATH=self.d + ':' + os.environ['PATH'], STATE=self.state,
                        HAPROXY_SUPERVISOR_CFG=self.cfg, HAPROXY_SUPERVISOR_MARKER=self.marker,
                        HAPROXY_SUPERVISOR_SOCKET=self.sock, HAPROXY_STDERR_LOG=self.log)
        self.sup = None

    def tearDown(self):
        if self.sup:
            self.sup.terminate()
            try:
                self.sup.wait(5)
            except subprocess.TimeoutExpired:
                self.sup.kill()
                self.sup.wait()
        for pid in _all_pids():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        if getattr(self, 'suplog', None):
            self.suplog.close()
        end = time.monotonic() + 5
        while _all_pids() and time.monotonic() < end:   # let the kernel finish reaping before the next test
            time.sleep(0.05)
        shutil.rmtree(self.d, ignore_errors=True)

    def write_cfg(self, valid):
        body = ('global\n    maxconn 100\n\n'
                'defaults\n    mode http\n    timeout connect 1s\n    timeout client 5s\n    timeout server 5s\n\n'
                'frontend fe\n    bind 127.0.0.1:%d\n    http-request return status 200 content-type text/plain string ok\n'
                % self.port)
        if not valid:
            body += '\nthis-is-not-a-haproxy-keyword 1\n'
        with open(self.cfg, 'w') as fh:
            fh.write(body)

    def start_master(self):
        with open(self.log, 'ab') as lf:
            subprocess.Popen([HAPROXY, '-W', '-db', '-S', self.sock + ',level,admin', '-f', self.cfg],
                             stdin=subprocess.DEVNULL, stdout=lf, stderr=lf, start_new_session=True)
        self.wait_for(lambda: self.serving(), 10, 'initial master serving')
        return _master_pids()[0]

    def serving(self):
        try:
            with socket.create_connection(('127.0.0.1', self.port), timeout=0.5) as c:
                c.sendall(b'GET / HTTP/1.0\r\n\r\n')
                return b'200' in c.recv(64)
        except OSError:
            return False

    def wait_for(self, fn, timeout, what):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if fn():
                return time.monotonic()
            time.sleep(0.02)
        self.fail('timed out waiting for ' + what)

    def start_supervisor(self, **extra):
        env = dict(self.env, **extra)
        self.suplog = open(os.path.join(self.d, 'supervisor.out'), 'w')
        self.sup = subprocess.Popen(['bash', SUPERVISOR], env=env, stdout=self.suplog, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL)

    def sup_output(self):
        self.suplog.flush()
        with open(os.path.join(self.d, 'supervisor.out')) as fh:
            return fh.read()

    def test_worker_abort_is_relaunched_directly_in_under_3_seconds(self):
        master = self.start_master()
        self.start_supervisor()
        workers = _worker_of(master)
        self.assertTrue(workers, 'no worker under the master')
        os.kill(workers[0], signal.SIGABRT)
        # premise: the master exits on a worker abort (exit-on-failure)
        died = self.wait_for(lambda: master not in _master_pids(), 5, 'master to exit after the worker abort')
        up = self.wait_for(lambda: self.serving() and master not in _master_pids(), 10, 'relaunched edge serving')
        gap = up - died
        self.wait_for(lambda: 'haproxy up in place' in self.sup_output(), 3, 'supervisor "up in place" line')
        out = self.sup_output()
        print('measured relaunch time (master exit -> serving): %.2f s' % gap)
        self.assertLess(gap, 3.0, out)
        new = _master_pids()
        self.assertEqual(len(new), 1, 'exactly one master, got %r' % new)
        self.assertNotEqual(new[0], master)
        self.assertFalse(os.path.exists(os.path.join(self.state, 'python-ran')), 'fast path fell back to python\n' + out)
        for step in ('haproxy process not found', 'on-disk config valid', 'launched', 'haproxy up in place'):
            self.assertIn(step, out)
        self.assertRegex(out, r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z \[haproxy-supervisor\]')
        self.wait_for(lambda: not os.path.exists(self.marker), 3, 'marker cleared')

    def test_marker_exists_while_restarting(self):
        master = self.start_master()
        self.start_supervisor()
        os.kill(_worker_of(master)[0], signal.SIGABRT)
        seen = []
        end = time.monotonic() + 8
        while time.monotonic() < end:
            if os.path.exists(self.marker):
                with open(self.marker) as fh:
                    seen.append(fh.read().split())
            if seen and not os.path.exists(self.marker):
                break
            time.sleep(0.005)
        # the recovery is ~100s of ms: a 5 ms poll sees the marker unless it was missed entirely
        self.assertTrue(seen, 'marker never observed\n' + self.sup_output())
        self.assertEqual(len(seen[0]), 2)
        self.assertLess(abs(int(seen[0][0]) - time.time()), 30)

    def test_running_master_is_never_duplicated(self):
        master = self.start_master()
        self.start_supervisor()
        time.sleep(3.5)
        self.assertEqual(_master_pids(), [master])
        self.assertNotIn('haproxy process not found', self.sup_output())

    def test_invalid_config_falls_back_to_ensure_haproxy(self):
        master = self.start_master()
        self.start_supervisor()
        self.write_cfg(valid=False)
        os.kill(_worker_of(master)[0], signal.SIGABRT)
        self.wait_for(lambda: os.path.exists(os.path.join(self.state, 'python-ran')), 8, 'python fallback')
        self.assertIn('rejected the on-disk config', self.sup_output())
        self.assertEqual(_master_pids(), [])


if __name__ == '__main__':
    if not HAPROXY:
        print('SKIP: haproxy not installed; the real-haproxy relaunch test did not run')
    unittest.main()
