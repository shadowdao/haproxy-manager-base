#!/usr/bin/env python3
"""Offline tests for scripts/haproxy-supervisor.sh (pidof / python are stubbed on PATH)."""
import os
import stat
import subprocess
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'haproxy-supervisor.sh')

PIDOF = """#!/bin/sh
# "haproxy" is alive iff the start stamp exists and is younger than $LIFE seconds
[ -f "$STATE/started" ] || exit 1
start=$(cat "$STATE/started")
now=$(date +%s.%N)
awk -v s="$start" -v n="$now" -v l="$LIFE" 'BEGIN{exit !(n - s < l)}'
"""
PYTHON = """#!/bin/sh
# stand-in for ensure_haproxy.py: stamp the start, record it
date +%s.%N > "$STATE/started"
date +%s.%N >> "$STATE/starts"
exit ${ENSURE_RC:-0}
"""


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='hap-sup-')
        self.state = os.path.join(self.d, 'state')
        os.mkdir(self.state)
        for name, body in (('pidof', PIDOF), ('python', PYTHON)):
            p = os.path.join(self.d, name)
            with open(p, 'w') as fh:
                fh.write(body)
            os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)

    def run_sup(self, seconds, **env):
        e = dict(os.environ, PATH=self.d + ':' + os.environ['PATH'], STATE=self.state)
        e.setdefault('LIFE', '0')
        e.update(env)
        try:
            subprocess.run(['bash', SCRIPT], env=e, timeout=seconds, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT)
            return 'exited'
        except subprocess.TimeoutExpired:
            return 'running'       # still looping when the clock ran out = alive

    def starts(self):
        try:
            with open(os.path.join(self.state, 'starts')) as fh:
                return [float(x) for x in fh.read().split()]
        except OSError:
            return []

    def test_non_integer_interval_does_not_kill_the_supervisor(self):
        self.assertEqual(self.run_sup(8, HAPROXY_SUPERVISOR_INTERVAL='0.5', ENSURE_RC='1'), 'running')
        self.assertGreaterEqual(len(self.starts()), 2)       # fell back to the default interval and kept trying

    def test_garbage_interval_and_max_fall_back(self):
        self.assertEqual(self.run_sup(4, HAPROXY_SUPERVISOR_INTERVAL='abc', HAPROXY_SUPERVISOR_MAX_BACKOFF='x'), 'running')
        self.assertGreaterEqual(len(self.starts()), 1)

    def test_crash_loop_backs_off_2_5_10_capped(self):
        # haproxy dies immediately after every successful start (LIFE=0) -> quick deaths
        self.run_sup(14, HAPROXY_SUPERVISOR_INTERVAL='1', HAPROXY_SUPERVISOR_BACKOFF_STEPS='1 2 3',
                     HAPROXY_SUPERVISOR_QUICK_DEATH='5', HAPROXY_SUPERVISOR_STABLE='8',
                     HAPROXY_SUPERVISOR_MAX_BACKOFF='3')
        s = self.starts()
        gaps = [round(b - a, 1) for a, b in zip(s, s[1:])]
        self.assertGreaterEqual(len(s), 4, gaps)
        # gap = interval(1) + backoff step: 2, 3, 4, then capped at 1+3 = 4
        self.assertLess(gaps[0], gaps[1] + 0.3, gaps)
        self.assertGreaterEqual(gaps[1], 3.0 - 0.3, gaps)
        self.assertGreaterEqual(gaps[2], 4.0 - 0.3, gaps)
        self.assertLessEqual(max(gaps), 4.0 + 0.8, gaps)

    def test_stable_haproxy_resets_the_backoff(self):
        # alive for 2s after each start; QUICK_DEATH=1 so a 2s life is NOT quick: no backoff growth
        self.run_sup(9, HAPROXY_SUPERVISOR_INTERVAL='1', LIFE='2', HAPROXY_SUPERVISOR_BACKOFF_STEPS='3 3 3',
                     HAPROXY_SUPERVISOR_QUICK_DEATH='1', HAPROXY_SUPERVISOR_STABLE='8',
                     HAPROXY_SUPERVISOR_MAX_BACKOFF='3')
        s = self.starts()
        gaps = [b - a for a, b in zip(s, s[1:])]
        self.assertGreaterEqual(len(s), 3, gaps)
        self.assertLess(max(gaps), 3.6, gaps)                # never the 3 s backoff on top

    def test_running_haproxy_is_left_alone(self):
        with open(os.path.join(self.state, 'started'), 'w') as fh:
            fh.write(str(time.time()))
        self.assertEqual(self.run_sup(3, HAPROXY_SUPERVISOR_INTERVAL='1', LIFE='1000'), 'running')
        self.assertEqual(self.starts(), [])


if __name__ == '__main__':
    unittest.main()
