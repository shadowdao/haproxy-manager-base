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


class SupervisorBase:
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
        # keep the fast path OFF unless a test opts in (no config -> python fallback)
        e.setdefault('HAPROXY_SUPERVISOR_CFG', os.path.join(self.d, 'no-such.cfg'))
        e.setdefault('HAPROXY_SUPERVISOR_MARKER', os.path.join(self.state, 'marker'))
        e.setdefault('HAPROXY_STDERR_LOG', os.path.join(self.d, 'stderr.log'))
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


class SupervisorTests(SupervisorBase, unittest.TestCase):
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


# stand-in `haproxy`: -c validates (rc from $CHECK_RC); a launch stamps the start,
# logs the line the supervisor waits for, and records whether the marker existed
HAPROXY = """#!/bin/sh
if [ "$1" = "-c" ]; then exit ${CHECK_RC:-0}; fi
[ -f "$MARKER" ] && echo yes >> "$STATE/marker-seen"
date +%s.%N > "$STATE/started"
date +%s.%N >> "$STATE/direct"
echo "[NOTICE] Loading success." >&2
exit ${LAUNCH_RC:-0}
"""


class FastPathTests(SupervisorBase, unittest.TestCase):
    def setUp(self):
        super().setUp()
        p = os.path.join(self.d, 'haproxy')
        with open(p, 'w') as fh:
            fh.write(HAPROXY)
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
        self.cfg = os.path.join(self.d, 'haproxy.cfg')
        with open(self.cfg, 'w') as fh:
            fh.write('# stub\n')

    def fast_env(self, **kw):
        e = dict(HAPROXY_SUPERVISOR_CFG=self.cfg, MARKER=os.path.join(self.state, 'marker'),
                 HAPROXY_SUPERVISOR_INTERVAL='1', LIFE='1000')
        e.update(kw)
        return e

    def direct(self):
        try:
            with open(os.path.join(self.state, 'direct')) as fh:
                return fh.read().split()
        except OSError:
            return []

    def test_dead_haproxy_is_relaunched_directly_without_python(self):
        self.run_sup(4, **self.fast_env(LIFE='0'))     # LIFE=0: haproxy is always "gone" at the first poll
        self.assertGreaterEqual(len(self.direct()), 1)
        self.assertEqual(self.starts(), [])             # ensure_haproxy.py / python never ran
        with open(os.path.join(self.state, 'marker-seen')) as fh:
            self.assertEqual(fh.read().split(), ['yes'] * len(self.direct()))
        self.assertFalse(os.path.exists(os.path.join(self.state, 'marker')))   # cleared after the recovery

    def test_invalid_config_falls_back_to_python(self):
        self.run_sup(4, **self.fast_env(LIFE='0', CHECK_RC='1'))
        self.assertEqual(self.direct(), [])
        self.assertGreaterEqual(len(self.starts()), 1)
        self.assertFalse(os.path.exists(os.path.join(self.state, 'marker')))

    def test_failed_direct_launch_falls_back_to_python(self):
        # haproxy binary not on PATH: the direct path cannot start it
        self.run_sup(4, **self.fast_env(LIFE='0', HAPROXY_SUPERVISOR_BIN='no-such-haproxy-bin'))
        self.assertEqual(self.direct(), [])
        self.assertGreaterEqual(len(self.starts()), 1)

    def test_missing_config_falls_back_to_python(self):
        self.run_sup(4, **self.fast_env(LIFE='0', HAPROXY_SUPERVISOR_CFG=os.path.join(self.d, 'gone.cfg')))
        self.assertEqual(self.direct(), [])
        self.assertGreaterEqual(len(self.starts()), 1)

    def test_running_haproxy_never_gets_a_second_master(self):
        with open(os.path.join(self.state, 'started'), 'w') as fh:
            fh.write(str(time.time()))
        self.assertEqual(self.run_sup(3, **self.fast_env()), 'running')
        self.assertEqual(self.direct(), [])
        self.assertEqual(self.starts(), [])

    def test_poll_interval_defaults_to_one_second(self):
        self.run_sup(3, **{k: v for k, v in self.fast_env(LIFE='0').items() if k != 'HAPROXY_SUPERVISOR_INTERVAL'})
        self.assertGreaterEqual(len(self.direct()), 1)  # first relaunch inside the 3 s budget (2 s poll + start would not fit twice)


if __name__ == '__main__':
    unittest.main()
