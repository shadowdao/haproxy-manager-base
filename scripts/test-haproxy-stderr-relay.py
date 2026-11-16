#!/usr/bin/env python3
"""Offline tests for scripts/haproxy-stderr-relay.py (runs in the image build)."""
import importlib.util
import io
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('relay', os.path.join(HERE, 'haproxy-stderr-relay.py'))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='hap-stderr-relay-')
        self.path = os.path.join(self.dir, 'haproxy-stderr.log')
        open(self.path, 'w').close()
        self.out = io.StringIO()
        self.clock = Clock()

    def make(self, burst=1000, per_min=120, max_bytes=10**6, backups=3):
        return relay.Relay(self.path, self.out, burst, per_min, max_bytes, backups, clock=self.clock)

    def append(self, text):
        with open(self.path, 'a') as fh:
            fh.write(text)

    def test_history_is_not_replayed_and_new_lines_are_prefixed(self):
        self.append('old line from a previous container\n')
        r = self.make()
        r.poll_once()
        self.assertEqual(self.out.getvalue(), '')
        self.append('[ALERT]    (10) : Current worker (67) exited with code 134 (Aborted)\n')
        r.poll_once()
        self.assertEqual(self.out.getvalue(),
                         'haproxy-stderr: [ALERT]    (10) : Current worker (67) exited with code 134 (Aborted)\n')

    def test_partial_line_is_held_until_complete(self):
        r = self.make()
        r.poll_once()
        self.append('Thread 1 is abo')
        r.poll_once()
        self.assertEqual(self.out.getvalue(), '')
        self.append('ut to kill the process.\n')
        r.poll_once()
        self.assertIn('Thread 1 is about to kill the process.', self.out.getvalue())

    def test_control_characters_cannot_forge_lines(self):
        r = self.make()
        r.poll_once()
        self.append('a\x1b[31mb\r\x00c\n')
        r.poll_once()
        self.assertEqual(self.out.getvalue().count('\n'), 1)
        self.assertNotIn('\x1b', self.out.getvalue())

    def test_rate_limit_passes_a_full_dump_then_summarises(self):
        r = self.make(burst=200, per_min=60)
        r.poll_once()
        self.append(''.join('dump line %d\n' % i for i in range(150)))
        r.poll_once()
        self.assertEqual(self.out.getvalue().count('\n'), 150)
        self.out.truncate(0), self.out.seek(0)
        self.append(''.join('flap %d\n' % i for i in range(500)))
        r.poll_once()
        self.assertLessEqual(self.out.getvalue().count('\n'), 52)  # ~50 tokens left
        self.clock.t += 600  # bucket refills
        self.out.truncate(0), self.out.seek(0)
        self.append('after storm\n')
        r.poll_once()
        r.tick()
        self.assertIn('[relay] suppressed ', self.out.getvalue())
        self.assertIn('after storm', self.out.getvalue())

    def test_copytruncate_rotation_bounds_the_file_and_keeps_following(self):
        r = self.make(max_bytes=100, backups=2)
        r.poll_once()
        self.append('x' * 150 + '\n')
        r.poll_once()
        r.rotate_if_needed()
        self.assertEqual(os.path.getsize(self.path), 0)
        self.assertTrue(os.path.exists(self.path + '.1'))
        self.append('after rotate\n')
        r.poll_once()
        self.assertIn('after rotate', self.out.getvalue())

    def test_missing_file_is_not_an_error(self):
        os.remove(self.path)
        r = self.make()
        r.poll_once()
        self.append('late\n')
        r.poll_once()
        self.assertIn('late', self.out.getvalue())



# --- captured scenario: 4 quick reloads (bucket drained) then a forced worker panic ---------------

def reload_block(pid, n_proxies=100):
    """What HAProxy 3.2 writes on stderr for ONE reload (~110 lines on a small config)."""
    L = ['[NOTICE]   (%d) : Reloading HAProxy' % pid,
         '[NOTICE]   (%d) : Initializing new worker (%d)' % (pid, pid + 100),
         '[NOTICE]   (%d) : haproxy version is 3.2.26-1~bpo13+1' % (pid + 100),
         '[NOTICE]   (%d) : path to executable is /usr/sbin/haproxy' % (pid + 100)]
    for i in range(6):
        L.append("[WARNING]  (%d) : config : parsing [/etc/haproxy/haproxy.cfg:%d] : a 'http-request' rule "
                 "placed after a 'use_backend' rule will still be processed before." % (pid + 100, 800 + i))
    L.append("[WARNING]  (%d) : config: Can't load stats-file '/var/lib/haproxy/stats.dat': cannot open file." % pid)
    L.append('[NOTICE]   (%d) : Loading success.' % pid)
    for i in range(n_proxies):
        L.append('[WARNING]  (%d) : Proxy be_%d stopped (cumulated conns: FE: 0, BE: 12).' % (pid + 50, i))
    L.append('[WARNING]  (%d) : Former worker (%d) exited with code 0 (Exit)' % (pid, pid + 50))
    return L


DUMP = [
    'Thread 1 is about to kill the process (pid 6631).',
    '* Thread 1 : id=0x7f60efa77400 act=1 glob=0 wq=1 rq=0 tl=0 tlsz=0 rqsz=0',
    '      1/1    loops=94 ctxsw=234 stuck=0 prof=0 harmless=0 isolated=0',
    '             call trace(15):',
    '             | 0x55c557cd3582 <00 00 00 e8 ae 03 dc ff]: ha_dump_backtrace+0x82/0x43d > main-0x7d0',
    '  Thread 2 : id=0x7f60ef5ff6c0 act=0 glob=0 wq=1 rq=0 tl=0 tlsz=0 rqsz=0',
    '             lock_hist: R:TASK_WQ U:TASK_WQ',
    '  Thread 3 : id=0x7f60ed5ff6c0 act=0 glob=0 wq=1 rq=0 tl=0 tlsz=0 rqsz=0',
    '  Thread 4 : id=0x7f60ecdfe6c0 act=0 glob=0 wq=1 rq=0 tl=0 tlsz=0 rqsz=0',
    '',
    "Hint: when reporting this bug to developers, please check if a core file was",
    "      produced, open it with 'gdb', issue 't a a bt full', check that the",
    '[ALERT]    (6328) : Current worker (6631) exited with code 134 (Aborted)',
    '[WARNING]  (6328) : A worker process unexpectedly died and this can only be explained by a bug in haproxy or its dependencies.',
    'Please check that you are running an up to date and maintained version of haproxy and open a bug report.',
    'HAProxy version 3.2.26-1~bpo13+1 2026/10/14 - https://haproxy.org/',
    'Known bugs: http://www.haproxy.org/bugs/bugs-3.2.26.html',
    '[ALERT]    (6328) : exit-on-failure: killing every processes with SIGTERM',
    '[WARNING]  (6328) : All workers exited. Exiting... (134)',
]
KEYS = ('about to kill', 'Thread 1 :', 'Thread 2 :', 'Thread 3 :', 'Thread 4 :', 'Current worker',
        'exited with code 134', 'exit-on-failure', 'All workers exited', 'call trace', 'ha_dump_backtrace',
        'bug in haproxy', 'Please check that you are running', 'produced, open it with')


def scenario(mod, burst=400, drained=True):
    """4 quick reloads (>400 lines: the bucket drains) then the panic dump. Returns facts."""
    out, err, t = io.StringIO(), io.StringIO(), [0.0]
    r = mod.Relay('/nonexistent', out, burst, 120, 1 << 30, 3, clock=lambda: t[0], err=err)
    lines = []
    for k in range(4):
        lines += reload_block(100 * (k + 1))
    n_before = len(lines)
    lines += DUMP
    for l in lines:
        if l.strip():          # poll_once drops blank lines before _emit
            r._emit(l)
        t[0] += 0.003
    r.tick()
    return {'out': out.getvalue(), 'err': err.getvalue(), 'reload_lines': n_before, 'bucket': r.tokens, 'r': r}


class CapturedScenarioTests(unittest.TestCase):
    def test_drained_bucket_then_panic_forwards_every_crash_line(self):
        f = scenario(relay)
        self.assertGreater(f['reload_lines'], 400)          # would drain a 400-line bucket
        e = f['err']
        for k in KEYS:
            self.assertIn(k, e, k)
        # the whole dump, line for line (blank lines are dropped by design)
        got = [l[len(relay.PREFIX):] for l in e.split('\n') if l]
        self.assertEqual(got, [d.rstrip() for d in DUMP if d.strip()])

    def test_dump_is_forwarded_in_full_even_with_an_empty_bucket(self):
        out, err = io.StringIO(), io.StringIO()
        r = relay.Relay('/nonexistent', out, 1, 1, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r.tokens = 0.0
        for l in ('benign %d' % i for i in range(10)):
            r._emit(l)
        self.assertEqual(out.getvalue(), '')
        for l in DUMP:
            if l.strip():
                r._emit(l)
        self.assertEqual(err.getvalue().count('\n'), len([d for d in DUMP if d.strip()]))
        self.assertEqual(r.suppressed, 10)

    def test_reload_noise_is_collapsed_not_drained(self):
        out, err, t = io.StringIO(), io.StringIO(), [0.0]
        r = relay.Relay('/nonexistent', out, 400, 120, 1 << 30, 3, clock=lambda: t[0], err=err)
        for k in range(10):
            for l in reload_block(100 * (k + 1)):
                r._emit(l)
        self.assertEqual(r.tokens, 400.0)                   # bucket untouched by 1000+ noise lines
        self.assertEqual(r.suppressed, 0)
        self.assertEqual(err.getvalue(), '')
        summ = [l for l in out.getvalue().split('\n') if 'reload/start ok' in l]
        self.assertEqual(len(summ), 10)                     # exactly one per reload
        self.assertNotIn('Proxy be_', out.getvalue())
        self.assertNotIn('parsing [', out.getvalue())
        self.assertLess(out.getvalue().count('\n'), 15)

    def test_suppressed_lines_are_summarised_per_minute(self):
        out, err, t = io.StringIO(), io.StringIO(), [0.0]
        r = relay.Relay('/nonexistent', out, 5, 60, 1 << 30, 3, clock=lambda: t[0], err=err)
        for i in range(105):
            r._emit('flapping server state %d' % i)
        self.assertNotIn('[relay] suppressed', out.getvalue())
        t[0] += 61
        r.tick()
        self.assertRegex(out.getvalue(), r'\[relay\] suppressed 100 lines')
        self.assertEqual(r.suppressed, 0)
        self.assertEqual(err.getvalue(), '')

    def test_benign_lines_go_to_stdout_and_crash_lines_to_stderr(self):
        # docker's journald driver: stdout -> PRIORITY 6, stderr -> PRIORITY 3, "<N>" is NOT parsed
        f = scenario(relay)
        self.assertIn('[relay] reload/start ok', f['out'])
        self.assertNotIn('Thread', f['out'])
        self.assertNotIn('Current worker', f['out'])
        self.assertNotIn('[ALERT]', f['out'])
        self.assertNotIn('reload/start ok', f['err'])
        for text in (f['out'], f['err']):
            for l in text.split('\n'):
                self.assertFalse(l.startswith('<') or l.startswith(relay.PREFIX + '<'), l)

    def test_clean_worker_exit_is_not_crash_evidence(self):
        out, err = io.StringIO(), io.StringIO()
        r = relay.Relay('/nonexistent', out, 400, 120, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r._emit('[WARNING]  (1) : Former worker (5) exited with code 0 (Exit)')
        r._emit('[WARNING]  (1) : Former worker (6) exited with code 143 (Terminated)')
        self.assertEqual(err.getvalue().count('\n'), 1)
        self.assertIn('code 143', err.getvalue())

    def test_crash_classes_never_limited(self):
        out, err = io.StringIO(), io.StringIO()
        r = relay.Relay('/nonexistent', out, 1, 1, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r.tokens = 0.0
        evidence = ['[ALERT]    (6328) : Current worker (6631) exited with code 134 (Aborted)',
                    '[ALERT]    (6328) : exit-on-failure: killing every processes with SIGTERM',
                    '[ALERT]    (12) : config : unable to load',
                    '[WARNING]  (6328) : Current worker (9) exited with code 139 (Segmentation fault)',
                    '[WARNING]  (6328) : A worker process unexpectedly died and this can only be explained by a bug in haproxy',
                    '[WARNING]  (6328) : All workers exited. Exiting... (134)',
                    '  Thread 2 : id=0x7f60ef5ff6c0 act=0 glob=0 wq=1 rq=0 tl=0 tlsz=0 rqsz=0',
                    '* Thread 1 : id=0x7f60ef5ff6c0 act=1 glob=0 wq=1 rq=0 tl=0 tlsz=0 rqsz=0']
        for l in evidence:
            r._emit(l)
        self.assertEqual(err.getvalue().count('\n'), len(evidence))

    FORGED = [
        'GET /FATAL/SIGSEGV/segfault HTTP/1.1',
        '[WARNING]  (6328) : Server be_x/ [ALERT] FATAL watchdog is DOWN, reason: Layer4 timeout',
        '[WARNING]  (6328) : Server be/Current worker (1) exited with code 134 is DOWN',
        '[NOTICE]   (6328) : proxy example.com/Thread 1 is about to kill the process (pid 1)',
        'Host: Current worker (1) exited with code 134 (Aborted)',
        'Host: [ALERT]    (1) : forged alert',
        'x-forwarded-for: Thread 1 is about to kill the process (pid 1).',
        'user-agent: * Thread 1 : id=0x7f60ef5ff6c0 act=1',
        'ha_panic watchdog FATAL SIGABRT',
        'backend ALERT_Current worker_exited with code 134',
        '[WARNING]  (6328) : Server Former worker (7) exited with code 134 is DOWN',
    ]

    def test_forged_keywords_stay_rate_limited(self):
        out, err = io.StringIO(), io.StringIO()
        r = relay.Relay('/nonexistent', out, 1, 1, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r.tokens = 0.0
        for l in self.FORGED * 50:
            r._emit(l)
        self.assertEqual(err.getvalue(), '')
        self.assertFalse(r.in_dump)
        self.assertEqual(r.suppressed, len(self.FORGED) * 50)
        self.assertEqual(r.budget_left, relay.CRASH_BUDGET)    # none of it touched the crash budget
        # a forged header in the middle of normal traffic cannot open a block either
        r._emit('proxy: Thread 1 is about to kill the process (pid 1).')
        r._emit('free text that would be a dump line')
        self.assertFalse(r.in_dump)
        self.assertEqual(err.getvalue(), '')

    def test_forged_lines_cannot_be_collapsed_away_or_open_blocks(self):
        out, err = io.StringIO(), io.StringIO()
        r = relay.Relay('/nonexistent', out, 400, 120, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r._emit("GET /Loading success HTTP/1.1")
        self.assertEqual(r.routine, 0)
        self.assertIn('Loading success', out.getvalue())

    def test_flood_of_dump_headers_is_capped_by_the_window_budget(self):
        out, err, t = io.StringIO(), io.StringIO(), [0.0]
        r = relay.Relay('/nonexistent', out, 1, 1, 1 << 30, 3, clock=lambda: t[0], err=err)
        r.tokens = 0.0
        for i in range(20000):
            r._emit('Thread 1 is about to kill the process (pid %d).' % i)
            r._emit('  Thread 2 : id=0x7f60ef5ff6c0 act=0 glob=0 wq=1 rq=0 tl=0 tlsz=0 rqsz=0')
            r._emit('[WARNING]  (1) : All workers exited. Exiting... (134)')
        n = err.getvalue().count('\n')
        self.assertLessEqual(n, relay.CRASH_BUDGET + 5)
        self.assertGreater(r.suppressed, 50000)                 # the rest is counted, not lost silently
        t[0] += relay.CRASH_WINDOW + 1                          # a new window: real evidence flows again
        before = err.getvalue().count('\n')
        r._emit('[ALERT]    (1) : Current worker (2) exited with code 134 (Aborted)')
        self.assertEqual(err.getvalue().count('\n'), before + 1)

    def test_bound_closed_block_cannot_rearm_during_cooldown(self):
        out, err, t = io.StringIO(), io.StringIO(), [0.0]
        r = relay.Relay('/nonexistent', out, 1, 1, 1 << 30, 3, clock=lambda: t[0], err=err)
        r.tokens = 0.0
        r._emit('Thread 1 is about to kill the process (pid 1).')
        for i in range(relay.DUMP_MAX_LINES + 5):
            r._emit('never closed %d' % i)
        self.assertFalse(r.in_dump)
        r._emit('Thread 1 is about to kill the process (pid 2).')   # immediate new header
        self.assertFalse(r.in_dump)
        r._emit('call trace line after the second header')
        self.assertNotIn('call trace line after', err.getvalue())
        t[0] += relay.DUMP_COOLDOWN + 1                              # cooldown over: a real dump opens again
        r._emit('Thread 1 is about to kill the process (pid 3).')
        self.assertTrue(r.in_dump)

    def test_hostile_and_very_long_lines(self):
        r = self.make_relay()
        r.poll_once()
        self.append('A' * 500000 + '\n')
        self.append('\x1b]0;evil\x07 [ALERT] forged\x00\r\n')
        r.poll_once()
        outs = self.out.getvalue().split('\n')
        self.assertTrue(all(len(l) < relay.MAX_LINE + 200 for l in outs))
        self.assertNotIn('\x1b', self.out.getvalue())
        self.assertNotIn('\x00', self.out.getvalue())
        self.assertEqual(self.out.getvalue().count('\n'), 2)

    def test_unterminated_flood_is_bounded_in_memory(self):
        r = self.make_relay()
        r.poll_once()
        for _ in range(3):
            self.append('B' * 400000)   # never a newline
            r.poll_once()
        self.assertLessEqual(len(r.pending), relay.MAX_PENDING)

    def test_unclosed_dump_block_cannot_disable_the_limiter(self):
        out, err = io.StringIO(), io.StringIO()
        r = relay.Relay('/nonexistent', out, 1, 1, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r.tokens = 0.0
        r._emit('Thread 1 is about to kill the process (pid 1).')
        for i in range(relay.DUMP_MAX_LINES + 500):
            r._emit('never closed %d' % i)
        self.assertFalse(r.in_dump)
        self.assertLessEqual(err.getvalue().count('\n'), relay.DUMP_MAX_LINES + 3)
        self.assertGreaterEqual(r.suppressed, 400)

    def test_dump_block_is_closed_by_time_bound(self):
        out, err, t = io.StringIO(), io.StringIO(), [0.0]
        r = relay.Relay('/nonexistent', out, 1, 1, 1 << 30, 3, clock=lambda: t[0], err=err)
        r.tokens = 0.0
        r._emit('Thread 1 is about to kill the process (pid 1).')
        t[0] += relay.DUMP_MAX_SECONDS + 1
        r._emit('later benign line')
        self.assertFalse(r.in_dump)
        self.assertNotIn('later benign', err.getvalue())

    # shared helpers for the file-driven tests
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='hap-stderr-relay-')
        self.path = os.path.join(self.dir, 'haproxy-stderr.log')
        open(self.path, 'w').close()
        self.out = io.StringIO()

    def make_relay(self):
        return relay.Relay(self.path, self.out, 1000, 120, 10 ** 6, 3, clock=lambda: 0.0)

    def append(self, text):
        with open(self.path, 'a') as fh:
            fh.write(text)


# --- mutants: the same scenario must FAIL when a guarantee is removed (private copies) ------------

def _scenario_ok(mod):
    f = scenario(mod)
    got = [l[len(mod.PREFIX):] for l in f['err'].split('\n') if l]
    crash_ok = all(k in f['err'] for k in KEYS) and got == [d.rstrip() for d in DUMP if d.strip()]
    collapse_ok = f['out'].count('reload/start ok') == 4 and 'Proxy be_' not in f['out'] and f['bucket'] > 300
    prio_ok = 'Thread' not in f['out'] and 'reload/start ok' not in f['err']
    return crash_ok, collapse_ok, prio_ok


class MutantTests(unittest.TestCase):
    SRC = os.path.join(HERE, 'haproxy-stderr-relay.py')

    def load_mutant(self, old, new):
        with open(self.SRC) as fh:
            src = fh.read()
        self.assertIn(old, src, 'mutation target vanished: update the test')
        mutated = src.replace(old, new, 1)
        self.assertNotEqual(mutated, src)
        d = tempfile.mkdtemp(prefix='hap-relay-mutant-')   # private copy, the real file is untouched
        path = os.path.join(d, 'mutant.py')
        with open(path, 'w') as fh:
            fh.write(mutated)
        sp = importlib.util.spec_from_file_location('mutant', path)
        m = importlib.util.module_from_spec(sp)
        sp.loader.exec_module(m)
        return m

    def test_unmutated_copy_passes_everything(self):
        self.assertEqual(_scenario_ok(relay), (True, True, True))

    def test_mutant_limiter_applied_to_crash_lines(self):
        m = self.load_mutant('if self.in_dump or CRASH_RE.match(line):', 'if False:')
        crash_ok, _, _ = _scenario_ok(m)
        self.assertFalse(crash_ok)

    def test_mutant_dump_block_not_tracked(self):
        m = self.load_mutant('if not self.in_dump and DUMP_START_RE.match(line) and now >= self.cooldown_until:', 'if False:')
        crash_ok, _, _ = _scenario_ok(m)
        self.assertFalse(crash_ok)

    def test_mutant_collapse_disabled(self):
        m = self.load_mutant('if ROUTINE_RE.match(line):', 'if False:')
        _, collapse_ok, _ = _scenario_ok(m)
        self.assertFalse(collapse_ok)

    def test_mutant_crash_lines_on_stdout(self):
        m = self.load_mutant('self._write(self.err, line)', 'self._write(self.out, line)')
        _, _, prio_ok = _scenario_ok(m)
        self.assertFalse(prio_ok)

    def test_mutant_dump_bound_removed(self):
        m = self.load_mutant('DUMP_MAX_LINES = 500 ', 'DUMP_MAX_LINES = 10 ** 9 ')
        err = io.StringIO()
        r = m.Relay('/nonexistent', io.StringIO(), 1, 1, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r.tokens = 0.0
        r._emit('Thread 1 is about to kill the process (pid 1).')
        for i in range(m.DUMP_MAX_LINES if False else 800):
            r._emit('never closed %d' % i)
        self.assertTrue(r.in_dump)   # real module closes at 500: see test_unclosed_dump_block...

    def _forged_run(self, mod):
        err = io.StringIO()
        r = mod.Relay('/nonexistent', io.StringIO(), 1, 1, 1 << 30, 3, clock=lambda: 0.0, err=err)
        r.tokens = 0.0
        for l in CapturedScenarioTests.FORGED * 20:
            r._emit(l)
        return err.getvalue()

    def test_forged_run_clean_on_real_module(self):
        self.assertEqual(self._forged_run(relay), '')

    def test_mutant_anchors_removed(self):
        m = self.load_mutant('if self.in_dump or CRASH_RE.match(line):',
                             "if self.in_dump or re.search(r'ALERT|FATAL|Current worker|about to kill|Thread \\d+ : id=', line):")
        self.assertNotEqual(self._forged_run(m), '')

    def _flood(self, mod):
        err, t = io.StringIO(), [0.0]
        r = mod.Relay('/nonexistent', io.StringIO(), 1, 1, 1 << 30, 3, clock=lambda: t[0], err=err)
        r.tokens = 0.0
        for i in range(5000):
            r._emit('Thread 1 is about to kill the process (pid %d).' % i)
            r._emit('[WARNING]  (1) : All workers exited. Exiting... (134)')
        return err.getvalue().count('\n')

    def test_flood_capped_on_real_module(self):
        self.assertLessEqual(self._flood(relay), relay.CRASH_BUDGET + 5)

    def test_mutant_budget_removed(self):
        m = self.load_mutant('if self._budget(now):', 'if True:')
        self.assertGreater(self._flood(m), relay.CRASH_BUDGET + 5)

    def _rearm(self, mod):
        r = mod.Relay('/nonexistent', io.StringIO(), 1, 1, 1 << 30, 3, clock=lambda: 0.0, err=io.StringIO())
        r.tokens = 0.0
        r._emit('Thread 1 is about to kill the process (pid 1).')
        for i in range(relay.DUMP_MAX_LINES + 5):
            r._emit('x %d' % i)
        r._emit('Thread 1 is about to kill the process (pid 2).')
        return r.in_dump

    def test_mutant_cooldown_removed(self):
        self.assertFalse(self._rearm(relay))
        m = self.load_mutant(' and now >= self.cooldown_until:', ':')
        self.assertTrue(self._rearm(m))

    def test_mutant_summary_removed(self):
        m = self.load_mutant("self._write(self.out, '[relay] suppressed %d lines", "self._noop = ('[relay] suppressed %d lines")
        out, t = io.StringIO(), [0.0]
        r = m.Relay('/nonexistent', out, 5, 60, 1 << 30, 3, clock=lambda: t[0], err=io.StringIO())
        for i in range(105):
            r._emit('x %d' % i)
        t[0] += 61
        r.tick()
        self.assertNotIn('[relay] suppressed', out.getvalue())


if __name__ == '__main__':
    unittest.main()
