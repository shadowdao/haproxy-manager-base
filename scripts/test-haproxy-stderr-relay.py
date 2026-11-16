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
        self.assertIn('suppressed by rate limit', self.out.getvalue())
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


if __name__ == '__main__':
    unittest.main()
