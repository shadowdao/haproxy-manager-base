#!/usr/bin/env python3
"""Backend health-check timing: one `default-server` line, jittered, pinned.

WHP appends `check ssl verify none` to every backend server, and each check is
a full TLS handshake. On a host with ~426 checked servers the HAProxy default
(inter 2s) is ~200+ handshakes/s of health-check churn, which together with
memory pressure preceded the 2026-11-25 watchdog aborts. So the interval is
30s, set ONCE in `defaults` (never per server line), and the checks are
desynchronised with the global `spread-checks`.

What this pins (the real `haproxy -c` of the same config is the
`check-timing` assertions in scripts/validate-rendered-config.py):
  * exactly one default-server line, in `defaults`, with the agreed timing;
  * `spread-checks 50` in `global` (documented max, 0..50);
  * the agreed timing detects a dead backend in <= ~75 s worst case (inside the 1-2
    minutes Josh accepted) -- computed from the numbers, so changing one of
    them without re-justifying the other fails here;
  * no template puts inter/fastinter/downinter on a customer server line
    (that would bypass the one knob), and the Coraza SPOA server keeps its
    own fast timing.

    python3 scripts/test-health-check-timing.py
"""
import os
import re
import sys
import unittest

MODULE_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')))
sys.path.insert(0, MODULE_DIR)
import haproxy_manager as hm  # noqa: E402

WANT = 'default-server inter 30s fastinter 10s downinter 30s rise 2 fall 3'


def header(**kw):
    return hm.template_env.get_template('hap_header.tpl').render(
        cluster_secret='s', syslog_target='/log.sock',
        coraza_spoe_backend=kw.pop('coraza_spoe_backend', None), **kw)


def code(text):
    return '\n'.join(l for l in text.splitlines() if not l.lstrip().startswith('#'))


def section(out, name):
    m = re.search(r'^%s\b.*?(?=^\S|\Z)' % name, code(out), re.M | re.S)
    assert m, name
    return m.group(0)


class Timing(unittest.TestCase):
    def test_one_default_server_in_defaults(self):
        for kw in ({}, {'coraza_spoe_backend': '127.0.0.1:9000'}, {'nbthread': 1}):
            out = header(**kw)
            lines = re.findall(r'^\s*default-server\s.*$', code(out), re.M)
            self.assertEqual(len(lines), 1, kw)
            self.assertEqual(' '.join(lines[0].split()), WANT)
            self.assertIn('default-server', section(out, 'defaults'))
            self.assertNotIn('default-server', section(out, 'global'))

    def test_spread_checks_in_global_at_documented_max(self):
        out = header()
        self.assertEqual(re.findall(r'^\s*spread-checks\s+(\d+)\s*$', section(out, 'global'), re.M),
                         ['50'])
        self.assertEqual(code(out).count('spread-checks'), 1)

    def test_dead_backend_detected_within_two_minutes(self):
        m = re.search(r'inter (\d+)s fastinter (\d+)s downinter (\d+)s rise (\d+) fall (\d+)', WANT)
        inter, fast, down, rise, fall = map(int, m.groups())
        jitter = 1.5  # spread-checks 50: each wait is up to +50%
        # first failing check <= inter*1.5 after death, then fall-1 more at fastinter
        mark_down = inter * jitter + (fall - 1) * fast * jitter
        mark_up = down * jitter + (rise - 1) * fast * jitter
        self.assertLessEqual(mark_down, 120)
        self.assertLessEqual(mark_up, 120)
        # start-up stagger window is the smallest interval in use (fastinter):
        # 2s would recreate a whole-edge burst on every reload
        self.assertGreaterEqual(fast, 5)

    def test_no_per_server_timing_in_customer_templates(self):
        tdir = os.path.join(MODULE_DIR, 'templates')
        for name in sorted(os.listdir(tdir)):
            if not name.endswith('.tpl') or name == 'hap_coraza_spoa_backend.tpl':
                continue
            with open(os.path.join(tdir, name)) as fh:
                body = code(fh.read())
            for line in body.splitlines():
                if line.strip().startswith('server '):
                    self.assertNotRegex(line, r'\b(inter|fastinter|downinter)\b', name)

    def test_coraza_spoa_keeps_fast_checks(self):
        src = hm.template_env.get_template('hap_coraza_spoa_backend.tpl').render(agent_target='127.0.0.1:9000')
        line = [l for l in code(src).splitlines() if l.strip().startswith('server coraza-spoa')]
        self.assertEqual(len(line), 1)
        for token in ('check', 'inter 2s', 'fastinter 2s', 'downinter 2s'):
            self.assertIn(token, line[0])

    def test_server_line_rendering_unchanged(self):
        # the per-server options still come straight from WHP, untouched
        out = hm.template_env.get_template('hap_backend.tpl').render(
            name='x', servers=[{'server_name': 's', 'server_address': 'a',
                                'server_port': 443, 'server_options': 'check ssl verify none'}])
        self.assertIn('server s a:443 check ssl verify none resolvers docker_dns init-addr last,libc,none', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
