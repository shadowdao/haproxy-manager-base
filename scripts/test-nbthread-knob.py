#!/usr/bin/env python3
"""HAPROXY_NBTHREAD knob: parsing, rendering, and the unset-path invariant.

The invariant that matters: a host that does not set HAPROXY_NBTHREAD gets a
`global` section BYTE-IDENTICAL to what the image rendered before the knob
existed (HAProxy keeps choosing its own thread count). The real `haproxy -c`
of the `nbthread 1` shape is in scripts/validate-rendered-config.py.

    python3 scripts/test-nbthread-knob.py
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


def render(**kw):
    return hm.template_env.get_template('hap_header.tpl').render(
        cluster_secret='s', syslog_target='/log.sock',
        coraza_spoe_backend=kw.pop('coraza_spoe_backend', None), **kw)


class ParseNbthread(unittest.TestCase):
    def test_unset_and_blank(self):
        for raw in (None, '', '   '):
            self.assertIsNone(hm.parse_nbthread(raw))

    def test_valid(self):
        self.assertEqual(hm.parse_nbthread('1'), 1)
        self.assertEqual(hm.parse_nbthread(' 4\n'), 4)
        self.assertEqual(hm.parse_nbthread('64'), 64)

    def test_invalid_is_ignored_never_rendered(self):
        for raw in ('0', '65', '-1', 'abc', '1.5', '1 2', '1;x', '١', '0x4', '+2'):
            self.assertIsNone(hm.parse_nbthread(raw), raw)


class Render(unittest.TestCase):
    def test_unset_has_no_nbthread_at_all(self):
        for kw in ({}, {'nbthread': None}, {'nbthread': 0}, {'coraza_spoe_backend': 'x:1'}):
            self.assertNotIn('nbthread', render(**kw).replace('{{', ''), kw)

    def test_unset_is_byte_identical_to_template_without_the_block(self):
        src_path = os.path.join(MODULE_DIR, 'templates', 'hap_header.tpl')
        with open(src_path) as fh:
            src = fh.read()
        stripped, n = re.subn(r'\{%- if nbthread %\}.*?\{%- endif %\}\n', '', src, flags=re.S)
        self.assertEqual(n, 1, 'expected exactly one nbthread block in hap_header.tpl')
        legacy = hm.template_env.from_string(stripped)
        for coraza in (None, 'x:1'):
            want = legacy.render(cluster_secret='s', syslog_target='/log.sock',
                                 coraza_spoe_backend=coraza)
            self.assertEqual(render(coraza_spoe_backend=coraza), want)
            self.assertEqual(render(coraza_spoe_backend=coraza, nbthread=None), want)

    def test_set_renders_one_directive_in_global_only(self):
        out = render(nbthread=1)
        self.assertEqual(len(re.findall(r'^\s*nbthread 1$', out, re.M)), 1)
        glob = out.split('\nresolvers ', 1)[0]
        self.assertIn('\n    nbthread 1\n', glob)
        self.assertLess(out.index('nbthread 1'), out.index('tune.ssl.default-dh-param'))
        # nothing else changed: removing the directive restores the unset render
        self.assertEqual(out.replace('\n    nbthread 1', '', 1).count('nbthread 1'), 0)

    def test_no_cpu_map_or_thread_groups_rendered(self):
        for kw in ({}, {'nbthread': 1}):
            out = '\n'.join(l for l in render(**kw).splitlines()
                            if not l.lstrip().startswith('#'))
            for bad in ('cpu-map', 'thread-groups', 'nbtgroups'):
                self.assertNotIn(bad, out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
