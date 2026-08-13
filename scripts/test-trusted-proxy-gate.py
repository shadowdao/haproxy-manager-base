#!/usr/bin/env python3
"""Regression tests for the trusted-proxy header gate in hap_listener.tpl.

Why this file exists
--------------------
txn.real_ip was derived from CF-Connecting-IP / X-Real-IP / X-Forwarded-For
with no check on the peer, so any direct client could assert any client IP.
That variable drives rate limiting, the trusted-IP whitelist, the wp-login
brute-force table and cookie challenge, the wp-json/batch/v1 virtual patch,
IP blocking, and Coraza's src-ip -- so a spoofed header bypassed all of them.

These tests pin the invariant that the header strip is rendered BEFORE any
real-IP resolution. Ordering is the whole fix: a del-header emitted after the
set-var chain would parse fine, validate fine, and do nothing.

Running
-------
    python3 scripts/test-trusted-proxy-gate.py
"""

import os
import re
import sys
import logging
import tempfile
import unittest

MODULE_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
)
os.chdir(MODULE_DIR)
sys.path.insert(0, MODULE_DIR)

_LOG_DIR = tempfile.mkdtemp(prefix='haproxy-mgr-test-logs-')
_real_file_handler = logging.FileHandler
logging.FileHandler = (
    lambda filename, *a, **kw: _real_file_handler(
        os.path.join(_LOG_DIR, os.path.basename(filename)), *a, **kw)
)

import haproxy_manager  # noqa: E402

GATED_HEADERS = ('CF-Connecting-IP', 'X-Real-IP', 'X-Forwarded-For')


def render_listener():
    return haproxy_manager.template_env.get_template('hap_listener.tpl').render(
        crt_path='/etc/haproxy/certs',
        suspension_enabled=False,
        coraza_spoe_backend=None,
    )


class TrustedProxyGate(unittest.TestCase):

    def setUp(self):
        self.cfg = render_listener()

    def test_trusted_proxy_acl_is_defined(self):
        self.assertIn('acl from_trusted_proxy src', self.cfg)
        self.assertIn('/etc/haproxy/cloudflare_ips.list', self.cfg)
        self.assertIn('/etc/haproxy/trusted_proxies.list', self.cfg)

    def test_each_header_is_deleted_for_untrusted_peers(self):
        for header in GATED_HEADERS:
            with self.subTest(header=header):
                pattern = (r'http-request\s+del-header\s+%s\s+if\s+!from_trusted_proxy'
                           % re.escape(header))
                self.assertRegex(self.cfg, pattern)

    def test_strip_precedes_real_ip_resolution(self):
        """The ordering invariant. A strip after the set-var chain is a no-op."""
        last_strip = max(
            self.cfg.index('del-header %s' % h) for h in GATED_HEADERS
        )
        first_setvar = self.cfg.index('set-var(txn.real_ip)')
        self.assertLess(
            last_strip, first_setvar,
            'del-header rules must be rendered before set-var(txn.real_ip)')

    def test_src_fallback_still_present(self):
        """Direct clients must fall through to the real TCP peer."""
        self.assertIn('set-var(txn.real_ip) src', self.cfg)


if __name__ == '__main__':
    unittest.main(verbosity=2)
