#!/usr/bin/env python3
"""Regression tests for per-client-IP rate limiting on POST /xmlrpc.php.

Why this file exists
--------------------
POST /xmlrpc.php floods were unthrottled fleet-wide. The generic frontend
rate limits (hap_listener.tpl) trigger at 3000/5000 req/10s -- i.e. 300-500
req/s -- but the observed floods run at a few req/s for hours, well under
that ceiling. The existing wp_bruteforce mechanism (dedicated stick-table,
60s window, per real client IP) solves exactly this shape of problem for
POST /wp-login.php; this change adds an equivalent dedicated table/rule pair
for POST /xmlrpc.php.

This is only safe to key on var(txn.real_ip) because of the trusted-proxy
gate added earlier (release 2026.08.3, see test-trusted-proxy-gate.py) --
before that fix, a direct client could spoof any client IP via
X-Forwarded-For and evade all per-IP tracking.

These tests pin:
  - a dedicated stick-table for xmlrpc tracking exists in
    hap_security_tables.tpl (own sc slot / own counter -- not sharing the
    wp_bruteforce counter, so a wp-login brute-force run and an xmlrpc flood
    from the same IP don't inflate each other's rate)
  - the tracking rule only fires on POST /xmlrpc.php (path_end, so
    subdirectory WP installs are covered)
  - the limiting rule tarpits over the chosen threshold
  - the limiting rule honors the same whitelist as every other rule in the
    file (!is_local !is_trusted_ip !is_whitelisted)
  - xmlrpc is not blocked outright -- only the rate-limit ACL is present,
    there's no blanket deny of the path

Running
-------
    python3 scripts/test-xmlrpc-rate-limit.py
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


def render_listener():
    return haproxy_manager.template_env.get_template('hap_listener.tpl').render(
        crt_path='/etc/haproxy/certs',
        suspension_enabled=False,
        coraza_spoe_backend=None,
    )


def render_security_tables():
    return haproxy_manager.template_env.get_template(
        'hap_security_tables.tpl').render()


class XmlrpcRateLimit(unittest.TestCase):

    def setUp(self):
        self.listener_cfg = render_listener()
        self.tables_cfg = render_security_tables()

    def test_dedicated_stick_table_defined(self):
        """A dedicated table (not wp_bruteforce) tracks xmlrpc requests, so a
        wp-login brute-force run and an xmlrpc flood from the same IP can't
        inflate each other's rate counter."""
        self.assertRegex(
            self.tables_cfg,
            r'backend\s+xmlrpc_bruteforce\s*\n\s*stick-table\s+type\s+ip\b.*store.*http_req_rate',
        )
        # Must not be the same table wp-login already uses.
        self.assertNotIn('backend wp_bruteforce\n    stick-table type ip size 100k expire 30m store http_req_rate(60s)\nbackend xmlrpc_bruteforce', self.tables_cfg)

    def test_xmlrpc_path_acl_uses_path_end(self):
        """path_end (not path_beg) so subdirectory WP installs are covered,
        matching the wp-login rule's reasoning."""
        self.assertRegex(
            self.listener_cfg,
            r'acl\s+xmlrpc_path\s+path_end\s+/xmlrpc\.php',
        )

    def test_tracking_rule_only_fires_on_post_xmlrpc(self):
        self.assertRegex(
            self.listener_cfg,
            r'http-request\s+track-sc2\s+var\(txn\.real_ip\)\s+table\s+xmlrpc_bruteforce\s+if\s+METH_POST\s+xmlrpc_path',
        )

    def test_limiting_rule_tarpits_over_threshold_with_whitelist(self):
        pattern = (
            r'http-request\s+tarpit\s+deny_status\s+429\s+if\s+METH_POST\s+xmlrpc_path\s+'
            r'\{\s*sc_http_req_rate\(2\)\s+gt\s+(\d+)\s*\}\s+'
            r'!is_local\s+!is_trusted_ip\s+!is_whitelisted'
        )
        match = re.search(pattern, self.listener_cfg)
        self.assertIsNotNone(
            match, 'expected a tarpit rule tracking sc2 with the full whitelist')
        threshold = int(match.group(1))
        self.assertGreater(threshold, 0)

    def test_xmlrpc_not_blocked_outright(self):
        """The endpoint must remain functional for clients under the
        threshold -- only a rate-limit ACL, no blanket deny of the path."""
        self.assertNotRegex(
            self.listener_cfg,
            r'http-request\s+deny\s+deny_status\s+\d+\s+if\s+(?:METH_POST\s+)?xmlrpc_path\s*(?:!is_local|\n)',
        )

    def test_rule_order_after_wp_login_block(self):
        """Not load-bearing for correctness (mutually exclusive paths), but
        keep the new block grouped with the other WordPress-specific rules
        rather than scattered elsewhere in the file."""
        wp_login_idx = self.listener_cfg.index('wp_login_path')
        xmlrpc_idx = self.listener_cfg.index('xmlrpc_path')
        self.assertLess(wp_login_idx, xmlrpc_idx)


if __name__ == '__main__':
    unittest.main(verbosity=2)
