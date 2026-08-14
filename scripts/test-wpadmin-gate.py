#!/usr/bin/env python3
"""Regression tests for the WordPress admin edge gate in hap_listener.tpl.

Why this file exists
--------------------
Unauthenticated GETs to /wp-admin/* were reaching PHP, booting WordPress just to
produce a login redirect and exhausting lsphp pools under a distributed
low-and-slow attack. The gate redirects them at the edge instead.

Two properties are easy to get wrong and invisible to `haproxy -c`:

  * ORDERING. `is_whitelisted` reads var(txn.real_ip). If the rule renders before
    the set-var chain, the whitelist evaluates against an unset variable.
  * THE ALLOWLIST. wp-login.php loads its OWN css/js from /wp-admin/. Dropping
    those entries leaves every login page on the fleet unstyled, while still
    returning 200 -- a silent regression.

Running
-------
    python3 scripts/test-wpadmin-gate.py
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

ALLOWLIST = ('/admin-ajax.php', '/admin-post.php',
             '/load-styles.php', '/load-scripts.php')
EXCLUSIONS = ('!wp_admin_allowed', '!wp_admin_asset', '!has_wp_logged_in',
              '!wp_gate_exempt', '!is_local', '!is_trusted_ip', '!is_whitelisted')


def render_listener():
    return haproxy_manager.template_env.get_template('hap_listener.tpl').render(
        crt_path='/etc/haproxy/certs',
        suspension_enabled=False,
        coraza_spoe_backend=None,
    )


class WpAdminGate(unittest.TestCase):

    def setUp(self):
        self.cfg = render_listener()

    def test_acls_declared(self):
        self.assertRegex(self.cfg, r'acl\s+wp_admin_path\s+path_reg')
        self.assertRegex(self.cfg, r'acl\s+wp_admin_asset\s+path_reg')
        self.assertRegex(self.cfg, r'acl\s+wp_admin_allowed\s+path_end')
        self.assertIn('/etc/haproxy/wpadmin_gate_exempt.list', self.cfg)

    def test_allowlist_entries_present(self):
        """wp-login.php loads its own css/js from /wp-admin/ -- see module docstring."""
        for entry in ALLOWLIST:
            with self.subTest(entry=entry):
                self.assertIn(entry, self.cfg)

    def test_static_asset_dirs_allowed(self):
        self.assertRegex(self.cfg, r'wp_admin_asset\s+path_reg.*\(css\|js\|images\)')

    def test_install_php_is_NOT_allowlisted(self):
        """install.php is deliberately gated -- a takeover vector on abandoned installs."""
        m = re.search(r'acl\s+wp_admin_allowed\s+path_end([^\n]*)', self.cfg)
        self.assertIsNotNone(m, 'wp_admin_allowed ACL not found')
        self.assertNotIn('install.php', m.group(1))

    def test_redirect_rule_has_all_exclusions(self):
        m = re.search(r'http-request redirect[^\n]*wp_admin_path[^\n]*', self.cfg)
        self.assertIsNotNone(m, 'wp-admin redirect rule not found')
        rule = m.group(0)
        for excl in EXCLUSIONS:
            with self.subTest(exclusion=excl):
                self.assertIn(excl, rule)

    def test_rule_renders_after_real_ip_resolution(self):
        """is_whitelisted reads txn.real_ip; before the set-var chain it is unset."""
        setvar = self.cfg.index('set-var(txn.real_ip)')
        rule = self.cfg.index('wp_admin_path')
        self.assertLess(setvar, rule)

    def test_rule_renders_after_has_wp_logged_in_declared(self):
        """HAProxy resolves ACLs as it parses; use-before-declare fails."""
        decl = self.cfg.index('acl has_wp_logged_in')
        rule = self.cfg.index('wp_admin_path')
        self.assertLess(decl, rule)

    def test_only_one_has_wp_logged_in_declaration(self):
        self.assertEqual(self.cfg.count('acl has_wp_logged_in'), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
