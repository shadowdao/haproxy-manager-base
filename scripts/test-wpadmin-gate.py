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

# The normalizer set, in the order it MUST render. Decoding has to precede the
# path walkers or "%2e%2e" is decoded to ".." only after path-strip-dotdot has
# already run, leaving the ".." unresolved -- measured against real HAProxy
# 3.0.11, both orders side by side.
NORMALIZERS = ('percent-to-uppercase',
               'percent-decode-unreserved',
               'path-merge-slashes',
               'path-strip-dot',
               'path-strip-dotdot full')


def render_listener():
    return haproxy_manager.template_env.get_template('hap_listener.tpl').render(
        crt_path='/etc/haproxy/certs',
        suspension_enabled=False,
        coraza_spoe_backend=None,
    )


def render_header():
    return haproxy_manager.template_env.get_template('hap_header.tpl').render(
        cluster_secret=None,
    )


def rule_lines(cfg, needle):
    """Non-comment config lines containing `needle`.

    Every assertion about a RULE must be scoped this way. This file's
    surrounding comment blocks quote the ACL names and even whole rules, so a
    bare `assertIn` over the rendered config passes just as happily when the
    rule has been deleted and only its explanation remains.
    """
    return [ln.strip() for ln in cfg.split('\n')
            if needle in ln and not ln.strip().startswith('#')]


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

    def test_allowlist_entries_are_anchored_to_wp_admin(self):
        """Bare `path_end /admin-ajax.php` also matches
        /wp-admin/evil/admin-ajax.php, which ALSO matches wp_admin_path
        (path_reg only requires /wp-admin/ to appear somewhere) -- an
        attacker-inserted path segment would then sail through the
        allowlist ungated. Entries must be anchored to sit directly under
        wp-admin/. Scoped to the captured ACL line only, since the
        surrounding comment block also mentions these bare filenames.
        """
        m = re.search(r'acl\s+wp_admin_allowed\s+path_end([^\n]*)', self.cfg)
        self.assertIsNotNone(m, 'wp_admin_allowed ACL not found')
        line = m.group(1)
        for entry in ALLOWLIST:
            with self.subTest(entry=entry):
                self.assertIn('/wp-admin' + entry, line)
                self.assertNotRegex(
                    line, r'(?<!wp-admin)' + re.escape(entry) + r'(?!\S)',
                    'found a bare, unanchored allowlist entry: ' + entry)

    def test_wp_login_url_setvar_renders_in_correct_order(self):
        """The inline regsub-in-`location` form is rejected by real HAProxy
        3.0.11 (invalid arg 2 in converter 'regsub'), so the regsub is
        computed in its own set-var line instead. That set-var must render
        after the set-var(txn.real_ip) chain (it must not disturb that
        load-bearing chain) and before the redirect rule that consumes it.
        """
        self.assertIn('set-var(txn.wp_login_url)', self.cfg)
        last_real_ip_setvar = self.cfg.rindex('set-var(txn.real_ip)')
        wp_login_setvar = self.cfg.index('set-var(txn.wp_login_url)')
        redirect_rule = self.cfg.index('http-request redirect code 302 location %[var(txn.wp_login_url)]')
        self.assertLess(last_real_ip_setvar, wp_login_setvar,
                         'wp_login_url set-var must render after the real_ip set-var chain')
        self.assertLess(wp_login_setvar, redirect_rule,
                         'wp_login_url set-var must render before the redirect rule that uses it')

    def test_redirect_rule_uses_setvar_not_inline_regsub(self):
        """Guards against reintroducing the rejected inline form."""
        m = re.search(r'http-request redirect[^\n]*wp_admin_path[^\n]*', self.cfg)
        self.assertIsNotNone(m, 'wp-admin redirect rule not found')
        rule = m.group(0)
        self.assertIn('%[var(txn.wp_login_url)]', rule)
        self.assertNotIn('regsub', rule)

    def test_redirect_rule_requires_safe_path(self):
        """OPEN REDIRECT guard. The redirect target is built by rewriting
        `path` with regsub, which only replaces the matched substring --
        everything before "/wp-admin/" survives untouched in the output.
        Three concrete requests turn that into an off-site `Location:`
        header: "//evil.example.com/wp-admin/x.php" (protocol-relative,
        browsers resolve "//host/path" to "https://host/path"),
        "/\\evil.example.com/wp-admin/x.php" (browsers normalise a leading
        "/\\" the same as "//"), and an RFC 7230 absolute-form request
        target ("https://evil.example.com/wp-admin/x.php") which can make
        HAProxy's `path` fetch return a full URI. wp_admin_safe_path
        (requiring a well-formed absolute path) must be a POSITIVE
        condition on the redirect rule -- scoped to the captured rule line
        only, since the surrounding comment block also mentions this ACL
        name and a bare substring match would pass even if the condition
        were dropped from the rule itself.
        """
        m = re.search(r'http-request redirect[^\n]*wp_admin_path[^\n]*', self.cfg)
        self.assertIsNotNone(m, 'wp-admin redirect rule not found')
        rule = m.group(0)
        self.assertIn('wp_admin_safe_path', rule)
        self.assertNotIn('!wp_admin_safe_path', rule,
                          'wp_admin_safe_path must be a positive condition, not negated')

    def test_wp_admin_safe_path_acl_declared(self):
        self.assertRegex(self.cfg, r'acl\s+wp_admin_safe_path\s+path_reg')

    def test_unsafe_wp_admin_path_is_denied_not_passed_through(self):
        """wp_admin_safe_path being a POSITIVE condition on the redirect means
        a path that fails it is simply not redirected -- which used to mean it
        fell through to the backend UNGATED, i.e. exactly the PHP-booting
        request the gate exists to stop. Normalisation removes the "//"
        spelling of that, but not "/\\", so the fall-through must be closed
        with an explicit deny rather than left implicit.
        """
        denies = rule_lines(self.cfg, '!wp_admin_safe_path')
        self.assertTrue(denies,
                        'no rule denies a wp-admin path that fails wp_admin_safe_path')
        self.assertTrue(any(d.startswith('http-request deny') for d in denies),
                        'the !wp_admin_safe_path rule must be a deny: %r' % denies)


class UriNormalisation(unittest.TestCase):
    """The gate matches the RAW path; the backend normalises and decodes it.
    Every gap between those is a bypass -- five were found this way. These
    tests pin the normalisation that closes the gap as a class.

    NOTE: these are config-TEXT assertions. They are necessary but NOT
    sufficient: the previous revision of this file passed while five live
    bypasses shipped. The real evidence is the behavioural matrix run against
    real haproxy 3.0.11 with raw sockets -- see
    .superpowers/sdd/2026-08-14-wpadmin-edge-gate/task-4-normalize-report.md.
    """

    def setUp(self):
        self.cfg = render_listener()
        self.header = render_header()

    def test_experimental_directives_exposed_in_global(self):
        """normalize-uri is experimental in 3.0; without this HAProxy does not
        start at all (ALERT, exit 1), which crash-loops the container.
        """
        self.assertTrue(
            [ln for ln in self.header.split('\n')
             if ln.strip() == 'expose-experimental-directives'],
            'expose-experimental-directives missing from the global section')

    def test_all_normalizers_render(self):
        for norm in NORMALIZERS:
            with self.subTest(normalizer=norm):
                self.assertTrue(
                    rule_lines(self.cfg, 'normalize-uri ' + norm),
                    'missing normalizer: ' + norm)

    def test_normalizer_order_decode_before_path_walkers(self):
        """Reverse this order and /wp-admin/js/%2e%2e/plugins.php reaches the
        ACLs as /wp-admin/js/../plugins.php -- decoded but unresolved.
        """
        rendered = [ln for ln in self.cfg.split('\n')
                    if ln.strip().startswith('http-request normalize-uri')]
        names = [ln.strip().split('normalize-uri ', 1)[1] for ln in rendered]
        self.assertEqual(names, list(NORMALIZERS))

    def test_normalisation_precedes_every_path_based_rule(self):
        """A normalizer placed after a path rule normalises nothing for it."""
        last_norm = max(self.cfg.index('http-request normalize-uri ' + n)
                        for n in NORMALIZERS)
        for marker in ('acl is_health_check', 'acl wp_login_path',
                       'acl xmlrpc_path', 'acl wp_batch_path',
                       'acl wp_admin_path', 'http-request set-path'):
            with self.subTest(rule=marker):
                self.assertLess(last_norm, self.cfg.index(marker),
                                marker + ' renders before URI normalisation')

    def test_query_sort_by_name_is_not_enabled(self):
        """It reorders query parameters, breaking anything that signs or caches
        on the exact query string, and buys this gate nothing (every rule here
        matches on `path`, which excludes the query).
        """
        self.assertFalse(rule_lines(self.cfg, 'normalize-uri query-sort-by-name'))

    def test_dotdot_normalizer_uses_full(self):
        """Without "full", ".." segments that climb above the root are left in
        place and /../../wp-admin/plugins.php survives -- measured.
        """
        lines = rule_lines(self.cfg, 'normalize-uri path-strip-dotdot')
        self.assertTrue(lines)
        for ln in lines:
            self.assertTrue(ln.endswith('path-strip-dotdot full'), ln)

    def test_encoded_separator_on_wp_admin_is_denied(self):
        """percent-decode-unreserved deliberately leaves %2F encoded ("/" is
        reserved), but OpenLiteSpeed decodes it and serves the file --
        /wp-admin%2Fplugins.php was measured booting PHP on the OLS tier while
        matching no wp-admin ACL. Normalisation cannot close this; it needs its
        own rule.
        """
        denies = [ln for ln in rule_lines(self.cfg, 'path_has_encoded_sep')
                  if ln.startswith('http-request deny')]
        self.assertTrue(denies, 'no deny rule for encoded separators')
        acl = rule_lines(self.cfg, 'acl path_has_encoded_sep')
        self.assertTrue(acl)
        self.assertIn('%2f', acl[0].lower())

    def test_encoded_separator_deny_is_scoped_to_wp_admin(self):
        """A blanket "deny any %2F in any path" would break non-WordPress
        customer apps that legitimately pass an encoded slash in a path
        parameter. The deny must be conditioned on the path mentioning
        wp-admin.
        """
        denies = [ln for ln in rule_lines(self.cfg, 'path_has_encoded_sep')
                  if ln.startswith('http-request deny')]
        for d in denies:
            self.assertIn('wp_admin_word', d)

    def test_encoded_separator_deny_honors_the_same_whitelist(self):
        denies = [ln for ln in rule_lines(self.cfg, 'path_has_encoded_sep')
                  if ln.startswith('http-request deny')]
        for d in denies:
            for excl in ('!has_wp_logged_in', '!wp_gate_exempt', '!is_local',
                         '!is_trusted_ip', '!is_whitelisted'):
                with self.subTest(rule=d, exclusion=excl):
                    self.assertIn(excl, d)

    def test_encoded_separator_acl_matches_a_substring_not_a_prefix(self):
        """/blog%2Fwp-admin/plugins.php hides the separator BEFORE "wp-admin",
        where an anchored pattern never matches, and OLS still resolves it.
        """
        acl = rule_lines(self.cfg, 'acl path_has_encoded_sep')[0]
        self.assertIn('-m sub', acl)

    def test_wp_admin_asset_bypass_cannot_cover_a_php_entrypoint(self):
        """The asset bypass anchored its prefix but not its suffix, so
        /wp-admin/css/../plugins.php took it and the backend then resolved
        ".." and booted plugins.php. path-strip-dotdot is the real fix; this
        keeps the bypass structurally incapable of covering PHP.
        """
        acl = rule_lines(self.cfg, 'acl wp_admin_asset')[0]
        self.assertIn('.php', acl,
                      'wp_admin_asset must exclude .php explicitly')

    def test_case_insensitive_acl_and_regsub_are_kept_in_sync(self):
        """A case-insensitive wp_admin_path with a case-sensitive regsub is an
        INFINITE REDIRECT LOOP: regsub finds no "/wp-admin/" in
        "/WP-ADMIN/plugins.php", returns `path` unchanged, and the Location
        then points at the request's own URL.
        """
        acl = rule_lines(self.cfg, 'acl wp_admin_path')[0]
        setvar = rule_lines(self.cfg, 'set-var(txn.wp_login_url)')[0]
        acl_ci = bool(re.search(r'path_reg\s+-i\s', acl))
        regsub_ci = bool(re.search(r'regsub\([^)]*,\s*i\)', setvar))
        self.assertEqual(
            acl_ci, regsub_ci,
            'wp_admin_path case-sensitivity (%s) and regsub flags (%s) disagree'
            % (acl, setvar))


if __name__ == '__main__':
    unittest.main(verbosity=2)
