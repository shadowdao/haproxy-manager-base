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

A THIRD property, added after an adversarial mutation audit: every assertion
here must be scoped to the CODE, not the surrounding prose. This file's own
comment blocks quote ACL names, rule fragments and even whole rules to explain
them -- which means a bare `assertIn` / `re.search` / `str.index` run over the
raw rendered config passes just as happily when the real rule has been deleted
(or merely commented out) and only its explanation survives. The audit proved
this concretely: commenting out the entire redirect rule, or the
`acl wp_admin_allowed` line, or all five normalizers, left the previous version
of this file at 26/26 PASS. See `rule_lines()` below, and use it (or one of the
guarded helpers built on it) for every assertion about whether a rule exists,
what it says, or where it sits relative to another rule. Do not add a new
`self.cfg.index(...)`, `self.assertIn(x, self.cfg)`, or `re.search(pattern,
self.cfg)` to this file -- none of them can tell code from comment.

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


# ---------------------------------------------------------------------------
# Comment-safe config inspection
#
# Every helper below operates on `rule_positions()`'s output, never on the raw
# rendered string. That is the one rule this whole module exists to enforce on
# itself: a mutation audit found that commenting out a real rule (prefixing it
# with '#', or -- more slyly -- deleting it and appending its own text as a
# TRAILING comment on the line above) left the previous version of these tests
# fully green, because plain `str.index` / `assertIn` / `re.search` over
# `self.cfg` cannot distinguish code from a comment that merely quotes it.
# ---------------------------------------------------------------------------

def rule_positions(cfg, needle):
    """[(comment-stripped line, char offset in cfg)] for every non-comment
    line containing `needle`, in document order.

    Two things a bare substring/regex search over `self.cfg` gets wrong, both
    fixed here:

      1. A line that is ENTIRELY a comment (starts with '#' once stripped) is
         dropped. This is necessary but not sufficient -- see (2).
      2. A line that MIXES real config with a trailing comment
         (`live-code  # note`, or the decoy `live-code  # was: <the other
         rule's exact text>`) is truncated at the first ' #' before matching,
         so text stuffed into a trailing comment cannot masquerade as the
         rule itself. A real HAProxy comment always starts at a '#' preceded
         by whitespace here -- none of these templates use bare '#' as a
         value character -- so this truncation does not clip real rules.

    Returning (line, position) pairs together -- rather than making callers
    re-derive one from the other with a second `cfg.index(line)` -- also
    avoids a subtler bug: if the same comment-stripped line occurs twice
    (e.g. a duplicated rule), re-deriving the position with `str.index` always
    finds the FIRST copy regardless of which one you meant. Walking the file
    once and recording positions as we go keeps first/last unambiguous.
    """
    out = []
    pos = 0
    for raw in cfg.split('\n'):
        stripped = raw.strip()
        if stripped and not stripped.startswith('#'):
            code = stripped.split(' #', 1)[0].rstrip()
            if code and needle in code:
                out.append((code, pos))
        pos += len(raw) + 1  # +1 for the '\n' split() consumed
    return out


def rule_lines(cfg, needle):
    """Comment-stripped rule lines containing `needle` (text only, no
    position). See `rule_positions()` for what this guards against. Every
    assertion about a RULE's presence or content must go through this (or
    `rule_positions`/the guarded helpers below) -- never a bare
    `needle in cfg` or `re.search(pattern, cfg)`.
    """
    return [line for line, _ in rule_positions(cfg, needle)]


def require_rule(cfg, needle, what=None):
    """The single rule line containing `needle`.

    Raises a plain AssertionError naming what was being looked for -- not
    IndexError from an unguarded `rule_lines(...)[0]`, and not
    `ValueError: substring not found` from a bare `cfg.index(...)` -- when
    the rule is missing. A missing rule and a broken test harness must not
    look identical in a failure report.

    Raises the same way if `needle` is ambiguous (matches more than one rule
    line): silently taking the first match in that case would hide the
    ambiguity instead of surfacing it.
    """
    label = what or needle
    lines = rule_lines(cfg, needle)
    if not lines:
        raise AssertionError('no rule found for %r (expected: %s)' % (needle, label))
    if len(lines) > 1:
        raise AssertionError(
            '%r matched %d rule lines, expected exactly one (%s): %r'
            % (needle, len(lines), label, lines))
    return lines[0]


def require_position(cfg, needle, what=None, last=False):
    """(line, char offset) for an ordering assertion, guarded the same way as
    `require_rule` -- but tolerant of the needle matching multiple lines
    (e.g. a multi-line set-var "chain"), since ordering checks often want the
    first or last of several. Pass last=True for the last occurrence.
    """
    label = what or needle
    positions = rule_positions(cfg, needle)
    if not positions:
        raise AssertionError(
            'no rule found for %r, cannot check ordering (expected: %s)' % (needle, label))
    return positions[-1] if last else positions[0]


class WpAdminGate(unittest.TestCase):

    def setUp(self):
        self.cfg = render_listener()

    def test_wp_admin_path_acl_declared(self):
        line = require_rule(self.cfg, 'acl wp_admin_path', 'wp_admin_path ACL')
        self.assertIn('path_reg', line)

    def test_wp_admin_asset_acl_declared(self):
        line = require_rule(self.cfg, 'acl wp_admin_asset', 'wp_admin_asset ACL')
        self.assertIn('path_reg', line)

    def test_wp_admin_allowed_acl_declared(self):
        line = require_rule(self.cfg, 'acl wp_admin_allowed', 'wp_admin_allowed ACL')
        self.assertIn('path_end', line)

    def test_wp_gate_exempt_acl_declared(self):
        """Scoped to the ACL line itself, not `self.cfg` as a whole -- the
        surrounding prose (see hap_listener.tpl's "per-site opt-out" comment)
        also spells out /etc/haproxy/wpadmin_gate_exempt.list verbatim, so an
        unscoped `assertIn` would still pass with the real ACL deleted.
        """
        line = require_rule(self.cfg, 'acl wp_gate_exempt', 'wp_gate_exempt ACL')
        self.assertIn('/etc/haproxy/wpadmin_gate_exempt.list', line)

    def test_allowlist_entries_present(self):
        """wp-login.php loads its own css/js from /wp-admin/ -- see module docstring."""
        line = require_rule(self.cfg, 'acl wp_admin_allowed', 'wp_admin_allowed ACL')
        for entry in ALLOWLIST:
            with self.subTest(entry=entry):
                self.assertIn(entry, line)

    def test_static_asset_dirs_allowed(self):
        line = require_rule(self.cfg, 'acl wp_admin_asset', 'wp_admin_asset ACL')
        self.assertRegex(line, r'path_reg.*\(css\|js\|images\)')

    def test_install_php_is_NOT_allowlisted(self):
        """install.php is deliberately gated -- a takeover vector on abandoned installs."""
        line = require_rule(self.cfg, 'acl wp_admin_allowed', 'wp_admin_allowed ACL')
        self.assertNotIn('install.php', line)

    def test_redirect_rule_has_all_exclusions(self):
        rule = require_rule_by_predicate(
            self.cfg, 'http-request redirect', lambda ln: 'wp_admin_path' in ln,
            'wp-admin redirect rule')
        for excl in EXCLUSIONS:
            with self.subTest(exclusion=excl):
                self.assertIn(excl, rule)

    def test_rule_renders_after_real_ip_resolution(self):
        """is_whitelisted reads txn.real_ip; before the set-var chain it is unset."""
        _, setvar_pos = require_position(self.cfg, 'set-var(txn.real_ip)',
                                          'real_ip set-var chain')
        _, rule_pos = require_position(self.cfg, 'wp_admin_path', 'wp_admin_path ACL/rule')
        self.assertLess(setvar_pos, rule_pos,
                         'wp_admin_path renders before txn.real_ip is resolved')

    def test_rule_renders_after_has_wp_logged_in_declared(self):
        """HAProxy resolves ACLs as it parses; use-before-declare fails."""
        _, decl_pos = require_position(self.cfg, 'acl has_wp_logged_in',
                                        'has_wp_logged_in ACL declaration')
        _, rule_pos = require_position(self.cfg, 'wp_admin_path', 'wp_admin_path ACL/rule')
        self.assertLess(decl_pos, rule_pos,
                         'wp_admin_path renders before has_wp_logged_in is declared')

    def test_only_one_has_wp_logged_in_declaration(self):
        self.assertEqual(len(rule_lines(self.cfg, 'acl has_wp_logged_in')), 1)

    def test_allowlist_entries_are_anchored_to_wp_admin(self):
        """Bare `path_end /admin-ajax.php` also matches
        /wp-admin/evil/admin-ajax.php, which ALSO matches wp_admin_path
        (path_reg only requires /wp-admin/ to appear somewhere) -- an
        attacker-inserted path segment would then sail through the
        allowlist ungated. Entries must be anchored to sit directly under
        wp-admin/. Scoped to the captured ACL line only, since the
        surrounding comment block also mentions these bare filenames.
        """
        line = require_rule(self.cfg, 'acl wp_admin_allowed', 'wp_admin_allowed ACL')
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
        _, last_real_ip_pos = require_position(self.cfg, 'set-var(txn.real_ip)',
                                                'real_ip set-var chain', last=True)
        _, wp_login_pos = require_position(self.cfg, 'set-var(txn.wp_login_url)',
                                            'wp_login_url set-var')
        _, redirect_pos = require_position(
            self.cfg, 'http-request redirect code 302 location %[var(txn.wp_login_url)]',
            'wp-admin redirect rule')
        self.assertLess(last_real_ip_pos, wp_login_pos,
                         'wp_login_url set-var must render after the real_ip set-var chain')
        self.assertLess(wp_login_pos, redirect_pos,
                         'wp_login_url set-var must render before the redirect rule that uses it')

    def test_redirect_rule_uses_setvar_not_inline_regsub(self):
        """Guards against reintroducing the rejected inline form."""
        rule = require_rule_by_predicate(
            self.cfg, 'http-request redirect', lambda ln: 'wp_admin_path' in ln,
            'wp-admin redirect rule')
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
        rule = require_rule_by_predicate(
            self.cfg, 'http-request redirect', lambda ln: 'wp_admin_path' in ln,
            'wp-admin redirect rule')
        self.assertIn('wp_admin_safe_path', rule)
        self.assertNotIn('!wp_admin_safe_path', rule,
                          'wp_admin_safe_path must be a positive condition, not negated')

    def test_wp_admin_safe_path_acl_declared(self):
        line = require_rule(self.cfg, 'acl wp_admin_safe_path', 'wp_admin_safe_path ACL')
        self.assertIn('path_reg', line)

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


def require_rule_by_predicate(cfg, needle, predicate, what):
    """Like require_rule(), but for rules identified by needle + a predicate
    over the comment-stripped line (e.g. "the `http-request redirect` line
    that also mentions wp_admin_path", since the frontend has more than one
    `http-request redirect`). Raises a clear AssertionError, not IndexError
    or a silently-empty match, if no line satisfies both.
    """
    candidates = [ln for ln in rule_lines(cfg, needle) if predicate(ln)]
    if not candidates:
        raise AssertionError('no rule found matching %s' % what)
    if len(candidates) > 1:
        raise AssertionError('%s matched more than one rule line: %r' % (what, candidates))
    return candidates[0]


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
        """normalize-uri is experimental in 3.0; without this HAProxy refuses
        to start (`haproxy -c` exits 1, ALERT). That does NOT crash-loop the
        container, though -- see hap_header.tpl's comment and
        haproxy_manager.py's start_haproxy()/do_initial_setup(): the failure
        is swallowed, and the container comes up with haproxy simply never
        running. This test exists so that silent-outage mode is never
        reintroduced by dropping this line.
        """
        lines = rule_lines(self.header, 'expose-experimental-directives')
        matches = [ln for ln in lines if ln == 'expose-experimental-directives']
        self.assertTrue(
            matches, 'expose-experimental-directives missing from the global section')

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
        lines = [ln for ln in rule_lines(self.cfg, 'http-request normalize-uri')
                 if ln.startswith('http-request normalize-uri')]
        names = [ln.split('normalize-uri ', 1)[1] for ln in lines]
        self.assertEqual(
            names, list(NORMALIZERS),
            'normalize-uri directives are missing, reordered, or duplicated: %r' % names)

    def test_normalisation_precedes_every_path_based_rule(self):
        """A normalizer placed after a path rule normalises nothing for it."""
        norm_positions = []
        for n in NORMALIZERS:
            _, pos = require_position(self.cfg, 'http-request normalize-uri ' + n,
                                       'normalizer: ' + n)
            norm_positions.append(pos)
        last_norm = max(norm_positions)
        for marker in ('acl is_health_check', 'acl wp_login_path',
                       'acl xmlrpc_path', 'acl wp_batch_path',
                       'acl wp_admin_path', 'http-request set-path'):
            with self.subTest(rule=marker):
                _, marker_pos = require_position(self.cfg, marker, marker)
                self.assertLess(last_norm, marker_pos,
                                 marker + ' renders before URI normalisation')

    def test_query_sort_by_name_is_not_enabled(self):
        """query-sort-by-name reorders query parameters, which would break
        anything that signs or caches on the exact query string. This is NOT
        because the enabled normalizers already leave the query alone --
        percent-to-uppercase and percent-decode-unreserved rewrite the WHOLE
        request-target, query string included (see hap_listener.tpl's BLAST
        RADIUS comment) -- it is a deliberate line between "case-fold /
        decode" (no-ops under RFC 3986) and "reorder" (not a no-op for a
        signed/cached query string).
        """
        self.assertFalse(rule_lines(self.cfg, 'normalize-uri query-sort-by-name'))

    def test_dotdot_normalizer_uses_full(self):
        """Without "full", ".." segments that climb above the root are left in
        place and /../../wp-admin/plugins.php survives -- measured.
        """
        lines = rule_lines(self.cfg, 'normalize-uri path-strip-dotdot')
        self.assertTrue(lines, 'missing normalizer: path-strip-dotdot')
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
        acl_line = require_rule(self.cfg, 'acl path_has_encoded_sep', 'path_has_encoded_sep ACL')
        self.assertIn('%2f', acl_line.lower())

    def test_encoded_separator_deny_is_scoped_to_wp_admin(self):
        """A blanket "deny any %2F in any path" would break non-WordPress
        customer apps that legitimately pass an encoded slash in a path
        parameter. The deny must be conditioned on the path mentioning
        wp-admin.
        """
        denies = [ln for ln in rule_lines(self.cfg, 'path_has_encoded_sep')
                  if ln.startswith('http-request deny')]
        self.assertTrue(denies, 'no deny rule for encoded separators')
        for d in denies:
            self.assertIn('wp_admin_word', d)

    def test_encoded_separator_deny_honors_the_same_whitelist(self):
        denies = [ln for ln in rule_lines(self.cfg, 'path_has_encoded_sep')
                  if ln.startswith('http-request deny')]
        self.assertTrue(denies, 'no deny rule for encoded separators')
        for d in denies:
            for excl in ('!has_wp_logged_in', '!wp_gate_exempt', '!is_local',
                         '!is_trusted_ip', '!is_whitelisted'):
                with self.subTest(rule=d, exclusion=excl):
                    self.assertIn(excl, d)

    def test_encoded_separator_acl_matches_a_substring_not_a_prefix(self):
        """/blog%2Fwp-admin/plugins.php hides the separator BEFORE "wp-admin",
        where an anchored pattern never matches, and OLS still resolves it.
        """
        acl_line = require_rule(self.cfg, 'acl path_has_encoded_sep', 'path_has_encoded_sep ACL')
        self.assertIn('-m sub', acl_line)

    def test_wp_admin_asset_bypass_cannot_cover_a_php_entrypoint(self):
        """The asset bypass anchored its prefix but not its suffix, so
        /wp-admin/css/../plugins.php took it and the backend then resolved
        ".." and booted plugins.php. path-strip-dotdot is the real fix; this
        keeps the bypass structurally incapable of covering PHP.
        """
        acl_line = require_rule(self.cfg, 'acl wp_admin_asset', 'wp_admin_asset ACL')
        self.assertIn('.php', acl_line,
                      'wp_admin_asset must exclude .php explicitly')

    def test_wp_admin_asset_pattern_is_end_of_flags_guarded(self):
        """A pattern starting with "(" makes HAProxy warn on EVERY load/reload:

            parsing acl 'wp_admin_asset' : matching 'path_reg' for pattern
            '(^|/)wp-admin/...' is likely a mistake ... Maybe you need to
            remove the extraneous space before '('.

        "--" is the end-of-flags marker HAProxy itself names as the fix. It is
        cosmetic to matching but not to operations: an unsilenced warning on
        every reload on every host trains people to skim past warnings, which
        is how a real one gets missed. Assert the pattern is still the one we
        think it is, so this can never pass by the pattern having been changed.
        """
        acl_line = require_rule(self.cfg, 'acl wp_admin_asset', 'wp_admin_asset ACL')
        self.assertRegex(
            acl_line, r'path_reg\s+--\s+\(',
            'wp_admin_asset pattern begins with "(" and MUST be preceded by "--"')
        self.assertIn('(^|/)wp-admin/(css|js|images)/', acl_line)

    def test_case_insensitive_acl_and_regsub_are_kept_in_sync(self):
        """A case-insensitive wp_admin_path with a case-sensitive regsub is an
        INFINITE REDIRECT LOOP: regsub finds no "/wp-admin/" in
        "/WP-ADMIN/plugins.php", returns `path` unchanged, and the Location
        then points at the request's own URL.
        """
        acl_line = require_rule(self.cfg, 'acl wp_admin_path', 'wp_admin_path ACL')
        setvar_line = require_rule(self.cfg, 'set-var(txn.wp_login_url)', 'wp_login_url set-var')
        acl_ci = bool(re.search(r'path_reg\s+-i\s', acl_line))
        regsub_ci = bool(re.search(r'regsub\([^)]*,\s*i\)', setvar_line))
        self.assertEqual(
            acl_ci, regsub_ci,
            'wp_admin_path case-sensitivity (%s) and regsub flags (%s) disagree'
            % (acl_line, setvar_line))


if __name__ == '__main__':
    unittest.main(verbosity=2)
