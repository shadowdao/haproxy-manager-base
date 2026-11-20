#!/usr/bin/env python3
"""BEHAVIOURAL test of the wp-admin edge gate against the REAL haproxy binary.

test-wpadmin-gate.py asserts on the TEXT of the rendered config. This file runs
the actual gate rules (extracted from the rendered hap_listener.tpl, not
re-typed) in a real haproxy and sends real requests, so the install-screen
exemption and its path-normalisation edge cases are measured, not inferred.

Only the exclusion ACLs that depend on the client address (is_local,
is_trusted_ip, is_whitelisted) are stubbed to never match: the test client is
127.0.0.1, which the real is_local would exempt wholesale. Everything else
(normalize-uri chain, wp_admin_* ACLs, deny rules, set-var, redirect) is the
production text.

A request that PASSES the gate gets 200 "ok" from a stub `http-request return`;
a gated one gets the edge 302 (Location: .../wp-login.php?redirect_to=...) or
the 403 deny.

Skips (exit 0, loud message) when no `haproxy` binary is on PATH. The Dockerfile
build has one, so the image build always runs it.

    python3 scripts/test-wpadmin-gate-behaviour.py
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.environ.setdefault('HAPROXY_MANAGER_DIR', os.path.abspath(os.path.join(HERE, '..')))

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    'wpadmin_gate_tests', os.path.join(HERE, 'test-wpadmin-gate.py'))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)

HAPROXY = shutil.which('haproxy')

# Code lines (comment-stripped) that make up the gate, in template order.
_KEEP = re.compile(
    r'^(?:'
    r'http-request normalize-uri '
    r'|acl (?:has_wp_logged_in|wp_gate_exempt|wp_admin_\w+|path_has_encoded_sep) '
    r'|http-request deny deny_status 403 if wp_admin'
    r'|http-request set-var\(txn\.wp_login_url\) '
    r'|http-request redirect code 302 location %\[var\(txn\.wp_login_url\)\]'
    r')')

# (description, raw request path, extra header, expected status, location-prefix)
PASS, REDIR, DENY = 200, 302, 403
LOGIN = '/wp-login.php?redirect_to='

CASES = [
    # --- the install/setup screens: exempt ------------------------------
    ('setup-config.php', '/wp-admin/setup-config.php', None, PASS, None),
    ('setup-config.php language step', '/wp-admin/setup-config.php?step=-1', None, PASS, None),
    ('install.php', '/wp-admin/install.php', None, PASS, None),
    ('install.php step 2', '/wp-admin/install.php?step=2', None, PASS, None),
    ('subdirectory install', '/blog/wp-admin/install.php', None, PASS, None),
    ('subdirectory setup-config', '/blog/wp-admin/setup-config.php', None, PASS, None),
    # spellings that NORMALISE to the exempt path are the same request to the backend
    ('dotdot normalises to the exempt page', '/wp-admin/css/../setup-config.php', None, PASS, None),
    ('encoded dot normalises to the exempt page', '/wp-admin/setup-config%2Ephp', None, PASS, None),
    ('double slash merges to the exempt page', '//wp-admin/install.php', None, PASS, None),
    # --- everything near them stays gated -------------------------------
    ('dashboard', '/wp-admin/', None, REDIR, LOGIN + '%2Fwp-admin%2F'),
    ('index.php', '/wp-admin/index.php', None, REDIR, LOGIN),
    ('upgrade.php is NOT exempt', '/wp-admin/upgrade.php', None, REDIR, LOGIN),
    ('plugins.php', '/wp-admin/plugins.php', None, REDIR, LOGIN),
    ('setup-config.php.php', '/wp-admin/setup-config.php.php', None, REDIR, LOGIN),
    ('setup-config.phpx', '/wp-admin/setup-config.phpx', None, REDIR, LOGIN),
    ('install.php.bak', '/wp-admin/install.php.bak', None, REDIR, LOGIN),
    ('case variant Setup-Config.php', '/wp-admin/Setup-Config.php', None, REDIR, LOGIN),
    ('case variant Install.php', '/wp-admin/Install.php', None, REDIR, LOGIN),
    ('upper-case dir WP-ADMIN', '/WP-ADMIN/install.php', None, REDIR, LOGIN),
    ('path info after the script', '/wp-admin/install.php/x', None, REDIR, LOGIN),
    ('trailing slash', '/wp-admin/install.php/', None, REDIR, LOGIN),
    ('inserted directory', '/wp-admin/evil/install.php', None, REDIR, LOGIN),
    ('inserted directory (setup-config)', '/wp-admin/x/setup-config.php', None, REDIR, LOGIN),
    ('dotdot climbs off the exempt page', '/wp-admin/install.php/../plugins.php', None, REDIR, LOGIN),
    ('asset dir dotdot to plugins.php', '/wp-admin/css/../plugins.php', None, REDIR, LOGIN),
    ('encoded slash separator', '/wp-admin%2Fsetup-config.php', None, DENY, None),
    ('encoded slash before wp-admin', '/blog%2Fwp-admin/install.php', None, DENY, None),
    ('backslash prefix (open redirect guard)', '/%5Cevil.example/wp-admin/plugins.php', None, DENY, None),
    # --- identity still passes ------------------------------------------
    ('logged-in cookie on plugins.php', '/wp-admin/plugins.php',
     'Cookie: wordpress_logged_in_abc=1', PASS, None),
]


def _free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _raw_get(port, path, header=None):
    req = 'GET %s HTTP/1.1\r\nHost: site.example.com\r\nConnection: close\r\n' % path
    if header:
        req += header + '\r\n'
    req += '\r\n'
    with socket.create_connection(('127.0.0.1', port), timeout=5) as s:
        s.sendall(req.encode('latin-1'))
        buf = b''
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    head = buf.split(b'\r\n\r\n', 1)[0].decode('latin-1')
    lines = head.split('\r\n')
    status = int(lines[0].split()[1])
    loc = None
    for ln in lines[1:]:
        if ln.lower().startswith('location:'):
            loc = ln.split(':', 1)[1].strip()
    return status, loc


@unittest.skipUnless(HAPROXY, 'SKIP: no haproxy binary on PATH (the image build has one)')
class WpAdminGateBehaviour(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cfg = gate.render_listener()
        lines = []
        for raw in cfg.split('\n'):
            stripped = raw.strip()
            if not stripped or stripped.startswith('#'):
                continue
            code = stripped.split(' #', 1)[0].rstrip()
            if _KEEP.match(code):
                lines.append(code)
        joined = '\n'.join(lines)
        # Guard against a silently empty extraction: every moving part must be there.
        for needle in ('normalize-uri path-strip-dotdot full', 'acl wp_admin_install',
                       'acl wp_admin_allowed', 'acl wp_admin_asset', 'acl wp_gate_exempt',
                       'acl has_wp_logged_in', 'acl path_has_encoded_sep',
                       'set-var(txn.wp_login_url)', 'http-request redirect code 302'):
            assert needle in joined, 'extraction lost %r' % needle

        cls.tmp = tempfile.mkdtemp(prefix='wpgate-behaviour-')
        exempt = os.path.join(cls.tmp, 'exempt.list')
        open(exempt, 'w').close()
        joined = joined.replace('/etc/haproxy/wpadmin_gate_exempt.list', exempt)
        cls.port = _free_port()
        conf = '\n'.join([
            'global',
            '    expose-experimental-directives',
            '    maxconn 100',
            'defaults',
            '    mode http',
            '    timeout connect 2s',
            '    timeout client 5s',
            '    timeout server 5s',
            'frontend gate',
            '    bind 127.0.0.1:%d' % cls.port,
            # client-address exclusions stubbed: the real is_local would match 127.0.0.1
            '    acl is_local src 203.0.113.1',
            '    acl is_trusted_ip src 203.0.113.2',
            '    acl is_whitelisted src 203.0.113.3',
            '    ' + joined.replace('\n', '\n    '),
            '    http-request return status 200 content-type text/plain string ok',
            '',
        ])
        cls.conf_path = os.path.join(cls.tmp, 'gate.cfg')
        with open(cls.conf_path, 'w') as f:
            f.write(conf)
        chk = subprocess.run([HAPROXY, '-c', '-f', cls.conf_path],
                             capture_output=True, text=True)
        assert chk.returncode == 0, 'haproxy -c rejected the gate:\n' + chk.stdout + chk.stderr
        cls.proc = subprocess.Popen([HAPROXY, '-db', '-f', cls.conf_path],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise AssertionError('haproxy did not start listening')

    @classmethod
    def tearDownClass(cls):
        proc = getattr(cls, 'proc', None)
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(getattr(cls, 'tmp', ''), ignore_errors=True)

    def test_cases(self):
        for desc, path, header, want, loc_prefix in CASES:
            with self.subTest(desc=desc, path=path):
                status, loc = _raw_get(self.port, path, header)
                self.assertEqual(status, want, '%s: %s -> %s %s' % (desc, path, status, loc))
                if loc_prefix is not None:
                    self.assertIsNotNone(loc, 'no Location header for ' + path)
                    self.assertTrue(loc.endswith(loc_prefix) or loc_prefix in loc,
                                    '%s: Location %r' % (path, loc))
                    # redirect must stay same-origin (open-redirect guard)
                    self.assertTrue(loc.startswith('/') and not loc.startswith('//'), loc)

    def test_nul_byte_after_exempt_name_is_not_exempt(self):
        """%00 is not an unreserved escape, so it is not decoded and the path no
        longer ends in the exempt name. Anything but a pass-through is fine
        (gated 302, or haproxy refusing the request)."""
        status, _ = _raw_get(self.port, '/wp-admin/setup-config.php%00')
        self.assertNotEqual(status, PASS)


if __name__ == '__main__':
    unittest.main(verbosity=2)
