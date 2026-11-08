#!/usr/bin/env python3
"""Regression tests for the default splash (unrouted hosts answered pre-WAF).

Why this file exists
--------------------
Visiting a WHP server's own hostname (https://whpNN.<domain>/ on 80/443, not
the panel port), its bare IP, or any name with no site behind it used to fall
through to `default_backend default-backend` -- but only AFTER every
http-request rule had run, Coraza's send-spoe-group included. `use_backend`
does not short-circuit http-request processing. So the catch-all was WAF
inspected with the server-wide rule set, and a browser on the server hostname
also carries the control panel's cookies (cookies are not port-scoped), which
produced the WAF block page for a host that has nothing behind it to protect.

The splash answers those requests with `http-request return` BEFORE the SPOE
call. Its safety property is that it must NEVER answer a host that routes to
a site. That is held by:
  - routed_hosts.list / routed_wildcards.list being written from the same
    rows, in the same generate_config() call, as the routing ACLs
  - the lists being port-stripped + lowercased (a superset of the raw-Host
    routing ACLs)
  - the lists being part of the rollback set
and it must keep ACME http-01, the blocked-IP page and the suspended page.

Running
-------
    python3 scripts/test-default-splash.py
"""

import logging
import os
import re
import sqlite3
import sys
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
try:
    import haproxy_manager as hm  # noqa: E402
finally:
    logging.FileHandler = _real_file_handler
logging.getLogger('haproxy_manager').setLevel(logging.CRITICAL)

SPLASH_FILE = os.path.join(MODULE_DIR, 'errors', 'default-splash.html')


def render_listener(**kw):
    args = dict(crt_path='/etc/haproxy/certs', suspension_enabled=False,
                coraza_spoe_backend='127.0.0.1:9000', default_splash=True)
    args.update(kw)
    return hm.template_env.get_template('hap_listener.tpl').render(**args)


def return_rules(cfg):
    return [l.strip() for l in cfg.splitlines()
            if l.strip().startswith('http-request return')
            and 'default-splash.html' in l]


class Template(unittest.TestCase):

    def test_off_renders_nothing(self):
        cfg = render_listener(default_splash=False)
        self.assertNotIn('default-splash', cfg)
        self.assertNotIn('splash_routed_host', cfg)

    def test_two_return_rules_root_200_other_404(self):
        rules = return_rules(render_listener())
        self.assertEqual(len(rules), 2, rules)
        self.assertTrue(rules[0].startswith('http-request return status 200 '))
        self.assertTrue(rules[0].endswith(' splash_root'))
        self.assertTrue(rules[1].startswith('http-request return status 404 '))
        self.assertTrue(rules[1].endswith(' !splash_root'))

    def test_static_file_not_lf_file(self):
        """`file` (verbatim), never `lf-file`: nothing from the request may be
        expanded into the page (Host echo, unique-id, ...)."""
        for rule in return_rules(render_listener()):
            self.assertIn(' file /haproxy/errors/default-splash.html ', rule)
            self.assertNotIn('lf-file', rule)

    def test_conditions_keep_acme_blocked_and_suspended_out(self):
        for susp in (False, True):
            for rule in return_rules(render_listener(suspension_enabled=susp)):
                cond = rule.split(' if ', 1)[1].split()
                self.assertIn('!splash_routed_host', cond)
                self.assertIn('!splash_acme', cond)
                self.assertIn('!is_blocked_ip', cond)
                if susp:
                    self.assertIn('!is_suspended_domain', cond)
                else:
                    self.assertNotIn('!is_suspended_domain', cond)

    def test_acme_acl_is_the_challenge_prefix(self):
        self.assertRegex(render_listener(),
                         r'acl splash_acme path_beg /\.well-known/acme-challenge/\n')

    def test_routed_acls_strip_port_and_lowercase(self):
        cfg = render_listener()
        self.assertIn('acl splash_routed_host req.hdr(host),field(1,:),lower '
                      '-f /etc/haproxy/routed_hosts.list', cfg)
        self.assertIn('acl splash_routed_host req.hdr(host),field(1,:),lower '
                      '-m end -f /etc/haproxy/routed_wildcards.list', cfg)

    def test_splash_runs_before_waf_and_after_ip_block_and_suspension(self):
        for susp in (False, True):
            cfg = render_listener(suspension_enabled=susp)
            first_return = cfg.index('file /haproxy/errors/default-splash.html')
            self.assertLess(first_return, cfg.index('http-request send-spoe-group coraza'))
            self.assertLess(first_return, cfg.index('filter spoe engine coraza'))
            self.assertGreater(first_return, cfg.index('acl is_blocked_ip'))
            self.assertGreater(first_return, cfg.index('http-request track-sc0'))
            if susp:
                self.assertGreater(first_return, cfg.index('acl is_suspended_domain'))


class Page(unittest.TestCase):

    def setUp(self):
        with open(SPLASH_FILE, 'rb') as fh:
            self.raw = fh.read()
        self.text = self.raw.decode('utf-8')

    def test_small_enough_for_one_buffer(self):
        # http-request return payload must fit tune.bufsize (16384) with headers.
        self.assertLess(len(self.raw), 8192)

    def test_no_links_scripts_or_external_resources(self):
        low = self.text.lower()
        for needle in ('href', 'src=', '<script', '<form', '<a ', 'http://', 'https://',
                       '8443', '@import', 'url('):
            self.assertNotIn(needle, low, needle)

    def test_no_version_or_template_expansions(self):
        self.assertNotRegex(self.text, r'20\d\d\.\d+\.\d+')
        self.assertNotIn('{{', self.text)
        self.assertNotIn('%[', self.text)


class RoutedLists(unittest.TestCase):

    def test_render_sorted_dedup_lower(self):
        body = hm.render_routed_list(['B.example.com', 'a.example.com', 'b.example.com ', ''])
        lines = [l for l in body.splitlines() if not l.startswith('#')]
        self.assertEqual(lines, ['a.example.com', 'b.example.com'])

    def test_name_with_whitespace_is_dropped_not_split(self):
        body = hm.render_routed_list(['ok.example.com', 'bad\nevil.example.com', 'a b'])
        lines = [l for l in body.splitlines() if not l.startswith('#')]
        self.assertEqual(lines, ['ok.example.com'])

    def test_lists_are_in_the_rollback_set(self):
        pairs = dict(hm._config_backup_pairs())
        self.assertIn(hm.ROUTED_HOSTS_PATH, pairs)
        self.assertIn(hm.ROUTED_WILDCARDS_PATH, pairs)


class GenerateConfigWritesLists(unittest.TestCase):
    """Run the real generate_config() with paths redirected and reload stubbed."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='splash-test-')
        self.saved = {k: getattr(hm, k) for k in (
            'DB_FILE', 'HAPROXY_CONFIG_PATH', 'HAPROXY_BACKUP_PATH',
            'CLUSTER_SECRET_PATH', 'HAPROXY_SOCKET_PATH', 'SSL_CERTS_DIR',
            'BLOCKED_IPS_MAP_PATH', 'BLOCKED_IPS_MAP_BACKUP_PATH',
            'CORAZA_SPOE_CONFIG_PATH', 'CORAZA_SPOE_BACKUP_PATH',
            'ROUTED_HOSTS_PATH', 'ROUTED_HOSTS_BACKUP_PATH',
            'ROUTED_WILDCARDS_PATH', 'ROUTED_WILDCARDS_BACKUP_PATH',
            'reload_haproxy_safely', 'create_backup')}
        j = lambda n: os.path.join(self.tmp, n)  # noqa: E731
        hm.DB_FILE = j('db.sqlite')
        hm.HAPROXY_CONFIG_PATH = j('haproxy.cfg')
        hm.HAPROXY_BACKUP_PATH = j('haproxy.cfg.backup')
        hm.CLUSTER_SECRET_PATH = j('cluster-secret')
        hm.HAPROXY_SOCKET_PATH = j('haproxy.sock')
        hm.SSL_CERTS_DIR = j('certs')
        hm.BLOCKED_IPS_MAP_PATH = j('blocked_ips.map')
        hm.BLOCKED_IPS_MAP_BACKUP_PATH = j('blocked_ips.map.backup')
        hm.CORAZA_SPOE_CONFIG_PATH = j('coraza-spoe.cfg')
        hm.CORAZA_SPOE_BACKUP_PATH = j('coraza-spoe.cfg.backup')
        hm.ROUTED_HOSTS_PATH = j('routed_hosts.list')
        hm.ROUTED_HOSTS_BACKUP_PATH = j('routed_hosts.list.backup')
        hm.ROUTED_WILDCARDS_PATH = j('routed_wildcards.list')
        hm.ROUTED_WILDCARDS_BACKUP_PATH = j('routed_wildcards.list.backup')
        hm.reload_haproxy_safely = lambda *a, **kw: (True, 'stubbed')
        hm.create_backup = lambda *a, **kw: (True, 'unavailable')
        self.env = {k: os.environ.pop(k, None) for k in (
            'HAPROXY_DEFAULT_SPLASH', 'HAPROXY_SUSPENSION_ENABLED',
            'HAPROXY_CORAZA_SPOE_BACKEND')}
        hm.init_db()
        with sqlite3.connect(hm.DB_FILE) as conn:
            cur = conn.cursor()

            def add(domain, backend, wildcard=0):
                cur.execute('INSERT INTO domains (domain, ssl_enabled, ssl_cert_path, '
                            'template_override, is_wildcard) VALUES (?, 1, NULL, NULL, ?)',
                            (domain, wildcard))
                did = cur.lastrowid
                if backend:
                    cur.execute('INSERT INTO backends (name, domain_id, settings) VALUES (?, ?, NULL)',
                                (backend, did))
                    cur.execute('INSERT INTO backend_servers (backend_id, server_name, '
                                'server_address, server_port, server_options) VALUES (?, ?, ?, ?, ?)',
                                (cur.lastrowid, 'web1', '10.0.0.10', 80, 'check'))
            add('Site.Example.com', 'site')
            add('*.wild.example.com', 'wild', wildcard=1)
            add('whp01.example.net', None)   # server hostname: cert-only
            conn.commit()

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(hm, k, v)
        for k, v in self.env.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _lines(self, path):
        with open(path) as fh:
            return [l for l in fh.read().splitlines() if l and not l.startswith('#')]

    def test_lists_written_from_routed_rows_only(self):
        hm.generate_config()
        self.assertEqual(self._lines(hm.ROUTED_HOSTS_PATH), ['site.example.com'])
        self.assertEqual(self._lines(hm.ROUTED_WILDCARDS_PATH), ['.wild.example.com'])
        with open(hm.HAPROXY_CONFIG_PATH) as fh:
            cfg = fh.read()
        # every exact routing ACL name is in the list (superset property)
        for name in re.findall(r'acl \S+-acl hdr\(host\) -i (\S+)', cfg):
            self.assertIn(name.lower(), self._lines(hm.ROUTED_HOSTS_PATH))
        for base in re.findall(r'acl \S+-acl hdr_end\(host\) -i (\S+)', cfg):
            self.assertIn(base.lower(), self._lines(hm.ROUTED_WILDCARDS_PATH))
        self.assertIn('default-splash.html', cfg)

    def test_lists_written_even_with_splash_off(self):
        os.environ['HAPROXY_DEFAULT_SPLASH'] = 'off'
        hm.generate_config()
        self.assertTrue(os.path.exists(hm.ROUTED_HOSTS_PATH))
        self.assertTrue(os.path.exists(hm.ROUTED_WILDCARDS_PATH))
        with open(hm.HAPROXY_CONFIG_PATH) as fh:
            self.assertNotIn('default-splash.html', fh.read())


if __name__ == '__main__':
    unittest.main(verbosity=2)
