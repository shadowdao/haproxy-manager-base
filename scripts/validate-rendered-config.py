#!/usr/bin/env python3
"""Build gate: render the real HAProxy config and hand it to the real `haproxy -c`.

Why this file exists
--------------------
On 2026-08-14 a change to hap_listener.tpl rendered perfectly, passed every
unit test in scripts/ (13 green), and was then rejected outright by HAProxy:

    [ALERT] config : parsing [/etc/haproxy/haproxy.cfg:...] :
            invalid arg 2 in converter 'regsub' : ... unexpected empty
            replacement string

Nothing between "commit" and "running in production" would have caught it.
The unit tests assert on the *text* of the rendered config with regexes, which
tells you what the template says, never whether HAProxy will accept it. And
scripts/test-config-rollback.py stubs the `haproxy` binary with a shell script
that only rejects a literal sentinel token, so its "validation" has never
parsed a single line of real HAProxy syntax.

The failure mode this guards is not cosmetic. When haproxy.cfg is invalid,
scripts/init.py refuses to start HAProxy but the container still comes up:
ports 80/443 are unbound, every site on the host is down, and /health keeps
answering 200 because the Flask API is fine.

So: render the config through the SAME code path production uses
(haproxy_manager.generate_config(), templates and all), then run the actual
`haproxy -c` against the result and gate on its exit code.

This runs as a RUN step in the Dockerfile, which means it also validates
against the exact haproxy binary that ships in the image being built - note
that the Dockerfile installs haproxy UNPINNED, so that binary can move under
us between builds. Any syntax the new binary rejects now fails the build
instead of failing at 3am on an edge node.

What it covers
--------------
  * every template generate_config() touches, assembled in the real order
  * a domain with SSL + a backend, a wildcard domain, a cert-only domain with
    no backend, and two template_override backends
  * blocked-IP map entries (single IP and CIDR)
  * BOTH sides of the two conditional blocks in hap_listener.tpl -
    {%- if suspension_enabled %} and {%- if coraza_spoe_backend %} - because a
    syntax error inside a conditional ships undetected otherwise. Scenario
    "full" turns both on; scenario "default" leaves both off, which is the
    byte-identical-to-standalone shape.

Warnings vs failures
--------------------
`haproxy -c` emits warnings on a clean config here (at minimum "Can't load
stats file" because /var/lib/haproxy/stats.dat doesn't exist at build time,
plus assorted path_reg/ACL advisories). Those are NOT failures. This gate keys
on the process EXIT CODE only, and dumps the full output when it is non-zero.

Running
-------
    python3 scripts/validate-rendered-config.py

Needs the real `haproxy` binary, the application's Python dependencies, and
write access to /etc/haproxy (several templates reference files there by
absolute path - see _REAL_PATH_NOTE below). Inside the image build all three
hold. On a workstation, run it in the container instead.
"""

import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

MODULE_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
)
os.chdir(MODULE_DIR)
sys.path.insert(0, MODULE_DIR)

# Same trick the other suites use: haproxy_manager configures logging at import
# time against /var/log/haproxy-manager.log. Redirect the handlers so this runs
# without root and without polluting the image's log files.
_LOG_DIR = tempfile.mkdtemp(prefix='haproxy-validate-logs-')
_real_file_handler = logging.FileHandler
logging.FileHandler = (
    lambda filename, *a, **kw: _real_file_handler(
        os.path.join(_LOG_DIR, os.path.basename(filename)), *a, **kw)
)
try:
    import haproxy_manager as hm  # noqa: E402
finally:
    logging.FileHandler = _real_file_handler

# The application logs a lot at INFO during a render, and legitimately logs at
# ERROR about things that are only true in this harness ("no existing HAProxy
# config on disk ... ROLLBACK IS NOT AVAILABLE" - correct, there is no live
# config during a build). Silence it so the build log carries the gate's own
# verdict and haproxy's output, which is what matters.
logging.getLogger('haproxy_manager').setLevel(logging.CRITICAL)


# _REAL_PATH_NOTE
# ---------------
# Most paths haproxy_manager writes to are module-level constants and are
# redirected into a temp dir below. Two cannot be:
#
#   /etc/haproxy/blocked_ips.map   - hardcoded inside hap_listener.tpl's
#                                    map_ip() converter
#   /etc/haproxy/coraza-spoe.cfg   - hardcoded in the `filter spoe engine`
#                                    line, and parsed by haproxy -c
#
# Redirecting the constants without editing the templates would just make
# haproxy read a different (missing) file, so those two are left at their real
# paths. Everything this script creates under /etc/haproxy is removed again on
# exit; pre-existing files (the baked trusted_ips.*) are never touched.
ETC_HAPROXY = '/etc/haproxy'

# Files referenced with `-f` / map_ip() from the templates. A missing `-f` file
# is a FATAL haproxy error, so a gate that didn't create these would fail for
# reasons that have nothing to do with the config being tested.
STUB_FILES = {
    os.path.join(ETC_HAPROXY, 'trusted_ips.list'): '# validation stub\n203.0.113.10\n',
    os.path.join(ETC_HAPROXY, 'trusted_ips.map'): '# validation stub\n203.0.113.11 1\n',
    os.path.join(ETC_HAPROXY, 'cloudflare_ips.list'): '# validation stub\n198.51.100.0/24\n',
    os.path.join(ETC_HAPROXY, 'trusted_proxies.list'): '# validation stub\n192.0.2.0/24\n',
    os.path.join(ETC_HAPROXY, 'wpadmin_gate_exempt.list'): '# validation stub\nexempt.example.test\n',
    os.path.join(ETC_HAPROXY, 'suspended_domains.list'): 'suspended.example.test\n',
    # `lf-file` on the Coraza deny rule; loaded at parse time. Present in the
    # image (COPY errors /haproxy/errors), stubbed for anything else.
    '/haproxy/errors/403-waf.html': '<html><body>blocked %[unique-id]</body></html>\n',
}

# (suspension_enabled, coraza_spoe_backend) combinations to render + validate.
SCENARIOS = (
    ('default', {}),
    ('full', {
        'HAPROXY_SUSPENSION_ENABLED': 'true',
        'HAPROXY_CORAZA_SPOE_BACKEND': '127.0.0.1:9000',
    }),
)


def log(msg):
    sys.stdout.write(f'[validate-config] {msg}\n')
    sys.stdout.flush()


def fail(msg):
    sys.stderr.write(f'[validate-config] FAIL: {msg}\n')
    sys.stderr.flush()
    raise SystemExit(1)


class CreatedFiles:
    """Tracks what we put on disk outside the temp dir so it can be removed.

    Two sources: files we create explicitly, and files generate_config() itself
    writes into /etc/haproxy (blocked_ips.map, coraza-spoe.cfg and their
    .backup copies). The latter are caught by diffing the directory listing,
    which also picks up anything a future change starts writing there.
    """

    def __init__(self):
        self.explicit = []
        self.etc_before = self._listdir(ETC_HAPROXY)

    @staticmethod
    def _listdir(path):
        try:
            return set(os.listdir(path))
        except OSError:
            return set()

    def ensure(self, path, content):
        """Create path with content if it does not already exist."""
        if os.path.exists(path):
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fh:
            fh.write(content)
        os.chmod(path, 0o644)
        self.explicit.append(path)

    def cleanup(self):
        for path in self.explicit:
            try:
                os.unlink(path)
            except OSError:
                pass
        for name in self._listdir(ETC_HAPROXY) - self.etc_before:
            try:
                os.unlink(os.path.join(ETC_HAPROXY, name))
            except OSError:
                pass


def require_haproxy_binary():
    """Fail closed. A gate that skips itself when the binary is missing is a
    gate that would have let the 2026-08-14 change through."""
    path = shutil.which('haproxy')
    if not path:
        fail('no `haproxy` binary on PATH - this gate cannot validate anything. '
             'Run it inside the image (the Dockerfile installs haproxy).')
    version = subprocess.run([path, '-v'], capture_output=True, text=True)
    log(f'using {path}: {version.stdout.strip().splitlines()[0] if version.stdout else "unknown version"}')


def make_self_signed_cert(certs_dir):
    """HAProxy loads every file in the `bind ... ssl crt <dir>` directory at
    parse time, so the directory has to hold a real, loadable bundle."""
    os.makedirs(certs_dir, exist_ok=True)
    cert = os.path.join(certs_dir, 'cert.tmp')
    key = os.path.join(certs_dir, 'key.tmp')
    subprocess.run(
        ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
         '-keyout', key, '-out', cert, '-days', '1',
         '-subj', '/CN=validate.example.test'],
        check=True, capture_output=True,
    )
    bundle = os.path.join(certs_dir, 'validate.example.test.pem')
    with open(bundle, 'w') as out:
        for part in (cert, key):
            with open(part) as fh:
                out.write(fh.read())
    os.unlink(cert)
    os.unlink(key)
    os.chmod(bundle, 0o600)


def seed_database(db_path):
    """A representative fleet: SSL + backend, wildcard, cert-only, overrides."""
    hm.DB_FILE = db_path
    hm.init_db()
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()

        def add_site(domain, backend, ssl_enabled=1, wildcard=0, override=None,
                     servers=(('web1', '10.0.0.10', 8080, 'check'),)):
            cur.execute(
                'INSERT INTO domains (domain, ssl_enabled, ssl_cert_path, '
                'template_override, is_wildcard) VALUES (?, ?, ?, ?, ?)',
                (domain, ssl_enabled, f'/etc/haproxy/certs/{domain}.pem',
                 override, wildcard),
            )
            domain_id = cur.lastrowid
            cur.execute('INSERT INTO backends (name, domain_id, settings) '
                        'VALUES (?, ?, ?)', (backend, domain_id, None))
            backend_id = cur.lastrowid
            for name, addr, port, opts in servers:
                cur.execute(
                    'INSERT INTO backend_servers (backend_id, server_name, '
                    'server_address, server_port, server_options) '
                    'VALUES (?, ?, ?, ?, ?)',
                    (backend_id, name, addr, port, opts),
                )

        add_site('site-one.example.test', 'site-one',
                 servers=(('web1', '10.0.0.10', 8080, 'check'),
                          ('web2', '10.0.0.11', 8080, 'check backup')))
        add_site('site-two.example.test', 'site-two', ssl_enabled=0)
        add_site('*.wildcard.example.test', 'wildcard-site', wildcard=1)
        add_site('ws.example.test', 'ws-site', override='hap_backend_websocket')
        add_site('sse.example.test', 'sse-site', override='hap_backend_longlived')

        # Cert/management-only domain: registered for certificates, no backend.
        # generate_config() has an explicit branch for this.
        cur.execute(
            'INSERT INTO domains (domain, ssl_enabled, ssl_cert_path, '
            'template_override, is_wildcard) VALUES (?, ?, ?, ?, ?)',
            ('panel.example.test', 1, '/etc/haproxy/certs/panel.pem', None, 0),
        )

        # Both map_ip() shapes: a single address and a CIDR.
        for ip in ('203.0.113.66', '198.51.100.0/24'):
            cur.execute('INSERT INTO blocked_ips (ip_address, reason, blocked_by) '
                        'VALUES (?, ?, ?)', (ip, 'validation fixture', 'gate'))
        conn.commit()


def render(scenario_name, env_overrides, workdir):
    """Render via generate_config() and return the path to the assembled config.

    generate_config() is the real production entry point: it takes the rollback
    snapshot, writes the blocked-IP map, renders every template, and writes
    haproxy.cfg. Only the reload is stubbed - there is no HAProxy process to
    reload during a build, and validating the file is the whole point.
    """
    scenario_dir = os.path.join(workdir, scenario_name)
    certs_dir = os.path.join(scenario_dir, 'certs')
    os.makedirs(scenario_dir)
    make_self_signed_cert(certs_dir)

    hm.HAPROXY_CONFIG_PATH = os.path.join(scenario_dir, 'haproxy.cfg')
    hm.HAPROXY_BACKUP_PATH = os.path.join(scenario_dir, 'haproxy.cfg.backup')
    hm.CLUSTER_SECRET_PATH = os.path.join(scenario_dir, 'cluster-secret')
    hm.HAPROXY_SOCKET_PATH = os.path.join(scenario_dir, 'haproxy.sock')
    hm.SSL_CERTS_DIR = certs_dir
    seed_database(os.path.join(scenario_dir, 'haproxy_config.db'))

    saved_env = {}
    for key in ('HAPROXY_SUSPENSION_ENABLED', 'HAPROXY_CORAZA_SPOE_BACKEND'):
        saved_env[key] = os.environ.pop(key, None)
    os.environ.update(env_overrides)

    real_reload = hm.reload_haproxy_safely
    hm.reload_haproxy_safely = lambda *a, **kw: (True, 'reload skipped: build-time validation')
    try:
        hm.generate_config()
    finally:
        hm.reload_haproxy_safely = real_reload
        for key, value in saved_env.items():
            os.environ.pop(key, None)
            if value is not None:
                os.environ[key] = value

    return hm.HAPROXY_CONFIG_PATH


def assert_scenario_branches(scenario_name, config_path, env_overrides):
    """Cheap sanity check that the conditional blocks actually rendered.

    Without this, a template refactor that silently stopped emitting the
    suspension or Coraza block would leave the gate passing while covering
    less than it claims to.
    """
    with open(config_path) as fh:
        text = fh.read()
    expected = {
        'suspension': ('acl is_suspended_domain',
                       'HAPROXY_SUSPENSION_ENABLED' in env_overrides),
        'coraza': ('filter spoe engine coraza',
                   'HAPROXY_CORAZA_SPOE_BACKEND' in env_overrides),
    }
    for label, (needle, should_be_present) in expected.items():
        present = needle in text
        if present != should_be_present:
            fail(f'[{scenario_name}] {label} block {"missing" if should_be_present else "unexpectedly present"} '
                 f'in the rendered config (looked for {needle!r}). The gate is '
                 f'not covering what it thinks it is.')


def _dump_context(config_path, output):
    """Print the rendered lines HAProxy complained about.

    The temp dir is deleted on the way out, so the build log has to carry the
    evidence. HAProxy reports `parsing [<file>:<line>]`; show a window around
    each reported line rather than dumping ~1500 lines of config.
    """
    line_numbers = sorted({
        int(n) for n in re.findall(
            r'parsing \[' + re.escape(config_path) + r':(\d+)\]', output)
    })
    if not line_numbers:
        return
    with open(config_path) as fh:
        lines = fh.read().splitlines()
    sys.stderr.write('[validate-config] --- rendered config around the error ---\n')
    for number in line_numbers:
        start = max(1, number - 6)
        end = min(len(lines), number + 4)
        for index in range(start, end + 1):
            marker = '>>' if index == number else '  '
            sys.stderr.write(f'{marker}{index:6d}| {lines[index - 1]}\n')
        sys.stderr.write('[validate-config] ---\n')


def validate(scenario_name, config_path):
    result = subprocess.run(['haproxy', '-c', '-f', config_path],
                            capture_output=True, text=True)
    if result.returncode != 0:
        output = result.stdout + result.stderr
        sys.stderr.write(
            f'\n[validate-config] ===== {scenario_name}: haproxy REJECTED the '
            f'rendered configuration (exit {result.returncode}) =====\n')
        sys.stderr.write(output if output.endswith('\n') else output + '\n')
        _dump_context(config_path, output)
        sys.stderr.write(
            '[validate-config] This is a real HAProxy parse failure. Shipping it '
            'would leave the container Up with ports 80/443 unbound and every '
            'site on the host down, while /health still returns 200.\n')
        sys.stderr.flush()
        raise SystemExit(1)

    # Exit code 0 is the verdict. Warnings are expected and are NOT failures:
    # "Can't load stats file" always fires at build time, and HAProxy emits
    # path_reg/ACL advisories on a perfectly valid config.
    noise = (result.stdout + result.stderr).strip()
    log(f'{scenario_name}: haproxy -c OK (exit 0)')
    if noise:
        for line in noise.splitlines():
            log(f'  {scenario_name}: haproxy said: {line}')


def main():
    require_haproxy_binary()

    if not os.path.isdir(ETC_HAPROXY) or not os.access(ETC_HAPROXY, os.W_OK):
        fail(f'{ETC_HAPROXY} must exist and be writable - several templates '
             'reference files there by absolute path. Run this inside the image.')

    created = CreatedFiles()
    workdir = tempfile.mkdtemp(prefix='haproxy-validate-')
    try:
        for path, content in STUB_FILES.items():
            created.ensure(path, content)

        for scenario_name, env_overrides in SCENARIOS:
            log(f'rendering scenario "{scenario_name}" '
                f'({env_overrides or "no optional features"})')
            config_path = render(scenario_name, env_overrides, workdir)
            assert_scenario_branches(scenario_name, config_path, env_overrides)
            validate(scenario_name, config_path)
    finally:
        created.cleanup()
        shutil.rmtree(workdir, ignore_errors=True)
        shutil.rmtree(_LOG_DIR, ignore_errors=True)

    log('all scenarios accepted by the real haproxy binary')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
