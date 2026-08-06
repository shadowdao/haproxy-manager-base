#!/usr/bin/env python3
"""Regression tests for the certificate publication shell scripts.

Why this file exists
--------------------
renew-certificates.sh and sync-certificates.sh published a bundle with

    cat "$CERT_FILE" "$KEY_FILE" > "$COMBINED_FILE"

where $COMBINED_FILE is the pem HAProxy is serving *right now*. The shell
truncates the destination when it opens the redirect, before cat runs, so any
failure after that point - unreadable source key, ENOSPC, container killed
mid-write - left a zero-length or key-less pem behind. The exit status of cat
was checked, but by then the live file was already destroyed.

HAProxy loads $SSL_CERTS_DIR as a DIRECTORY (`bind :443 ssl crt /etc/haproxy/
certs`) and tries to load every file in it, so a single unloadable file fails
the whole bind: HTTPS down for every customer on the host.

The fix (scripts/cert-publish-lib.sh) assembles into a sibling staging dir,
validates, backs up the outgoing bundle into a sibling backup dir, and renames
into place. These tests pin the observable guarantees:

  * a successful publish replaces the live pem and archives the old one;
  * a FAILED publish leaves the previous, still-valid pem byte-for-byte intact;
  * nothing that is not a final *.pem ever appears in the certs directory;
  * HAProxy is not reloaded when `haproxy -c` rejects the configuration.

Running
-------
    python3 scripts/test-cert-scripts.py            # tests the repo checkout
    HAPROXY_MANAGER_DIR=/some/other/tree \
        python3 scripts/test-cert-scripts.py        # tests another tree

Self-contained stdlib unittest - no pytest, no venv, no bats, and nothing is
imported from the application. The scripts are driven as subprocesses with
every path they touch redirected by environment variable (SSL_CERTS_DIR,
LETSENCRYPT_LIVE_DIR, CERT_STAGING_DIR, CERT_BACKUP_DIR, LOG_FILE,
ERROR_LOG_FILE, HAPROXY_CONFIG) and stub `certbot`, `socat` and `haproxy`
binaries on PATH.

The certificate material below is a real self-signed test certificate with its
matching key (plus a second, unrelated key for the mismatch case), embedded as
constants so the tests need no openssl to *create* material. The one test that
needs openssl to *verify* pairing skips itself if the binary is absent.
"""

import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

MODULE_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
)
SCRIPTS_DIR = os.path.join(MODULE_DIR, 'scripts')
LIB = os.path.join(SCRIPTS_DIR, 'cert-publish-lib.sh')

BROKEN_TOKEN = '__BROKEN__'
DOMAIN = 'test.example.com'

# --- test key material -------------------------------------------------------
# openssl req -x509 -newkey rsa:2048 -keyout key1 -out cert1 -days 3650 -nodes \
#         -subj /CN=test.example.com
TEST_CERT = """\
-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUeaz/lNOESOTHsB3Y97+Xja7Fy4gwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAeFw0yNjA4MDYxNTQyMTda
Fw0zNjA4MDMxNTQyMTdaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDF5GL7Gjn+UnPFy5sqP2k4XHth
mkWFZj+mjK6cDhbBXYt60NrwVdrrgOFydMC75VeUceFxG/5GD7wrXZP23xzbnWKm
7FxfOSmr4y+1rVEZwi8IeWEz3W6C6y5rjZsCI+pBgdna+aJSpTQZHPfDpNtQm5vl
enj5BfizYixinORxm9kvXMGXV+Cw1CJkqB3mzScwWt40EtQoVxekebf8B7i4ZHyx
xT6/xwF+WY8OliZkY1pdqncoTLUAYcaE/HR/ojJKmSVIq1GswZE/y3E56LIwq+wJ
eGbgH46a+86z+VO2UX1jbad1kWKBCsRoOpaybZDEWAYTOqahW7kOH7umTUsRAgMB
AAGjUzBRMB0GA1UdDgQWBBTIqa3BNEjjcxkhXqnRwInrLM9yijAfBgNVHSMEGDAW
gBTIqa3BNEjjcxkhXqnRwInrLM9yijAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQB/lYzXb5PI3magMz/IXmwTsMCrVSdaUYEIKLEJggmbGxqpwO1a
iYagWZ/5H3B9KDvNQA+L4FkMJ726ZkdGEH/vkwvTAuhwU2NSWcbRJ8DK5u3Q4rnJ
VswPcW5njUF9mQq0NPX/PMCeOoFDEI8+RrgQZxtHhopwuKOgVA6HRBINKdEZJlrp
oLLQrHDNVLMYTclNHG6kBg0lOHUV31TgkJQ8kMgtq0WQX7RseKR10QKgN5iOBomU
3+y713Ibpac5B1zw5l3LjE/59xFteFbDENr2+A5VGhVNVZC+bs+YTYTzeAsGB0e3
MQ+XJMJq3kaJmQ+QcTrRaKMtoMz2h1AIRbLd
-----END CERTIFICATE-----
"""

# The private key that matches TEST_CERT.
TEST_KEY = """\
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDF5GL7Gjn+UnPF
y5sqP2k4XHthmkWFZj+mjK6cDhbBXYt60NrwVdrrgOFydMC75VeUceFxG/5GD7wr
XZP23xzbnWKm7FxfOSmr4y+1rVEZwi8IeWEz3W6C6y5rjZsCI+pBgdna+aJSpTQZ
HPfDpNtQm5vlenj5BfizYixinORxm9kvXMGXV+Cw1CJkqB3mzScwWt40EtQoVxek
ebf8B7i4ZHyxxT6/xwF+WY8OliZkY1pdqncoTLUAYcaE/HR/ojJKmSVIq1GswZE/
y3E56LIwq+wJeGbgH46a+86z+VO2UX1jbad1kWKBCsRoOpaybZDEWAYTOqahW7kO
H7umTUsRAgMBAAECggEAA9SnFFqGfR1yO4XUlfmmgyZqJoJmnl2TdZlDT4bHyrwx
dSIKHO0iiNzEsHMhYHnA62EVdruunUNUdofwE28v9zHZnSbV5mt8OqUyERue5mdf
gvPbjXYXu63LBx61fZH9qME3WwFqUpx7UNGiW62LJ8ktWEC5ywNCNFG+D3YfR3Iu
v3PdIFXwkpJMaXO+42JSoSVoiqxlONqNiqcdQj64iYgCYdNxcgdLy+mHGrf1hAZs
dom2Jp0oEM4ZdOQu3Z6uyEyPsECiz1PdQjzagaEfPWtKCQk0kY8DDCn5X2xQif9w
3xeaISqho7bQgSo4IEgWHTP6V0v7brTP7VcK+gyMyQKBgQD15FrE4XAL89NBQ6iX
m2l6quZv5tIUtreuYxsOpFIMU22zfsRZOvA7sJR3ufOJ+b7tFHuJ8DAJUpK08Vvg
A930/LW9wUsY42d54XKIO/8DTsIrmjppoGdshs3axJQkqfN0zQkhqfbwaXRJ9X2k
Fvax+5jftaIaw0hQdWLnfTmGmQKBgQDOBue89D8THYl/LvDGg6WoVyK3ljBMK2s3
4BljeZCJdWAjtido13Mltubc6YVHScmVoIZKTmx+fCjdQ3y1t92vZZSBeLsXhfFr
N+IOGZu3ZmJu64x3OukSYQ7x6agi5yP3+7k0siZgxOMXJRQDYZUcHxIHDrSGLeLZ
sj7LnbvLOQKBgE8murE1gEPYsOAJT3O96y45ZQQQYP+Z8XaJIGSOMHsXP/DPlZTD
jCEqrh/8E5EOe48FUN8OGehmVCM6rkBl/kSmNDpoxiu0x9JL5/pClcwSxh4S/0qQ
/7nHiuwo6ycCLgQjHBViCMNKrsw/4bm4SqDwRD1+0jebNOPxZWzuul3BAoGAZij0
ZjSyxhbCZEdxau5CiYvTkjct8cch3k4IKNRRwGdsaajcN9eFqHDeXzKIPQYwqDo1
/MiQcdO9K6JYR39JtLxo/B5Sn2JyiJjoRdea6EEjlB7GwyR6B/wKvhf/oHb+1euD
NccU0q0ucf6XwulzV8NsXAWFrHc6YnpJOwwW37kCgYAkEyjUc73jImiTyf/IXVOD
UHlRXZPvwtZUuPGe4RI0Gds97tKnvXnvFsPIRCOGfVzZ8z79DGiQ8TR2a0hgZec1
Mo3J2dCjlv4Q6ACjHkCA1cmi13OHUPnpaeesrOk+SpEVJfR2k4qRWH4z3oxbPO/q
TDFnjWHSgjkDMrxVHZ8wPg==
-----END PRIVATE KEY-----
"""

# A perfectly valid RSA key that has nothing to do with TEST_CERT.
UNRELATED_KEY = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDE7mosrsdBhdn1
ZIErYmMuPU69ws51JdyqwtRZlV2uLLby0dOfJpFKZPuBPEqTqDimd9N4FSL0CGjG
zXG23RYd9AbdSoorFORrUxeiPzFnbz4v38srGHckOS9ozKAbPLACUEjWMX1NwAZ+
wGlSz3cWYTWVztFCUIxpvLVR87PSpTnpdCXIj0EABOc6WoLBLE+v2knZOa63LKg6
GryInD43CnWFBKpH0gdgWqh+ie3NFMumLR8M3lZq2Mk0EFgVWrxPnJobYvOmavNp
NBR3ZugR4X57c1YFyLkYXQIdhxuYV1ZAY6NgmAIsaiCKFqdksF5AJSV7FZNBM43r
33ae/R5hAgMBAAECggEAIgNYsL9+OEWtU8ooWi0r2q5plXJaVNb1gkPUx+U5sS3V
amKNxbj0UrBW1Scr7U1afXwIOP8TkqkKKb4NpCsS2RkO/3USoKbC3fuTwyjdeFM5
Hy0sytR2rXm4A8aF57ZnYvrpXZ9eGEnwhT9n4Y7mL2YaSnXWZDkDy3Z1rcIk/p5P
jUo4UQyzD/9Gab1stcBbGv+66B3mlVdRVJor5+tGn6zmr4TjvqupAexuXd+Q6+1L
OG4e2bAUmuOVOa+w8Xo4vwkiXSDLVEsl1z1x4Bcrv61bIg0rbZAeqcZ4EUPyrEyR
RpaaOLAiwdzjOj5pQvHAF2q/++IlY6xPhotTr11tvQKBgQD37C2UQRGRo622+2kx
qgsdA6jPM9vCE9S4aS4qaOj8XSMMCu6bQW5lU48DaONvXxDmT6x9IrgR3QN1Iz/t
17kUCCghuviEP1RjnahBRQqZR38KdDzKhaWt9jgdjCun9MzUXIaQRTFlFGA1z1pz
apZ9a8/ehYPSk4pv9h06/B3IjQKBgQDLWPBuhj203QOmwVF1v1k4yyuJ7UBqtRaY
I9jMW93sB2hPs6Se10UroQHlF95IHeRXvNKH/UXuAILIJMN8oTI4uU7t60shJHvI
o14RzEZoUQjES7BBVhePglndJmYIKoKKAX5lSFe9Lk0ei9B+1Dle5Q+9ZeP09cp4
vVcGvOgqJQKBgQCtxe1srO8TlhZ821uwY+/GNnpsQX0XW68OUyr4rvAfc2jNWBxG
1mX6v8bOLQa9WXUO+Wl9jIhYfQGfaUW2AC7Jy63VdqgaigksiaUVmr8DEQoK2c6C
ZYrrlFlg3I78+qlXcEMhfF5S6yVEkkJkA6HX52mcHxl2z9OJBokWfwChQQKBgAzH
xzy7FS/D4FHfvpXu89Wc91yQ28aZIRVo01xsvbLy+DxiJwuQrhlC4lKawG656jsV
dAn2AiomQBICNYMkwnpMM0jCzBMGLv16PxRRSW+PAEUOGMLSfWKYp7s9iZYjzdaM
p3wIIvOR8GjmErGV9xEexnF58OzZceNKyyhyQQk9AoGAbvjJvYLOhQpAbbqErNNv
LK1P+TngKpukRHXjiUpPVEGNhN6krBBJCBWzY7ucrIy6jz8UBy7SbITBy7qIKhxZ
PVP7WVATMWEeW1AfdBfCYDI4jFKAD8SLECby45nRBuBllYdQnW1gBzLcCulCwB+w
FV0RvuQPDYkqsx8ibqpSv7c=
-----END PRIVATE KEY-----
"""

# The bundle already on disk when a run starts. Same key material, plus a
# trailing marker so "the live file was replaced" and "the old file was
# archived" can be told apart byte-for-byte.
PREVIOUS_BUNDLE = TEST_CERT + TEST_KEY + '# previous bundle\n'
NEW_BUNDLE = TEST_CERT + TEST_KEY

# --- stub binaries -----------------------------------------------------------
STUB_CERTBOT = """\
#!/bin/sh
# Test stub for certbot: pretend there was nothing to renew.
echo "No renewals were attempted."
exit 0
"""

STUB_SOCAT = """\
#!/bin/sh
# Test stub for socat: record that a reload was attempted, and what was sent.
{ printf 'socat %s <<' "$*"; cat; printf '>>\\n'; } >> "$SOCAT_LOG"
exit 0
"""

STUB_HAPROXY = """\
#!/bin/sh
# Test stub for the haproxy binary: `haproxy -c -f FILE` rejects any config
# containing %(token)s, which is how the tests inject an invalid config.
cfg=""
while [ $# -gt 0 ]; do
  case "$1" in -f) cfg="$2"; shift ;; esac
  shift
done
if [ -n "$cfg" ] && grep -q '%(token)s' "$cfg" 2>/dev/null; then
  echo "[ALERT] parsing [$cfg:1] : unknown keyword '%(token)s'" >&2
  exit 1
fi
exit 0
""" % {'token': BROKEN_TOKEN}

GOOD_HAPROXY_CFG = textwrap.dedent("""\
    global
        daemon
    defaults
        mode http
    frontend fe
        bind 0.0.0.0:443 ssl crt /etc/haproxy/certs
""")


def write(path, content, mode=None):
    with open(path, 'w') as fh:
        fh.write(content)
    if mode is not None:
        os.chmod(path, mode)
    return path


def read(path):
    with open(path) as fh:
        return fh.read()


class CertScriptFixture(unittest.TestCase):
    """An isolated fake /etc/haproxy + /etc/letsencrypt plus stub binaries."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='haproxy-cert-test-')
        self.addCleanup(self._cleanup_tmp)

        self.bindir = os.path.join(self.tmp, 'bin')
        os.makedirs(self.bindir)
        write(os.path.join(self.bindir, 'certbot'), STUB_CERTBOT, 0o755)
        write(os.path.join(self.bindir, 'socat'), STUB_SOCAT, 0o755)
        write(os.path.join(self.bindir, 'haproxy'), STUB_HAPROXY, 0o755)
        self.socat_log = os.path.join(self.tmp, 'socat-invocations.log')

        # Mirrors the real layout: certs dir, with staging/backups as SIBLINGS.
        self.haproxy_dir = os.path.join(self.tmp, 'etc', 'haproxy')
        self.certs_dir = os.path.join(self.haproxy_dir, 'certs')
        self.staging_dir = os.path.join(self.haproxy_dir, 'cert-staging')
        self.backup_dir = os.path.join(self.haproxy_dir, 'cert-backups')
        os.makedirs(self.certs_dir)

        self.le_live = os.path.join(self.tmp, 'etc', 'letsencrypt', 'live')
        self.domain_dir = os.path.join(self.le_live, DOMAIN)
        os.makedirs(self.domain_dir)
        self.src_cert = write(os.path.join(self.domain_dir, 'fullchain.pem'), TEST_CERT)
        self.src_key = write(os.path.join(self.domain_dir, 'privkey.pem'), TEST_KEY)

        self.live_pem = os.path.join(self.certs_dir, DOMAIN + '.pem')
        self.haproxy_cfg = write(os.path.join(self.haproxy_dir, 'haproxy.cfg'),
                                 GOOD_HAPROXY_CFG)
        self.log_file = os.path.join(self.tmp, 'haproxy-manager.log')
        self.error_log = os.path.join(self.tmp, 'haproxy-manager-errors.log')

    def _cleanup_tmp(self):
        # A test may have chmod 000'd a fixture file.
        for root, dirs, files in os.walk(self.tmp):
            for name in files:
                try:
                    os.chmod(os.path.join(root, name), 0o600)
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ---------------------------------------------------------
    def env(self, **overrides):
        env = dict(os.environ)
        env.update({
            'PATH': self.bindir + os.pathsep + os.environ['PATH'],
            'SSL_CERTS_DIR': self.certs_dir,
            'LETSENCRYPT_LIVE_DIR': self.le_live,
            'CERT_STAGING_DIR': self.staging_dir,
            'CERT_BACKUP_DIR': self.backup_dir,
            'LOG_FILE': self.log_file,
            'ERROR_LOG_FILE': self.error_log,
            'HAPROXY_CONFIG': self.haproxy_cfg,
            'SOCAT_LOG': self.socat_log,
        })
        env.update(overrides)
        return env

    def run_script(self, name, **env_overrides):
        path = os.path.join(SCRIPTS_DIR, name)
        self.assertTrue(os.path.exists(path), f'{path} does not exist')
        return subprocess.run(['bash', path], env=self.env(**env_overrides),
                              capture_output=True, text=True, timeout=120)

    def bundle_is_valid(self, path):
        """Ask the shipped library whether HAProxy could use this bundle."""
        return subprocess.run(
            ['bash', '-c', '. "$1"; cert_bundle_valid "$2"', '_', LIB, path],
            env=self.env(), capture_output=True, text=True).returncode == 0

    def reload_attempted(self):
        return os.path.exists(self.socat_log) and os.path.getsize(self.socat_log) > 0

    def logs(self):
        text = ''
        for path in (self.log_file, self.error_log):
            if os.path.exists(path):
                text += read(path)
        return text

    def seed_previous_bundle(self, content=PREVIOUS_BUNDLE):
        return write(self.live_pem, content)

    def assert_certs_dir_is_clean(self):
        """HAProxy loads this directory wholesale: only final *.pem may be here."""
        entries = sorted(os.listdir(self.certs_dir))
        strays = [e for e in entries if not e.endswith('.pem')]
        self.assertEqual(strays, [],
                         f'non-.pem files left in the certs directory HAProxy '
                         f'loads wholesale: {strays} (dir: {entries})')

    def assert_no_staging_leftovers(self):
        if os.path.isdir(self.staging_dir):
            self.assertEqual(sorted(os.listdir(self.staging_dir)), [],
                             'staging file was not cleaned up')


class CertScriptBehaviour:
    """Behaviour shared by renew-certificates.sh and sync-certificates.sh.

    A mixin rather than a TestCase so the cases are collected once per concrete
    script, not a third time for the base class.
    """

    SCRIPT = None

    def run_it(self, **env_overrides):
        return self.run_script(self.SCRIPT, **env_overrides)

    # -- happy path ------------------------------------------------------
    def test_publish_replaces_live_pem_and_archives_the_previous_one(self):
        self.seed_previous_bundle()
        result = self.run_it()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(read(self.live_pem), NEW_BUNDLE,
                         'live pem is not the newly assembled cert+key')
        backup = os.path.join(self.backup_dir, DOMAIN + '.pem')
        self.assertTrue(os.path.exists(backup),
                        f'previous bundle was not archived to {backup}')
        self.assertEqual(read(backup), PREVIOUS_BUNDLE,
                         'the archived bundle is not the one that was replaced')
        self.assertIn('1 updated, 0 failed', self.logs())
        self.assertTrue(self.reload_attempted(),
                        'HAProxy was never reloaded after a successful update')
        self.assert_certs_dir_is_clean()
        self.assert_no_staging_leftovers()

    def test_first_publish_works_with_no_previous_bundle(self):
        result = self.run_it()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(read(self.live_pem), NEW_BUNDLE)
        self.assert_certs_dir_is_clean()

    # -- THE HEADLINE ----------------------------------------------------
    def test_unreadable_source_key_leaves_the_previous_bundle_intact(self):
        """The bug this whole change exists for.

        Pre-fix: `cat cert key > live.pem` truncated live.pem before cat ran,
        so an unreadable key left a key-less (or empty) pem in the directory
        HAProxy loads wholesale -> the :443 bind fails -> every site on the
        host loses HTTPS. Checking cat's exit status did not undo that.
        """
        self.seed_previous_bundle()
        before = read(self.live_pem)
        self.assertTrue(self.bundle_is_valid(self.live_pem),
                        'fixture precondition: the seeded bundle must be valid')

        how = self.break_source_key()

        result = self.run_it()

        self.assertEqual(read(self.live_pem), before,
                         f'the live pem was damaged by a failed publish ({how}); '
                         f'HAProxy would fail to load the certs directory')
        self.assertTrue(self.bundle_is_valid(self.live_pem),
                        'the pem left on disk is no longer a usable bundle')
        logs = self.logs()
        self.assertIn(f'Failed to combine certificate for {DOMAIN}', logs)
        self.assertIn('0 updated, 1 failed', logs)
        self.assertFalse(self.reload_attempted(),
                         'HAProxy was reloaded even though nothing was updated')
        self.assert_certs_dir_is_clean()
        self.assert_no_staging_leftovers()
        self.assertEqual(result.returncode, 0,
                         'a per-domain failure should not change the exit code')

    def break_source_key(self):
        """Make reading the source key fail, however this environment allows.

        chmod 000 is the faithful reproduction (file present, `-f` true, cat
        fails), but it is a no-op for root, so as root we truncate the key
        instead: pre-fix that is even nastier, because `cat` then *succeeds*
        and silently publishes a key-less pem.
        """
        if os.geteuid() == 0:
            write(self.src_key, '')
            return 'zero-length source key (running as root)'
        os.chmod(self.src_key, 0o000)
        return 'unreadable source key (chmod 000)'

    # -- other ways to end up with an unusable bundle --------------------
    def test_cert_only_bundle_is_rejected(self):
        self.seed_previous_bundle()
        before = read(self.live_pem)
        write(self.src_key, TEST_CERT)  # no private key block at all

        self.run_it()

        self.assertEqual(read(self.live_pem), before,
                         'a key-less bundle was published over the live pem')
        self.assertIn('0 updated, 1 failed', self.logs())
        self.assertFalse(self.reload_attempted())
        self.assert_certs_dir_is_clean()
        self.assert_no_staging_leftovers()

    def test_truncated_certificate_block_is_rejected(self):
        self.seed_previous_bundle()
        before = read(self.live_pem)
        write(self.src_cert, TEST_CERT.split('\n')[0] + '\nMIIDFzCCAf+gAwIBA\n')

        self.run_it()

        self.assertEqual(read(self.live_pem), before,
                         'a truncated certificate was published over the live pem')
        self.assertIn('0 updated, 1 failed', self.logs())
        self.assert_certs_dir_is_clean()

    def test_mismatched_key_is_rejected(self):
        if shutil.which('openssl') is None:
            self.skipTest('openssl CLI not available: the cert/key pairing '
                          'check is best-effort and is skipped by design')
        self.seed_previous_bundle()
        before = read(self.live_pem)
        write(self.src_key, UNRELATED_KEY)

        self.run_it()

        self.assertEqual(read(self.live_pem), before,
                         'a bundle whose key does not match the cert was published')
        self.assertIn('does not match the certificate', self.logs())
        self.assertIn('0 updated, 1 failed', self.logs())
        self.assert_certs_dir_is_clean()

    # -- the certs directory is HAProxy's, not ours ----------------------
    def test_no_stray_files_in_certs_dir_after_success_or_failure(self):
        self.seed_previous_bundle()
        self.run_it()
        self.assert_certs_dir_is_clean()
        self.assertEqual(sorted(os.listdir(self.certs_dir)), [DOMAIN + '.pem'])

        self.break_source_key()
        self.run_it()
        self.assert_certs_dir_is_clean()
        self.assertEqual(sorted(os.listdir(self.certs_dir)), [DOMAIN + '.pem'])
        self.assert_no_staging_leftovers()

    def test_staging_and_backup_dirs_are_outside_the_certs_dir(self):
        """Belt and braces: even with the defaults, nothing lands under certs/."""
        self.seed_previous_bundle()
        # Drop the explicit overrides so the derived defaults are exercised.
        env = {'CERT_STAGING_DIR': '', 'CERT_BACKUP_DIR': ''}
        self.run_it(**env)

        self.assert_certs_dir_is_clean()
        self.assertEqual(sorted(os.listdir(self.certs_dir)), [DOMAIN + '.pem'])
        self.assertTrue(
            os.path.exists(os.path.join(self.haproxy_dir, 'cert-staging')),
            'default staging dir is not the documented sibling of the certs dir')
        self.assertTrue(
            os.path.exists(os.path.join(self.haproxy_dir, 'cert-backups',
                                        DOMAIN + '.pem')),
            'default backup dir is not the documented sibling of the certs dir')

    # -- reload gating ---------------------------------------------------
    def test_reload_is_not_attempted_when_haproxy_config_is_invalid(self):
        write(self.haproxy_cfg, GOOD_HAPROXY_CFG + BROKEN_TOKEN + '\n')

        result = self.run_it()

        self.assertFalse(self.reload_attempted(),
                         'HAProxy was reloaded with a configuration that '
                         '`haproxy -c` rejects')
        self.assertNotEqual(result.returncode, 0,
                            'refusing to reload must be a loud, non-zero exit')
        self.assertIn('does not validate', self.logs())

    def test_reload_happens_when_the_config_validates(self):
        self.run_it()
        self.assertTrue(self.reload_attempted())
        self.assertIn('reload', read(self.socat_log))

    def test_reload_is_not_attempted_when_nothing_was_updated(self):
        shutil.rmtree(self.domain_dir)
        result = self.run_it()
        self.assertEqual(result.returncode, 0)
        self.assertFalse(self.reload_attempted())


class TestRenewCertificates(CertScriptBehaviour, CertScriptFixture):
    SCRIPT = 'renew-certificates.sh'


class TestSyncCertificates(CertScriptBehaviour, CertScriptFixture):
    SCRIPT = 'sync-certificates.sh'


class TestCertPublishLibrary(CertScriptFixture):
    """Unit-level checks on cert-publish-lib.sh itself."""

    def call(self, snippet, *args):
        return subprocess.run(
            ['bash', '-c', '. "$1"; shift; ' + snippet, '_', LIB, *args],
            env=self.env(), capture_output=True, text=True)

    def test_valid_bundle_accepted(self):
        path = write(os.path.join(self.tmp, 'ok.pem'), NEW_BUNDLE)
        self.assertEqual(self.call('cert_bundle_valid "$1"', path).returncode, 0)

    def test_empty_and_missing_bundles_rejected(self):
        empty = write(os.path.join(self.tmp, 'empty.pem'), '')
        self.assertNotEqual(self.call('cert_bundle_valid "$1"', empty).returncode, 0)
        missing = os.path.join(self.tmp, 'nope.pem')
        self.assertNotEqual(self.call('cert_bundle_valid "$1"', missing).returncode, 0)

    def test_key_without_end_marker_rejected(self):
        truncated = write(os.path.join(self.tmp, 'cut.pem'),
                          TEST_CERT + '-----BEGIN PRIVATE KEY-----\nMIIEvAIB\n')
        self.assertNotEqual(self.call('cert_bundle_valid "$1"', truncated).returncode, 0)

    def test_a_broken_live_pem_does_not_overwrite_a_good_backup(self):
        """Mirrors create_backup(require_valid=True) in haproxy_manager.py.

        If the pem currently on disk is already garbage, archiving it would
        replace a restorable backup with an unusable one.
        """
        os.makedirs(self.backup_dir)
        good_backup = write(os.path.join(self.backup_dir, DOMAIN + '.pem'),
                            PREVIOUS_BUNDLE)
        write(self.live_pem, 'garbage, not a pem at all\n')

        result = self.call('cert_publish "$1" "$2" "$3"',
                           self.src_cert, self.src_key, self.live_pem)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(read(self.live_pem), NEW_BUNDLE)
        self.assertEqual(read(good_backup), PREVIOUS_BUNDLE,
                         'a good backup was overwritten with an unusable pem')

    def test_publish_fails_loudly_when_the_rename_cannot_happen(self):
        """No silent fallback to writing straight into the certs dir."""
        self.seed_previous_bundle()
        before = read(self.live_pem)
        os.chmod(self.certs_dir, 0o500)          # no writes: mv will fail
        self.addCleanup(os.chmod, self.certs_dir, 0o755)
        if os.geteuid() == 0:
            self.skipTest('root ignores directory permissions')

        result = self.call('cert_publish "$1" "$2" "$3"',
                           self.src_cert, self.src_key, self.live_pem)

        self.assertNotEqual(result.returncode, 0,
                            'a failed rename was reported as success')
        self.assertEqual(read(self.live_pem), before,
                         'the live pem was damaged by a failed rename')
        self.assert_no_staging_leftovers()

    def test_haproxy_config_ok_follows_the_validator(self):
        self.assertEqual(self.call('haproxy_config_ok').returncode, 0)
        write(self.haproxy_cfg, GOOD_HAPROXY_CFG + BROKEN_TOKEN + '\n')
        self.assertNotEqual(self.call('haproxy_config_ok').returncode, 0)

    def test_missing_openssl_warns_but_does_not_block(self):
        """Best-effort layer: a missing checker must not stall renewals."""
        fake_path = os.path.join(self.tmp, 'no-openssl-bin')
        os.makedirs(fake_path)
        for tool in ('cat', 'grep', 'mktemp', 'mv', 'cp', 'rm', 'mkdir',
                     'basename', 'dirname', 'find', 'date', 'chmod'):
            real = shutil.which(tool)
            if real:
                os.symlink(real, os.path.join(fake_path, tool))
        path = write(os.path.join(self.tmp, 'ok.pem'), NEW_BUNDLE)

        # bash by absolute path: the stripped PATH cannot resolve it.
        result = subprocess.run(
            [shutil.which('bash'), '-c', '. "$1"; cert_bundle_valid "$2"',
             '_', LIB, path],
            env=self.env(PATH=fake_path), capture_output=True, text=True)

        self.assertEqual(result.returncode, 0,
                         'a missing openssl blocked publication')
        self.assertRegex(result.stdout + result.stderr,
                         r'(?i)warning.*openssl',
                         'the skipped pairing check was not announced loudly')

    def test_missing_openssl_still_rejects_a_structurally_broken_bundle(self):
        fake_path = os.path.join(self.tmp, 'no-openssl-bin2')
        os.makedirs(fake_path)
        for tool in ('cat', 'grep', 'date'):
            real = shutil.which(tool)
            if real:
                os.symlink(real, os.path.join(fake_path, tool))
        path = write(os.path.join(self.tmp, 'nokey.pem'), TEST_CERT)

        # bash by absolute path: the stripped PATH cannot resolve it.
        result = subprocess.run(
            [shutil.which('bash'), '-c', '. "$1"; cert_bundle_valid "$2"',
             '_', LIB, path],
            env=self.env(PATH=fake_path), capture_output=True, text=True)

        self.assertNotEqual(result.returncode, 0,
                            'structural checks stopped being mandatory')


class TestScriptsAreSane(unittest.TestCase):
    """Cheap static guards against the failure mode coming back."""

    SHELL_FILES = ('renew-certificates.sh', 'sync-certificates.sh',
                   'cert-publish-lib.sh')

    def test_shell_files_parse(self):
        for name in self.SHELL_FILES:
            path = os.path.join(SCRIPTS_DIR, name)
            result = subprocess.run(['bash', '-n', path],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0,
                             f'{name}: {result.stderr}')

    def test_no_script_redirects_into_the_live_pem(self):
        pattern = re.compile(r'>\s*"?\$\{?COMBINED_FILE')
        for name in ('renew-certificates.sh', 'sync-certificates.sh'):
            body = read(os.path.join(SCRIPTS_DIR, name))
            self.assertIsNone(pattern.search(body),
                              f'{name} still redirects output straight into the '
                              f'live pem HAProxy is serving')


if __name__ == '__main__':
    print(f'testing scripts from: {SCRIPTS_DIR}')
    unittest.main(verbosity=2)
