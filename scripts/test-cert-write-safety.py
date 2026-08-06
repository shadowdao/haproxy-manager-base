#!/usr/bin/env python3
"""Regression tests for certificate bundle publishing.

Why this file exists
--------------------
Every code path that refreshed a combined PEM used to do this:

    with open(combined_path, 'w') as combined:              # TRUNCATES
        subprocess.run(['cat', cert, key], stdout=combined)  # rc ignored

`combined_path` is the live bundle HAProxy is serving. open(..., 'w') empties it
BEFORE any source material has been read, and the `cat` exit status was never
checked, so a half-written certbot lineage, an unreadable source or a full disk
left a truncated or key-less PEM in place. HAProxy loads /etc/haproxy/certs as a
directory and refuses to start if any file in it is unusable, so that is HTTPS
down for every site on the host - and unlike a broken haproxy.cfg it is not
recoverable by config rollback.

The bundle endpoint made it worse: it deleted superseded .pem files AND ran
`certbot delete` on their lineages before anything had checked that the
replacement was usable, destroying both copies of a working certificate.
Recovery there means fresh, rate-limited ACME orders.

These tests pin the invariants:
  * a failed publish leaves the previously served bundle byte-for-byte intact
    and the edge still able to start;
  * nothing is published that is not a complete, validated cert+key pair;
  * no old certificate file is removed and no lineage deleted until the
    replacement is validated, in place, and actually loaded by HAProxy;
  * only final .pem files ever exist in the crt directory.

Running
-------
    python3 scripts/test-cert-write-safety.py            # tests the repo checkout
    HAPROXY_MANAGER_DIR=/some/other/tree \
        python3 scripts/test-cert-write-safety.py        # tests another tree

Pointing HAPROXY_MANAGER_DIR at a pre-fix checkout is how the bugs above were
reproduced: the behavioural tests run there too (the fix-only tests skip
themselves), and they fail.

Same conventions as scripts/test-config-rollback.py: self-contained stdlib
unittest, no pytest/venv/extra dependencies, stub binaries on PATH. The
certificate material below is real (a self-signed leaf plus its matching key,
and one unrelated key for the mismatch case) and embedded as constants so the
suite needs no crypto tooling to create fixtures.
"""

import logging
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

BROKEN_TOKEN = '__BROKEN__'

MODULE_DIR = os.path.abspath(
    os.environ.get('HAPROXY_MANAGER_DIR',
                   os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
)

# haproxy_manager builds its Jinja2 environment from the relative path
# Path('templates'), so it has to be imported with the module dir as cwd.
os.chdir(MODULE_DIR)
sys.path.insert(0, MODULE_DIR)

# The module opens /var/log/haproxy-manager.log at import time via
# logging.FileHandler. Redirect that one call so the suite runs unprivileged.
_LOG_DIR = tempfile.mkdtemp(prefix='haproxy-mgr-test-logs-')
_real_file_handler = logging.FileHandler
logging.FileHandler = (
    lambda fn, *a, **kw: _real_file_handler(
        os.path.join(_LOG_DIR, os.path.basename(fn)), *a, **kw)
)
try:
    import haproxy_manager as hm
except ImportError as exc:  # pragma: no cover - environment problem, not a failure
    sys.stderr.write(
        f"SKIP: cannot import haproxy_manager ({exc}).\n"
        "Install the application requirements first: pip install -r requirements.txt\n"
    )
    raise SystemExit(77)
finally:
    logging.FileHandler = _real_file_handler

logging.getLogger('haproxy_manager').setLevel(logging.CRITICAL)

HAS_PUBLISHER = hasattr(hm, 'publish_pem_bundle')

# FIX_ONLY marks tests that can only run against a tree that HAS the fix, so
# that pointing HAPROXY_MANAGER_DIR at a pre-fix checkout (how the bugs were
# reproduced) skips them instead of erroring.
#
# It used to be `skipUnless(HAS_PUBLISHER, ...)` unconditionally, which is
# tautological when testing THIS tree: rename or delete publish_pem_bundle and
# 10 of the 17 tests silently skip themselves while the run still reports OK.
# A guard that disappears when the thing it guards disappears is not a guard.
# So the escape hatch is now tied to the thing it exists for - testing a
# FOREIGN tree - and a missing publisher in the repo checkout is a hard
# failure (see TestPublisherApiIsPresent).
_REPO_ROOT = os.path.realpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
TESTING_FOREIGN_TREE = os.path.realpath(MODULE_DIR) != _REPO_ROOT
FIX_ONLY = unittest.skipIf(
    TESTING_FOREIGN_TREE and not HAS_PUBLISHER,
    'HAPROXY_MANAGER_DIR points at a tree without the certificate publishing '
    'fix (publish_pem_bundle)')
NEEDS_OPENSSL = unittest.skipUnless(
    shutil.which('openssl'), 'needs the openssl CLI')

# --- real test material -----------------------------------------------------
# Self-signed leaf, CN=test.example.com, SAN test.example.com +
# www.test.example.com, valid until 2126.
LEAF_CERT = """\
-----BEGIN CERTIFICATE-----
MIIDTjCCAjagAwIBAgIUTliK3dNIdYS3i7R3yxNMHfxVWTcwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTAgFw0yNjA4MDYxNTQxMjda
GA8yMTI2MDcxMzE1NDEyN1owGzEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMRuorQDGdsyc/rk3WST8J70
9oVcTz2QSTQ5QNxqa4jKX7vD0YdLK2Kz7TKLbR//ju+dnqFhLTAs38KqljmU5M1d
7hC1frSV9Y9heHTa51fc9hxewDl9535TdIsUga5HT+sc7q3Np7RparOf1NOm/aBd
27j+LGKclbJ5YaU3I39S05H+S8mgmFpLezwQ7uzFomkk/E5deUcqGpJrW8k2t6Uv
jvfejB8FGAM6DxEL4yTjizmIaJE+jadPTJRq1TtHG+LE4rt2UpF4ggNFXlK7xXfp
p0mcIE1b3MwGaPGmAe5Vw2+nl4uD9LRgQh3XxO2+as4QTTYhlR40Fn03ksXVo6cC
AwEAAaOBhzCBhDAdBgNVHQ4EFgQUjAt+yg/dpNHyeWNqH2oAURfW3iUwHwYDVR0j
BBgwFoAUjAt+yg/dpNHyeWNqH2oAURfW3iUwDwYDVR0TAQH/BAUwAwEB/zAxBgNV
HREEKjAoghB0ZXN0LmV4YW1wbGUuY29tghR3d3cudGVzdC5leGFtcGxlLmNvbTAN
BgkqhkiG9w0BAQsFAAOCAQEABo5x4n3/61XxwJEkNPyv/mCAN5t/+NrMxfadRFJK
+jBxtOO8w8vhi21zF1NDVQkt2bt69QGrVleP5X78FaIaI6sJpLKDE1nOyE9Dpt4y
mnLoRi0Ep7NaDV6rHmfbokLkVdd4Z9RKUESnYCc1Zt5x82oGhEe3GJ4ej2HS8sGY
r79qGVEhQIbLPDA3PD+RQCF6+xNU2CVgZUJ7ZtSeAaNaQQqTRUT2qCBvIKfV8fMS
VDmV6/YORV2jTzO3odKsKxXQY8oWCzfwosxD0dJ2zbZWvMAqcQQq3d/iuH8NiS4Y
+zZ6j9KI/RdRYJz/co2FKAy3FfQ/gZo8eWF2gf9RUDgNQg==
-----END CERTIFICATE-----
"""

LEAF_KEY = """\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDEbqK0AxnbMnP6
5N1kk/Ce9PaFXE89kEk0OUDcamuIyl+7w9GHSytis+0yi20f/47vnZ6hYS0wLN/C
qpY5lOTNXe4QtX60lfWPYXh02udX3PYcXsA5fed+U3SLFIGuR0/rHO6tzae0aWqz
n9TTpv2gXdu4/ixinJWyeWGlNyN/UtOR/kvJoJhaS3s8EO7sxaJpJPxOXXlHKhqS
a1vJNrelL4733owfBRgDOg8RC+Mk44s5iGiRPo2nT0yUatU7RxvixOK7dlKReIID
RV5Su8V36adJnCBNW9zMBmjxpgHuVcNvp5eLg/S0YEId18TtvmrOEE02IZUeNBZ9
N5LF1aOnAgMBAAECggEAR0NcA7KcTsmfCga9yx9gzEpSpU838D3IUQn0XgK9wIKq
+JOyEENVGhnsk8nBbTppwMSOKD35BuFAzH7WwU0jNN4+4BD4RsugqsPRz5MbGuUu
5Fv7oN/sfAgK3+owoel9NO7qKGPT07/q1f/GVoLewK9MZ3DO6XelV3px0l6OokHn
Oy+ShWw4CnUXRIAKBuRNLLA0HQ4ld0dceV/kT428tZIluj9pkUhnp9xux5yDWkMu
dj26CXZxp2PMzVLD21TmI/BZO+3Ev+Nf5GaS8GrmROlXLKTE5YDmU1ZTECsSSFLK
Nuw7B3TT+xEQUf5lokDigkbTgIQ5kpnIy1LSbqLAAQKBgQDudSbhaqABZk6B09UL
PZVQZSrGZDXl4vwnkHXArrr2BRz1+B67tWebq3V0pCrZqwFc9eOtq1F0vH6q11Ns
vLZ9lZ7KUEsFS6InZkqSQSGrgWt4MIjocc8qHLlaEk/EGgHgtwBblm2hEyDwy487
jhnc2wI82D6ZLvIc27pQQFNjAQKBgQDS4gXINPsaq9YFiQ9JQG8oJGSq6yn137wJ
DQYrTaB9tqcmIXWx6ZgMiKZiOGLQYVmlNFoh10cTxbebWjXjWL4VP3gg5nE87pQz
8KKvkXP07QWiSQLV5SJzEeDM/l3Lkyc9O69PYnusWjdFOrIPDTmxZ2l6wNyAVxpm
zEK17gYOpwKBgQC+glxAxZX16E2ajanspBPRujG1dMRW2MTJuzFIcpCuEyGzJbsw
DlsrVI2vVaViZ6vcIBr5WiDm2d19EjD1c8N8i/fj/Mgi/+0Z+zBirqR+yBQbXvNS
efKf23j+DBksO/b6GFqx0XnesVCk8IyLcRkaiOK9x6ojag1Gnwm4Kdw1AQKBgAen
ssQIwFDAih1bU1W6ZA6V+52Eudo2C/JcKawqvjeyCLFGp6oUq7NQxpFsMJIV5pYr
p1XxJaBfHgIirTAaiZPl4Ot40gV/N5wHETDEW+w5Kmowskyna6+3p2xpk2gPaG49
m2iLT6f7AmSd89a+CSkacubE13xFLS0sHwPRpyCjAoGBAJfFYXWFAD2viAmBshCS
g6Ba78n0vkF74/DnFRWpIqxw8vufQ5nY/k67tGko+zZg3jzI1d1REvI1qHYctKFM
Ko7fmF3ny803cdJT8EuIlrU2+V5lh0GkPO/or+68qso+qBj3R8f6jRLbahkUbY5e
yR3PzoVVfGaftvLsdbAqD+VC
-----END PRIVATE KEY-----
"""

# A perfectly valid key that simply does not belong to LEAF_CERT.
UNRELATED_KEY = """\
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDBpZAkTBLhiDnq
cCjsSsBwAW/fhYYfx+t2iauYPrvaLmiJHFkXEr7gaBlYWTKJRISY2jqYTM1RdLJB
DDjNThrewOLtcF7d+k+ArMPWXxqBotbCTKMkh7djRfnXEcjJ/mil31W351cR/11q
EPBdCcj4BYegBzc4GG2qIh/Nww+jd1KkkxUhnTMPp5Ie0myJafh0Pdsss9lbmqBH
fW6BO341C9jG8N/7C7FHCzzf74q7mf0Bx+isYgW/1YL0Ndg/R8yTRVKTbPvU3ZM2
hEeLDXFbvcceREq1j0VEXGd9rcB2JHBE4TAQZq9WmeT51uynW8a1hnUcUs/li7jL
cuI6DswxAgMBAAECggEADeC4Z42HJeAeLHG80RBbYbuMobN/RPxOIOjlYgwO6Og+
CCN+tANdKBZ1yInd8A33xb+QBvWsGjwXgUdns7j2/oNK0BLnTZfAhlt7Tnvy2ZsK
spKM95N9XlE3wkTNQ8Kmi8qpaTxcVlcbgfw0SaqnmzTEP0D9IVlI1LJM3rFtx7xn
xhrtKzhcv6WbnZKjrKlPpJq7dFC8+3WtbWFBvWFUTs2mQJ3eFWlc/EBh60PKuMAz
44aMrypzQSdcAs0+f0fOpnhpWa6Px4uEAIvSNPjPI7gt/7v4qb+fNrGGYrou9Pd9
hW0MGDOxfTxr094YCdapklIV3OyCvrCeS8XVYnVddQKBgQDiZzBTNnc6O2EWgY2h
82VSEBMDTnk+rT7CTx4RGkzyq2z6oUg0itr+TQGhyjRX24VbROXtXlCBNXQkn9UA
aZsss+KnrF6KLEmdwQIoNKSgBIiTgX/PHmkf3a+scDShgL5aIItjazu9TEblBqKF
+H4eBwuPjKc20h2CctoZswE0HQKBgQDa9iZBOPCjyTtq4oSeJbyvjYfJN5EoI9nZ
hl0Yqa8ajbJ8nyxGziy5z5ktqBFYiVa53xamagJJp69DCmnm6vSy01KZIOtKNEKb
PCaNc1Lp+cf5SEIHX0Pakx/zmi0PzDx1V0DhtjLhF8dFUfQhWvvxF+m16LZeBYZ+
0UP6NRAUJQKBgQCM/e/1UkzrocDzkBiQy4/EjCga/gq5gpA716OEyRk0YpdKeZgK
yJJancAvbkoskJO64+xAZ2TBInXCvRqb2Ch/rUKwYsK5T51EtcbPHQGMeWZIXfQn
GuwioR7exz2vegqQ/AVyE3yvhUn9JKWfwsFfl8mWSuRzWmRwMXArYvOT7QKBgQCV
6Y2LfjaTjMUXivsNY/zpnNbo1xiVCOawXaQDrLlsTrNzS29/Es3gcdgIQFeP7Ifq
Pmk9irsCPsJp/gk/xoG+pZyZpsYxSdKIgghLNDgCZbeaXvSGI51LWwu3N0m+1TBX
jmOnpZz0K9mNBm1FIQv5p0ul9ixV9yZ8UT5fYlEd2QKBgQDLWMgMD9rOORl+0s8Z
RcpSfu2E7KP0e2DaxP4dYRmUyNuE8iK8hglNqqVBLhrFHmDZ1yo1lFIDBROaJ9EW
pAxSb8kRi2dba8ZnpEDhhiqoDwkoXRDOrzd5bdHyiOJV39U1F5U6HqDE4URaq8iu
k49ABlblWHBsoUF63ka1PBrMgA==
-----END PRIVATE KEY-----
"""

GOOD_BUNDLE = LEAF_CERT + LEAF_KEY

# What a bundle already on disk looks like when a test starts: the same, valid
# material plus a trailing marker. Without it the "previous" and "new" bundles
# are byte-identical, and a test that meant to prove a publish HAPPENED cannot
# tell that from a publish that did nothing at all. Trailing text after the key
# is ignored by both HAProxy and openssl, so the file stays genuinely usable.
PREVIOUS_MARKER = '# previous bundle\n'
PREVIOUS_BUNDLE = GOOD_BUNDLE + PREVIOUS_MARKER

# Stub haproxy. Beyond the config check the parent suite's stub does, this one
# also walks the crt directory the way HAProxy does when a `bind ... ssl crt
# <dir>` is used: every file in there must be a loadable cert+key bundle, and
# one that is not takes the whole listener (i.e. the whole edge) down. That is
# what makes "the edge would still start" an assertion rather than a hope.
FAKE_HAPROXY = textwrap.dedent(f"""\
    #!/bin/sh
    #   haproxy -c -f FILE  -> reject FILE containing {BROKEN_TOKEN}
    #                          reject any unusable file in $TEST_CERTS_DIR
    cfg=""
    while [ $# -gt 0 ]; do
      case "$1" in -f) cfg="$2"; shift ;; esac
      shift
    done
    if [ -n "$cfg" ] && grep -q '{BROKEN_TOKEN}' "$cfg" 2>/dev/null; then
      echo "[ALERT] parsing [$cfg:1] : unknown keyword '{BROKEN_TOKEN}'" >&2
      exit 1
    fi
    if [ -n "$TEST_CERTS_DIR" ] && [ -d "$TEST_CERTS_DIR" ]; then
      for f in "$TEST_CERTS_DIR"/*; do
        [ -e "$f" ] || continue
        if [ ! -s "$f" ]; then
          echo "[ALERT] unable to load SSL certificate from empty file '$f'" >&2
          exit 1
        fi
        if ! grep -q -- '-----END CERTIFICATE-----' "$f"; then
          echo "[ALERT] unable to load SSL certificate from '$f'" >&2
          exit 1
        fi
        if ! grep -q -- '-----END .*PRIVATE KEY-----' "$f"; then
          echo "[ALERT] unable to load SSL private key from '$f'" >&2
          exit 1
        fi
      done
    fi
    exit 0
""")

# certbot stub: succeeds, announces a renewal, and records every invocation so
# tests can assert that `certbot delete` did or did not run.
FAKE_CERTBOT = textwrap.dedent("""\
    #!/bin/sh
    if [ -n "$TEST_CERTBOT_LOG" ]; then
      echo "$@" >> "$TEST_CERTBOT_LOG"
    fi
    case "$1" in
      renew) echo "Congratulations, all renewals succeeded" ;;
      delete) [ -n "$TEST_CERTBOT_DELETE_FAILS" ] && exit 1 ;;
    esac
    exit 0
""")

# socat stub: records reload attempts so tests can assert HAProxy was NOT
# reloaded with unvalidated material.
FAKE_SOCAT = textwrap.dedent("""\
    #!/bin/sh
    if [ -n "$TEST_SOCAT_LOG" ]; then
      echo "$@" >> "$TEST_SOCAT_LOG"
    fi
    cat > /dev/null 2>&1
    exit 0
""")


def structurally_valid(text):
    """Is this text a usable cert+key bundle?

    Deliberately implemented here rather than calling into haproxy_manager, so
    the assertions stay honest when the suite is pointed at a tree whose
    validation code is the thing under test (or absent entirely).
    """
    return ('-----BEGIN CERTIFICATE-----' in text
            and '-----END CERTIFICATE-----' in text
            and any(f'-----END {label}-----' in text for label in
                    ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY')))


class CertPublishTestCase(unittest.TestCase):
    """Isolated fake /etc/haproxy + /etc/letsencrypt plus stub binaries."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='haproxy-cert-test-')
        self.addCleanup(shutil.rmtree, self.tmp, True)

        bindir = os.path.join(self.tmp, 'bin')
        os.makedirs(bindir)
        for name, body in (('haproxy', FAKE_HAPROXY),
                           ('certbot', FAKE_CERTBOT),
                           ('socat', FAKE_SOCAT)):
            path = os.path.join(bindir, name)
            with open(path, 'w') as fh:
                fh.write(body)
            os.chmod(path, 0o755)

        self.certbot_log = os.path.join(self.tmp, 'certbot-invocations.log')
        self.socat_log = os.path.join(self.tmp, 'socat-invocations.log')
        self.etc = os.path.join(self.tmp, 'etc')
        self.certs = os.path.join(self.etc, 'certs')
        os.makedirs(self.certs)

        self._saved_env = dict(os.environ)
        os.environ['PATH'] = bindir + os.pathsep + os.environ['PATH']
        os.environ['TEST_CERTS_DIR'] = self.certs
        os.environ['TEST_CERTBOT_LOG'] = self.certbot_log
        os.environ['TEST_SOCAT_LOG'] = self.socat_log
        self.addCleanup(self._restore_env)

        overrides = {
            'DB_FILE': os.path.join(self.etc, 'haproxy_config.db'),
            'HAPROXY_CONFIG_PATH': os.path.join(self.etc, 'haproxy.cfg'),
            'HAPROXY_BACKUP_PATH': os.path.join(self.etc, 'haproxy.cfg.backup'),
            'BLOCKED_IPS_MAP_PATH': os.path.join(self.etc, 'blocked_ips.map'),
            'BLOCKED_IPS_MAP_BACKUP_PATH': os.path.join(self.etc, 'blocked_ips.map.backup'),
            'CORAZA_SPOE_CONFIG_PATH': os.path.join(self.etc, 'coraza-spoe.cfg'),
            'CORAZA_SPOE_BACKUP_PATH': os.path.join(self.etc, 'coraza-spoe.cfg.backup'),
            'CLUSTER_SECRET_PATH': os.path.join(self.etc, 'cluster-secret'),
            'SSL_CERTS_DIR': self.certs,
            'HAPROXY_SOCKET_PATH': os.path.join(self.etc, 'haproxy.sock'),
            'API_KEY': None,
        }
        self._saved = {}
        for name, value in overrides.items():
            self._saved[name] = getattr(hm, name, None)
            setattr(hm, name, value)
        self.addCleanup(self._restore_globals)

        # find_certbot_live_dir() resolves /etc/letsencrypt/live, which we
        # cannot repoint on older trees. Stubbing this one lookup keeps the
        # suite runnable against a pre-fix checkout for bug reproduction; every
        # line of code under test is downstream of it.
        self.le_live = os.path.join(self.tmp, 'letsencrypt', 'live')
        os.makedirs(self.le_live)
        self._real_find = hm.find_certbot_live_dir
        hm.find_certbot_live_dir = self._fake_find_live_dir
        self.addCleanup(
            lambda: setattr(hm, 'find_certbot_live_dir', self._real_find))

        # log_operation() appends to a hardcoded /var/log path. Injecting `open`
        # into the module namespace shadows the builtin for that module only.
        real_open = open
        log_dir = self.tmp

        def _redirecting_open(path, *args, **kwargs):
            if isinstance(path, str) and path.startswith('/var/log/'):
                path = os.path.join(log_dir, os.path.basename(path))
            return real_open(path, *args, **kwargs)

        hm.open = _redirecting_open
        self.addCleanup(lambda: hm.__dict__.pop('open', None))

        hm.init_db()
        self.client = hm.app.test_client()

    def _restore_env(self):
        os.environ.clear()
        os.environ.update(self._saved_env)

    def _restore_globals(self):
        for name, value in self._saved.items():
            if value is None:
                setattr(hm, name, None)
            else:
                setattr(hm, name, value)

    def _fake_find_live_dir(self, *args, **kwargs):
        base = args[0] if args else kwargs.get('base_domain')
        path = os.path.join(self.le_live, base)
        return path if os.path.isdir(path) else None

    # -- helpers ---------------------------------------------------------
    def write(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as fh:
            fh.write(text)
        return path

    def read(self, path):
        with open(path) as fh:
            return fh.read()

    def make_lineage(self, domain, cert=LEAF_CERT, key=LEAF_KEY):
        """Create a certbot live directory. key=None omits privkey.pem."""
        live = os.path.join(self.le_live, domain)
        os.makedirs(live, exist_ok=True)
        self.write(os.path.join(live, 'fullchain.pem'), cert)
        if key is not None:
            self.write(os.path.join(live, 'privkey.pem'), key)
        return live

    def publish_live_bundle(self, domain, content=PREVIOUS_BUNDLE):
        """A good bundle already being served for `domain`."""
        return self.write(os.path.join(self.certs, f'{domain}.pem'), content)

    def add_domain(self, domain, backend_name, ssl_cert_path=None):
        with sqlite3.connect(hm.DB_FILE) as conn:
            cur = conn.cursor()
            cur.execute(
                'INSERT INTO domains (domain, ssl_enabled, ssl_cert_path) '
                'VALUES (?, ?, ?)',
                (domain, 1 if ssl_cert_path else 0, ssl_cert_path))
            domain_id = cur.lastrowid
            cur.execute('INSERT INTO backends (name, domain_id) VALUES (?, ?)',
                        (backend_name, domain_id))
            backend_id = cur.lastrowid
            cur.execute(
                'INSERT INTO backend_servers '
                '(backend_id, server_name, server_address, server_port) '
                'VALUES (?, ?, ?, ?)', (backend_id, 'srv1', '10.0.0.1', 8080))
            conn.commit()

    def certbot_invocations(self):
        if not os.path.exists(self.certbot_log):
            return []
        return [line.strip() for line in self.read(self.certbot_log).splitlines()]

    def certbot_deletes(self):
        return [c for c in self.certbot_invocations() if c.startswith('delete')]

    def edge_would_start(self):
        """Would HAProxy load the current config + crt directory?"""
        return subprocess.run(
            ['haproxy', '-c', '-f', hm.HAPROXY_CONFIG_PATH],
            capture_output=True).returncode == 0

    def assert_only_final_pems_in_certs_dir(self):
        strays = [n for n in os.listdir(self.certs) if not n.endswith('.pem')]
        self.assertEqual(
            [], strays,
            'HAProxy loads every file in the crt directory; only final .pem '
            f'bundles may exist there, found: {strays}')


class TestLivePemIsNeverTruncated(CertPublishTestCase):
    """Bug 1: the live PEM was opened in truncate mode before any source read."""

    def test_failed_renewal_leaves_previous_bundle_intact(self):
        """HEADLINE: a failure mid-publish must not disturb what is served.

        The renewed lineage has a privkey.pem that exists but is empty - the
        signature of a write that died half way, and the case the old
        `os.path.exists(key)` guard waved straight through into
        `cat fullchain emptykey > livepem`.
        """
        cert_path = self.publish_live_bundle('renew.example.com')
        before = self.read(cert_path)
        self.add_domain('renew.example.com', 'renew_backend',
                        ssl_cert_path=cert_path)
        self.make_lineage('renew.example.com', key='')

        resp = self.client.post('/api/certificates/renew')

        after = self.read(cert_path)
        self.assertEqual(before, after,
                         'the live PEM must still be the previous bundle, '
                         'byte for byte')
        self.assertTrue(structurally_valid(after),
                        'the served bundle must still contain a cert AND a key')
        self.assertTrue(self.edge_would_start(),
                        'HAProxy must still be able to load the crt directory')
        self.assertEqual(500, resp.status_code,
                         'a failed publish must be reported loudly, not as success')
        self.assert_only_final_pems_in_certs_dir()

    def test_missing_source_key_leaves_previous_bundle_intact(self):
        """Same invariant when privkey.pem is absent rather than empty."""
        cert_path = self.publish_live_bundle('gone.example.com')
        before = self.read(cert_path)
        self.add_domain('gone.example.com', 'gone_backend',
                        ssl_cert_path=cert_path)
        self.make_lineage('gone.example.com', key=None)

        self.client.post('/api/certificates/renew')

        self.assertEqual(before, self.read(cert_path))
        self.assertTrue(self.edge_would_start())

    def test_issuance_failure_leaves_previous_bundle_intact(self):
        """/api/ssl re-issuing over an existing bundle must be all-or-nothing."""
        cert_path = self.publish_live_bundle('issue.example.com')
        before = self.read(cert_path)
        self.add_domain('issue.example.com', 'issue_backend')
        self.make_lineage('issue.example.com', key='')

        resp = self.client.post('/api/ssl', json={'domain': 'issue.example.com'})

        self.assertEqual(before, self.read(cert_path))
        self.assertTrue(structurally_valid(self.read(cert_path)))
        self.assertTrue(self.edge_would_start())
        self.assertEqual(500, resp.status_code)
        self.assertEqual('error', resp.get_json()['status'])

    def test_successful_renewal_still_publishes(self):
        """The guard must not block the normal path.

        The old version built its "renewed" certificate with a no-op
        `.replace('\\n-----END CERTIFICATE-----', '\\n-----END CERTIFICATE-----')`,
        so the renewed lineage was byte-identical to what was already being
        served. Every assertion still passed if the renewal published nothing
        at all - which is the failure this test is supposed to catch. The live
        bundle now carries a marker the renewed material does not, so "the file
        on disk changed" is an actual assertion.
        """
        cert_path = self.publish_live_bundle('ok.example.com')
        self.assertIn(PREVIOUS_MARKER, self.read(cert_path),
                      'fixture precondition: the live bundle is distinguishable')
        self.add_domain('ok.example.com', 'ok_backend', ssl_cert_path=cert_path)
        self.make_lineage('ok.example.com')

        resp = self.client.post('/api/certificates/renew')

        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        published = self.read(cert_path)
        self.assertEqual(GOOD_BUNDLE, published,
                         'the renewed cert+key was not written to the live pem')
        self.assertNotIn(PREVIOUS_MARKER, published,
                         'the previous bundle is still on disk: the renewal '
                         'published nothing')
        self.assertTrue(structurally_valid(published))
        self.assertTrue(self.edge_would_start())
        self.assert_only_final_pems_in_certs_dir()
        backup = os.path.join(hm.cert_backup_dir(), 'ok.example.com.pem')
        self.assertTrue(os.path.exists(backup))
        self.assertEqual(PREVIOUS_BUNDLE, self.read(backup),
                         'the archived copy is not the bundle that was replaced')


class TestOldCertificateIsNotDestroyedFirst(CertPublishTestCase):
    """Bug 2: superseded .pem removed and lineage deleted before validation."""

    def _setup_supersede(self, broken=True):
        # An older single-SAN file whose CN is covered by the new bundle.
        old_path = self.write(
            os.path.join(self.certs, 'www.test.example.com.pem'), GOOD_BUNDLE)
        self.add_domain('test.example.com', 'bundle_backend')
        self.make_lineage('test.example.com', key='' if broken else LEAF_KEY)
        return old_path

    @NEEDS_OPENSSL
    def test_failed_bundle_does_not_remove_the_old_certificate(self):
        old_path = self._setup_supersede(broken=True)

        resp = self.client.post('/api/ssl/bundle', json={
            'primary': 'test.example.com',
            'sans': ['www.test.example.com'],
        })

        self.assertEqual(500, resp.status_code)
        self.assertTrue(
            os.path.exists(old_path),
            'the superseded certificate must survive a failed replacement - '
            'it may be the only working copy left')
        self.assertTrue(structurally_valid(self.read(old_path)))
        self.assertEqual(
            [], self.certbot_deletes(),
            '`certbot delete` is irreversible and rate-limited to recover from; '
            'it must never run for a replacement that was never published')
        self.assertTrue(self.edge_would_start())

    @FIX_ONLY
    @NEEDS_OPENSSL
    def test_lineage_is_deleted_only_after_haproxy_loads_the_bundle(self):
        """A reload failure must leave the lineage intact and the file recoverable."""
        old_path = self._setup_supersede(broken=False)
        # Make generate_config() produce a config the validator rejects, so the
        # publish succeeds but HAProxy never loads it.
        self.add_domain('other.example.com', BROKEN_TOKEN + '_backend')

        resp = self.client.post('/api/ssl/bundle', json={
            'primary': 'test.example.com',
            'sans': ['www.test.example.com'],
        })

        self.assertEqual(500, resp.status_code)
        self.assertEqual(
            [], self.certbot_deletes(),
            'the lineage must not be deleted when HAProxy did not reload')
        self.assertFalse(os.path.exists(old_path))
        quarantined = os.path.join(hm.cert_backup_dir(),
                                   os.path.basename(old_path))
        self.assertTrue(os.path.exists(quarantined),
                        'the superseded file must be recoverable by hand')
        self.assertTrue(structurally_valid(self.read(quarantined)))

    @FIX_ONLY
    @NEEDS_OPENSSL
    def test_successful_bundle_still_supersedes_and_deletes(self):
        """The cleanup must still do its job on the happy path."""
        old_path = self._setup_supersede(broken=False)

        resp = self.client.post('/api/ssl/bundle', json={
            'primary': 'test.example.com',
            'sans': ['www.test.example.com'],
        })

        self.assertEqual(200, resp.status_code, resp.get_data(as_text=True))
        self.assertFalse(os.path.exists(old_path),
                         'the superseded file must leave the crt directory or '
                         'it keeps shadowing the new bundle')
        self.assertEqual(['delete --cert-name www.test.example.com -n'],
                         self.certbot_deletes())
        self.assertTrue(self.edge_would_start())
        self.assert_only_final_pems_in_certs_dir()


class TestBundleValidation(CertPublishTestCase):
    """What may and may not be published."""

    @FIX_ONLY
    def test_structure_checks(self):
        cases = [
            ('', False, 'empty'),
            ('   \n', False, 'whitespace only'),
            (LEAF_CERT, False, 'certificate without a key'),
            (LEAF_KEY, False, 'key without a certificate'),
            (GOOD_BUNDLE[:len(LEAF_CERT) // 2], False, 'truncated mid-block'),
            (LEAF_CERT + LEAF_KEY.replace('-----END PRIVATE KEY-----', ''),
             False, 'key block never closed'),
            (GOOD_BUNDLE, True, 'complete bundle'),
        ]
        for text, expected, label in cases:
            with self.subTest(label):
                ok, _ = hm.validate_pem_structure(text)
                self.assertEqual(expected, ok)

    @FIX_ONLY
    @NEEDS_OPENSSL
    def test_key_must_match_the_leaf_certificate(self):
        dest = os.path.join(self.certs, 'pair.example.com.pem')
        cert = self.write(os.path.join(self.tmp, 'src', 'fullchain.pem'), LEAF_CERT)
        bad_key = self.write(os.path.join(self.tmp, 'src', 'wrong.pem'),
                             UNRELATED_KEY)
        with self.assertRaises(hm.CertificatePublishError):
            hm.publish_pem_bundle(dest, [cert, bad_key])
        self.assertFalse(os.path.exists(dest))
        self.assert_only_final_pems_in_certs_dir()

    @FIX_ONLY
    @NEEDS_OPENSSL
    def test_mismatched_pair_does_not_disturb_the_live_bundle(self):
        """The atomic-swap invariant, not just the pre-write content check.

        A cert+key that only turns out to be unusable once assembled (here: a
        structurally perfect bundle whose key belongs to another certificate)
        is the case that proves the live file is never opened for writing -
        the failure is discovered with the replacement already fully staged.
        """
        dest = self.publish_live_bundle('swap.example.com')
        before = self.read(dest)
        cert = self.write(os.path.join(self.tmp, 'srcm', 'fullchain.pem'),
                          LEAF_CERT)
        bad_key = self.write(os.path.join(self.tmp, 'srcm', 'privkey.pem'),
                             UNRELATED_KEY)

        with self.assertRaises(hm.CertificatePublishError):
            hm.publish_pem_bundle(dest, [cert, bad_key])

        self.assertEqual(before, self.read(dest),
                         'the previously served bundle must survive byte for byte')
        self.assertTrue(self.edge_would_start())
        self.assert_only_final_pems_in_certs_dir()

    @FIX_ONLY
    def test_unexpected_error_mid_publish_leaves_the_live_bundle_intact(self):
        """A failure anywhere between staging and swap must be survivable.

        Stands in for the failures we cannot stage deterministically - disk
        full, container killed, an exception in a future validation step.
        """
        dest = self.publish_live_bundle('boom.example.com')
        before = self.read(dest)
        cert = self.write(os.path.join(self.tmp, 'srcb', 'fullchain.pem'),
                          LEAF_CERT)
        key = self.write(os.path.join(self.tmp, 'srcb', 'privkey.pem'), LEAF_KEY)

        real_validate = hm.validate_pem_bundle

        def _explode(path):
            raise RuntimeError('simulated failure while publishing')

        hm.validate_pem_bundle = _explode
        self.addCleanup(lambda: setattr(hm, 'validate_pem_bundle', real_validate))

        with self.assertRaises(Exception):
            hm.publish_pem_bundle(dest, [cert, key])

        self.assertEqual(before, self.read(dest))
        self.assertTrue(self.edge_would_start())
        self.assert_only_final_pems_in_certs_dir()

    @FIX_ONLY
    def test_staging_and_backups_live_outside_the_crt_directory(self):
        """A temp or backup file inside the crt dir would be loaded by HAProxy.

        `startswith(certs + os.sep)` alone let the worst case through: if
        cert_staging_dir() returned the crt directory ITSELF - staging straight
        into the directory HAProxy scans, the exact hazard this design exists
        to prevent - the assertion passed, because the certs dir is not a
        strict subpath of itself.
        """
        certs = os.path.realpath(self.certs)
        for name, path in (('staging', hm.cert_staging_dir()),
                           ('backup', hm.cert_backup_dir())):
            real = os.path.realpath(path)
            self.assertNotEqual(
                certs, real,
                f'the {name} directory IS the crt directory - HAProxy would '
                f'load every temp/backup file in it')
            self.assertFalse(
                real.startswith(certs + os.sep),
                f'the {name} directory {path} must not be inside {self.certs}')

    @FIX_ONLY
    def test_previous_bundle_is_backed_up_on_publish(self):
        dest = self.publish_live_bundle('backup.example.com')
        previous = self.read(dest)
        cert = self.write(os.path.join(self.tmp, 'src2', 'fullchain.pem'),
                          LEAF_CERT)
        key = self.write(os.path.join(self.tmp, 'src2', 'privkey.pem'), LEAF_KEY)

        hm.publish_pem_bundle(dest, [cert, key])

        backup = os.path.join(hm.cert_backup_dir(), 'backup.example.com.pem')
        self.assertTrue(os.path.exists(backup),
                        'an operator needs a manual path back to the previous '
                        'certificate')
        self.assertEqual(previous, self.read(backup))

    @FIX_ONLY
    def test_corrupt_live_bundle_does_not_overwrite_a_good_backup(self):
        """Mirrors create_backup(require_valid=True) for haproxy.cfg."""
        dest = os.path.join(self.certs, 'guard.example.com.pem')
        os.makedirs(hm.cert_backup_dir(), exist_ok=True)
        good_backup = self.write(
            os.path.join(hm.cert_backup_dir(), 'guard.example.com.pem'),
            GOOD_BUNDLE)
        self.write(dest, LEAF_CERT)  # live file is key-less garbage

        cert = self.write(os.path.join(self.tmp, 'src3', 'fullchain.pem'),
                          LEAF_CERT)
        key = self.write(os.path.join(self.tmp, 'src3', 'privkey.pem'), LEAF_KEY)
        hm.publish_pem_bundle(dest, [cert, key])

        self.assertEqual(GOOD_BUNDLE, self.read(good_backup),
                         'a good backup must not be replaced by a corrupt live '
                         'file')

    @FIX_ONLY
    @NEEDS_OPENSSL
    def test_no_temp_file_survives_a_failed_publish(self):
        """The failure must happen AFTER something has been staged.

        This used to feed publish_pem_bundle() an empty privkey, which is
        rejected while reading the sources - before the staging directory is
        even created. The test then asserted `[] == []` and proved nothing
        about temp-file cleanup. A structurally perfect bundle whose key
        belongs to a different certificate is rejected by the pairing check,
        which runs on the fully staged file, so the temp definitely exists at
        the moment the publish fails.
        """
        dest = os.path.join(self.certs, 'leak.example.com.pem')
        cert = self.write(os.path.join(self.tmp, 'src4', 'fullchain.pem'),
                          LEAF_CERT)
        wrong = self.write(os.path.join(self.tmp, 'src4', 'privkey.pem'),
                           UNRELATED_KEY)
        with self.assertRaises(hm.CertificatePublishError):
            hm.publish_pem_bundle(dest, [cert, wrong])

        staging = hm.cert_staging_dir()
        self.assertTrue(os.path.isdir(staging),
                        'the publish never got as far as staging, so this '
                        'asserts nothing about cleanup')
        self.assertEqual([], os.listdir(staging),
                         'staged files must be cleaned up when a publish fails')
        self.assertFalse(os.path.exists(dest),
                         'a rejected bundle was published anyway')
        self.assert_only_final_pems_in_certs_dir()


    @FIX_ONLY
    @NEEDS_OPENSSL
    def test_empty_pem_blocks_are_rejected(self):
        """Why the pairing check may not be best-effort.

        Structural validation is weak on its own: BEGIN/END pairs with nothing
        between them satisfy every rule in validate_pem_structure(). Only
        openssl can say this is not a certificate.
        """
        hollow = ('-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n'
                  '-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----\n')
        ok, _ = hm.validate_pem_structure(hollow)
        self.assertTrue(ok, 'precondition: structure alone accepts this file')

        path = self.write(os.path.join(self.tmp, 'hollow.pem'), hollow)
        ok, msg = hm.validate_pem_bundle(path)
        self.assertFalse(ok, 'a bundle of empty pem blocks was accepted')

    @FIX_ONLY
    def test_publish_refuses_when_the_pairing_check_cannot_run(self):
        """No fail-open. 'unavailable' means the image is broken, not the cert.

        The previous behaviour logged a warning and published on structural
        checks alone, justified by "the Dockerfile does not install the openssl
        CLI". It does - openssl 3.x comes in with ca-certificates, and
        generate_self_signed_cert() shells out to `openssl req` with
        check=True during setup - so this branch never fired and the fail-open
        was safe only by accident.
        """
        real = hm._openssl_pairing_status
        hm._openssl_pairing_status = lambda path: ('unavailable',
                                                   'openssl binary not found')
        self.addCleanup(setattr, hm, '_openssl_pairing_status', real)

        dest = self.publish_live_bundle('nocheck.example.com')
        before = self.read(dest)
        cert = self.write(os.path.join(self.tmp, 'src5', 'fullchain.pem'),
                          LEAF_CERT)
        key = self.write(os.path.join(self.tmp, 'src5', 'privkey.pem'), LEAF_KEY)

        with self.assertRaises(hm.CertificatePublishError):
            hm.publish_pem_bundle(dest, [cert, key])

        self.assertEqual(before, self.read(dest),
                         'the live pem was disturbed by a refused publish')
        self.assert_only_final_pems_in_certs_dir()

    @FIX_ONLY
    def test_binary_corrupt_live_bundle_can_still_be_republished(self):
        """Republishing is how an operator heals a corrupt live pem.

        A pem corrupted into binary (a partial write from before this fix, a
        bad restore) is unreadable as text. backup_existing_pem() opens it in
        text mode and caught only OSError, so the UnicodeDecodeError escaped
        publish_pem_bundle() entirely: the single operation that would have put
        a working certificate back blew up trying to archive the broken one.
        The shell half recovers from this without complaint.
        """
        dest = os.path.join(self.certs, 'binary.example.com.pem')
        with open(dest, 'wb') as fh:
            fh.write(b'\x00\x01\x02\xfe\xff' * 128)
        cert = self.write(os.path.join(self.tmp, 'src6', 'fullchain.pem'),
                          LEAF_CERT)
        key = self.write(os.path.join(self.tmp, 'src6', 'privkey.pem'), LEAF_KEY)

        hm.publish_pem_bundle(dest, [cert, key])

        self.assertEqual(GOOD_BUNDLE, self.read(dest),
                         'a binary-corrupt live pem blocked its own repair')
        self.assertTrue(self.edge_would_start())

    @FIX_ONLY
    def test_published_pem_file_mode(self):
        """Publishing must not silently re-permission a private key.

        The staged file is created by mkstemp at 0600; without the explicit
        mode copy in write_config_atomically() every publish would tighten a
        0644 bundle, and a future change in the other direction would loosen
        one. Neither is a decision a write-safety fix gets to make as a side
        effect, so pin it.
        """
        cert = self.write(os.path.join(self.tmp, 'src7', 'fullchain.pem'),
                          LEAF_CERT)
        key = self.write(os.path.join(self.tmp, 'src7', 'privkey.pem'), LEAF_KEY)

        for mode in (0o644, 0o640, 0o600):
            with self.subTest(oct(mode)):
                dest = self.publish_live_bundle(f'mode{mode:o}.example.com')
                os.chmod(dest, mode)
                hm.publish_pem_bundle(dest, [cert, key])
                self.assertEqual(mode,
                                 stat.S_IMODE(os.stat(dest).st_mode),
                                 'publishing changed who can read the key')

        fresh = os.path.join(self.certs, 'fresh.example.com.pem')
        hm.publish_pem_bundle(fresh, [cert, key])
        fresh_mode = stat.S_IMODE(os.stat(fresh).st_mode)
        self.assertEqual(0o644, fresh_mode,
                         'a newly created bundle should match the 0644 that '
                         '`cat > file` produced under the standard umask')
        self.assertEqual(0, fresh_mode & 0o022,
                         'a private key must never be group/world writable')


@unittest.skipIf(TESTING_FOREIGN_TREE,
                 'HAPROXY_MANAGER_DIR points at another tree')
class TestPublisherApiIsPresent(unittest.TestCase):
    """FIX_ONLY must never be able to hide the fix going missing.

    With `FIX_ONLY = skipUnless(hasattr(hm, 'publish_pem_bundle'))`, renaming
    that one function turned 10 of these 17 tests into skips and the run still
    printed OK. This class fails loudly instead.
    """

    def test_publisher_api_is_present(self):
        for name in ('publish_pem_bundle', 'validate_pem_bundle',
                     'validate_pem_structure', 'backup_existing_pem',
                     'cert_staging_dir', 'cert_backup_dir',
                     'CertificatePublishError', '_openssl_pairing_status'):
            self.assertTrue(
                hasattr(hm, name),
                f'haproxy_manager.{name} is gone - the tests that exercise it '
                f'would otherwise skip themselves and report OK')


class TestClusterSecretSelfHeal(CertPublishTestCase):
    """Bug 4: a zero-byte secret file was never healed."""

    def test_empty_secret_file_is_healed(self):
        self.write(hm.CLUSTER_SECRET_PATH, '')
        secret = hm.get_or_create_cluster_secret()
        self.assertTrue(
            secret,
            'an empty secret file must be regenerated, not returned as ""')
        self.assertEqual(secret, self.read(hm.CLUSTER_SECRET_PATH).strip())
        self.assertEqual(secret, hm.get_or_create_cluster_secret(),
                         'the healed secret must then be stable')

    def test_existing_secret_is_preserved(self):
        self.write(hm.CLUSTER_SECRET_PATH, 'deadbeef\n')
        self.assertEqual('deadbeef', hm.get_or_create_cluster_secret())


if __name__ == '__main__':
    print(f"testing haproxy_manager from: {MODULE_DIR}", file=sys.stderr)
    unittest.main(verbosity=2)
