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
constants so the tests need no openssl to *create* material. openssl IS needed
to run them: the library's cert/key pairing check is mandatory (it is the only
layer that can reject a bundle of empty pem blocks), so without the binary
every publish is refused by design. The image ships openssl 3.x.

The acceptance bar for this file is a green run INSIDE the built image, as
root, which is where these scripts actually execute - not on a workstation.
Several failure modes are invisible outside the container (root ignores the
directory permissions one test used to rely on) and one was actively
destructive there; see _cleanup_tmp().
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import textwrap
import time
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

# A SECOND, unrelated but internally consistent pair. Needed by the
# concurrency test: two bundles that are each perfectly valid but whose keys
# differ, so a validator that reads the certificate from one and the key from
# the other reports a mismatch. Two bundles sharing key material - which is
# what PREVIOUS_BUNDLE and NEW_BUNDLE are - cannot detect that at all.
# openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
#         -subj /CN=second.example.com
TEST_CERT_2 = """\
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIUKQAAvrVkden7gIg2zYMLb6dO1c8wDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSc2Vjb25kLmV4YW1wbGUuY29tMB4XDTI2MDgwNjE2NTcz
NVoXDTM2MDgwMzE2NTczNVowHTEbMBkGA1UEAwwSc2Vjb25kLmV4YW1wbGUuY29t
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv2pfTOvN2zrZJ6d+biiD
VOczMqanuHPBCy2CnTBif+7VWf8AaywRzQ3ShfhmalVRNEFMn0MSO+GocmH71Ve1
nl89oGiJPmvX1lpncbgM692ddhP9ez4xUeNj+QAWp9VBZhInNuM4Pawv5BPngtpj
2MGXf3ZlBSli8Ng7jBo1fTMT3bh8GcE1rIPRvmUuQwFIt2eGnLR8jQd+xGelhAjG
nnXtlc+ebo4r2OjljNgvtdUknBZdpiZXmjdFzyClYTeMuEen2uwMpJNc0wLbRjcU
khVF3nw4jUnkOhWH3JYGAoWslJyEqZSANwt/eOHwXgyVuxg31bCl297iskW0IRZL
wQIDAQABo1MwUTAdBgNVHQ4EFgQU7HH8GacJzc2j9s2UJCPwykgrIckwHwYDVR0j
BBgwFoAU7HH8GacJzc2j9s2UJCPwykgrIckwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAQEAYE5jHX1dK091jVsFSZDdiw9AU5rrk8XpF1yuPmDisRnE
dJ4QQq3dzWXRnp0bzZnq7fdfiEz1m39zVixov7WFp24QhenD2n5K7/wew7RpXTnA
pAGBEdsGvBJ+3MgkRYklXCM9f9f4z21xXRNZ+BwBcM25D+gR4b+PRMQR6BhZx5R+
y2jQsoM68cFjRApFWgmji4pBjg/eOaZMBCfVTjP+npVyqG7UtV5EyYXwPgPa/rm2
FoP+eftzP6dszBEonkIVyyvkdscI4Wkr8hw3S0R/TP8l9lTnvN1HC3o7Es5VY53R
swNAXWBlgm0N7A96ISLtQjgvOfeMRTCSjxW9pm0wJA==
-----END CERTIFICATE-----
"""

TEST_KEY_2 = """\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/al9M683bOtkn
p35uKINU5zMypqe4c8ELLYKdMGJ/7tVZ/wBrLBHNDdKF+GZqVVE0QUyfQxI74ahy
YfvVV7WeXz2gaIk+a9fWWmdxuAzr3Z12E/17PjFR42P5ABan1UFmEic24zg9rC/k
E+eC2mPYwZd/dmUFKWLw2DuMGjV9MxPduHwZwTWsg9G+ZS5DAUi3Z4actHyNB37E
Z6WECMaede2Vz55ujivY6OWM2C+11SScFl2mJleaN0XPIKVhN4y4R6fa7Aykk1zT
AttGNxSSFUXefDiNSeQ6FYfclgYChayUnISplIA3C3944fBeDJW7GDfVsKXb3uKy
RbQhFkvBAgMBAAECggEABQLqy6eedRPt31sLOMFEDkzbZdFHOMpZeuqThsNmjo7z
t9diokgeD4ZQXimbEQqsZYDAtmFGdiEp86I9JQBk/4TUiqFhHrOADBe1jQAptjfs
iyIb51gIPnjZ1RBA5Al8zohy28T9h1+Z7+/OeCvcgLyVAixf/U9pU8D1El9cu9zv
4q4WJPB5Tgkq+YwcmeuT8LzsKoSDmPQjFVY9v+gz6hoVUVyP6gswnlFnKjNcmfZU
0CKP90sCAc5mKZv7RyGG920LDU4u2ggnQoK05GhXK8R3amJmoAF3i+xGeTRvNEKe
wDC7NinTG2WDVo6y/FCvFKs0+qqlKww1u39fq166rQKBgQDtjPjvkDkSYFcWFznn
sfsxN5R1cLpxdutLZhfvtpHIj5NkQbmOk0r3LbDAwU+UNVQ6F8jWQVHUsni9jAY6
3RNRF4ZabC51aqg/Ssj7d5mE4kj7y6Ch/nnSXIogRxLG4bWo2rtG1M2Dt3Ef08R4
6gjcp9ZmELyVx7H4yXFJGIaDdQKBgQDOSCHFK/ggZzzy4iC7DOq1lrbR+jyk95rh
F5EGzyAkgJ4uYc9TCPkUDxXjWL17r61/obfbW4znaV9fHEKpz3R54osDXln3oLea
BBWkJI3ANe8iNrGDE4FN9to4DdUMFsWX/WEiRyBPIqDy9DTyadblMLTNZjNPuLmg
ZJOB3tRZnQKBgQCjeglya9Eq2Uv1MuSxk2VnmHU9YOed4BXLHKZKXFz1JgFr1GNL
QAguFK536FDIkO62z9lxwR/8fRnkb7F13uBFRSg7oAlU2qKQc/nePI9UyJkrVxXj
hYn2f6K61c6ROZFXc7e/5gDMrXhXS9gA0iZpG8PLF6eAeB39NTwV7p/bZQKBgQCV
v5eEY58FJu0ABVhtcbsRiA+/70EHIRi2Pz1xC/vxg81RLoArb2AiR7FEEa+8kpQJ
C4VFIPjxJXWuvf1G+Os9cFAqadw1/95JWJ29QywEVSL8W2gSF57O0l0oRCJdXEql
Q7O4BppV2HWu6clmEZ+HUgxu77pgLWHUJi9PIExXoQKBgEq6rYBXmsSQermnPTOn
YFx7c2ns97hsjYIbs497+gPW4/xQWwsN76t60SWqjXV4DHJCpi5Tnjo2fk5/OzK+
HfshC9CKFDk8T0KGQWwaPwqP/OYbqOA88IlJ7xbPdSuJkjefHCtVVEtao6+HNgzm
lniLtDMpU0MLPgB98ClQ4HDA
-----END PRIVATE KEY-----
"""

# The bundle already on disk when a run starts. Same key material, plus a
# trailing marker so "the live file was replaced" and "the old file was
# archived" can be told apart byte-for-byte.
PREVIOUS_BUNDLE = TEST_CERT + TEST_KEY + '# previous bundle\n'
NEW_BUNDLE = TEST_CERT + TEST_KEY
OTHER_BUNDLE = TEST_CERT_2 + TEST_KEY_2

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
        # Without the library every "the library rejects X" assertion in this
        # file can be satisfied by bash exiting 127, so make its absence a
        # failure of every test rather than a silent pass of several.
        self.assertTrue(os.path.isfile(LIB),
                        f'{LIB} is missing - nothing below tests anything')

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
        # A test may have chmod 000'd a fixture file, which would stop rmtree.
        #
        # SYMLINKS ARE SKIPPED, and that is not a nicety. os.chmod() FOLLOWS
        # symlinks, and the openssl-availability tests below build a stripped
        # PATH directory out of symlinks to real system binaries (/usr/bin/cat,
        # /usr/bin/chmod, ...). Walking those with chmod 0600 as root - which is
        # how this container runs - stripped the exec bit from a dozen core
        # binaries of the machine running the tests, chmod itself included, so
        # it could not even be undone from inside the container: every later
        # test failed with "/usr/bin/grep: Permission denied" and certificate
        # publishing stayed dead until the container was recreated. It never
        # showed up on a workstation because an unprivileged chmod of a
        # root-owned file fails EPERM and was swallowed by `except OSError`.
        # This file ships in the image (COPY scripts /haproxy/scripts), so
        # running it in place is a thing an operator will do.
        for root, dirs, files in os.walk(self.tmp):
            for name in files:
                path = os.path.join(root, name)
                if os.path.islink(path):
                    continue
                try:
                    os.chmod(path, 0o600)
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

    def assert_rejected(self, result, because):
        """The library refused, FOR THE STATED REASON.

        `assertNotEqual(rc, 0)` on its own proves nothing about this library.
        Delete cert-publish-lib.sh and `. "$1"` fails, cert_bundle_valid is
        never defined, bash exits 127 - and a bare rc!=0 assertion passes. Four
        tests in TestCertPublishLibrary were doing exactly that; they were
        pinning "some bash pipeline failed", not "the bundle was rejected".
        """
        output = result.stdout + result.stderr
        self.assertNotIn('command not found', output,
                         'the shell could not find the function under test - '
                         'this asserts nothing about the library')
        self.assertNotEqual(127, result.returncode,
                            f'exit 127 means "no such command", not "rejected": {output}')
        self.assertNotEqual(0, result.returncode,
                            f'expected a rejection, got success: {output}')
        self.assertIn(because, output,
                      f'rejected, but not for the expected reason '
                      f'({because!r} not in output): {output}')


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
        # This used to assert returncode == 0 with the comment "a per-domain
        # failure should not change the exit code", codifying the script's
        # `exit 0`. That is wrong and it is the dangerous kind of wrong: a host
        # where EVERY domain fails to publish looked, to cron and to
        # host-renew-certificates.sh (which branches on this exit code),
        # exactly like a clean run. Nothing would notice until the certificates
        # expired. Continuing past a failed domain so the others still get
        # published is right; reporting success afterwards is not.
        self.assertNotEqual(result.returncode, 0,
                            'a domain that failed to publish must be reported '
                            'in the exit code, not just in the log')

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
            self.skipTest('openssl CLI not available: without it every publish '
                          'is refused, so this test could not tell a pairing '
                          'rejection from a missing-checker rejection')
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

    def call(self, snippet, *args, **env_overrides):
        return subprocess.run(
            ['bash', '-c', '. "$1"; shift; ' + snippet, '_', LIB, *args],
            env=self.env(**env_overrides), capture_output=True, text=True)

    def test_valid_bundle_accepted(self):
        path = write(os.path.join(self.tmp, 'ok.pem'), NEW_BUNDLE)
        self.assertEqual(self.call('cert_bundle_valid "$1"', path).returncode, 0)

    def test_empty_and_missing_bundles_rejected(self):
        empty = write(os.path.join(self.tmp, 'empty.pem'), '')
        self.assert_rejected(self.call('cert_bundle_valid "$1"', empty),
                             'is empty')
        missing = os.path.join(self.tmp, 'nope.pem')
        self.assert_rejected(self.call('cert_bundle_valid "$1"', missing),
                             'does not exist')

    def test_key_without_end_marker_rejected(self):
        truncated = write(os.path.join(self.tmp, 'cut.pem'),
                          TEST_CERT + '-----BEGIN PRIVATE KEY-----\nMIIEvAIB\n')
        self.assert_rejected(self.call('cert_bundle_valid "$1"', truncated),
                             'unterminated private key block')

    def test_empty_pem_blocks_are_rejected(self):
        """Why the pairing check is mandatory rather than best-effort.

        Every structural check in the library passes on this file: a complete
        CERTIFICATE block and a complete PRIVATE KEY block, both with nothing
        between BEGIN and END. Only openssl can tell it is not a certificate.
        """
        hollow = write(os.path.join(self.tmp, 'hollow.pem'),
                       '-----BEGIN CERTIFICATE-----\n'
                       '-----END CERTIFICATE-----\n'
                       '-----BEGIN PRIVATE KEY-----\n'
                       '-----END PRIVATE KEY-----\n')
        self.assert_rejected(self.call('cert_bundle_valid "$1"', hollow),
                             'openssl could not read the certificate')

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
        """No silent fallback to writing straight into the certs dir.

        The failure is injected with a stub `mv` that refuses, rather than by
        chmod 0500 on the certs dir: the container these scripts run in is
        root, root ignores directory permissions, so the chmod version skipped
        itself exactly where it matters and only ever ran on a workstation.
        """
        self.seed_previous_bundle()
        before = read(self.live_pem)
        write(os.path.join(self.bindir, 'mv'),
              "#!/bin/sh\n"
              "echo \"mv: cannot move '$2': Permission denied\" >&2\n"
              "exit 1\n", 0o755)
        self.addCleanup(os.unlink, os.path.join(self.bindir, 'mv'))

        result = self.call('cert_publish "$1" "$2" "$3"',
                           self.src_cert, self.src_key, self.live_pem)

        self.assert_rejected(result, 'NOT falling back to a direct write')
        self.assertEqual(read(self.live_pem), before,
                         'the live pem was damaged by a failed rename')
        self.assert_no_staging_leftovers()

    def test_published_pem_keeps_the_mode_of_the_file_it_replaces(self):
        """A write-safety fix must not silently re-permission private keys.

        Both directions matter: mktemp stages at 0600, so without the explicit
        chmod every publish would tighten a 0644 bundle; and the mode must not
        be copied from a symlink (see the next test).
        """
        for mode in (0o644, 0o640, 0o600):
            with self.subTest(oct(mode)):
                write(self.live_pem, PREVIOUS_BUNDLE, mode)
                result = self.call('cert_publish "$1" "$2" "$3"',
                                   self.src_cert, self.src_key, self.live_pem)
                self.assertEqual(result.returncode, 0,
                                 result.stdout + result.stderr)
                self.assertEqual(read(self.live_pem), NEW_BUNDLE)
                self.assertEqual(
                    stat.S_IMODE(os.stat(self.live_pem).st_mode), mode,
                    'publishing changed who can read the private key')

    def test_symlinked_live_pem_does_not_become_world_writable(self):
        """`stat -c %a` on a symlink reports 0777 - the LINK's mode, not a
        permission. Copying that onto the staged bundle put a world-writable
        private key in the directory HAProxy serves from. -L is what makes the
        preserved mode the mode of the file an operator actually chose.
        """
        target = write(os.path.join(self.tmp, 'real-bundle.pem'),
                       PREVIOUS_BUNDLE, 0o640)
        os.symlink(target, self.live_pem)

        result = self.call('cert_publish "$1" "$2" "$3"',
                           self.src_cert, self.src_key, self.live_pem)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        mode = stat.S_IMODE(os.stat(self.live_pem).st_mode)
        self.assertEqual(
            0, mode & 0o022,
            f'published bundle is group/world writable ({oct(mode)}) - the '
            f'symlink mode was copied onto a real private key')
        self.assertEqual(0o640, mode)

    def test_publish_refuses_when_staging_is_on_another_filesystem(self):
        """The header used to claim a cross-device mv "fails loudly and leaves
        the live pem alone". GNU mv does no such thing: across filesystems it
        copies, so it truncates and writes the DESTINATION first and only then
        discovers it cannot finish (ENOSPC being the realistic case) - the very
        truncation this library exists to prevent. Both directories are
        env-overridable, so the device numbers have to be checked up front.
        """
        staging = os.path.join(self.a_dir_on_another_filesystem(),
                               'cert-staging')
        self.seed_previous_bundle()
        before = read(self.live_pem)

        result = self.call('cert_publish "$1" "$2" "$3"',
                           self.src_cert, self.src_key, self.live_pem,
                           CERT_STAGING_DIR=staging)

        self.assert_rejected(result, 'different filesystems')
        self.assertEqual(read(self.live_pem), before,
                         'the live pem was disturbed by a refused publish')
        self.assert_certs_dir_is_clean()

    def test_stale_python_side_staging_temps_are_reaped(self):
        """The staging dir has two writers.

        write_config_atomically() on the Python side stages as
        `<name>.<random>.tmp` (tempfile.mkstemp(prefix=name + '.',
        suffix='.tmp')). The reaper matched only mktemp's `*.??????` shape, so
        every temp leaked by a SIGKILL on the Python side stayed there forever.
        """
        os.makedirs(self.staging_dir, exist_ok=True)
        stale_py = write(os.path.join(self.staging_dir,
                                      DOMAIN + '.pem.ab12cd34.tmp'), 'stale\n')
        stale_sh = write(os.path.join(self.staging_dir,
                                      DOMAIN + '.pem.AbCdEf'), 'stale\n')
        fresh = write(os.path.join(self.staging_dir,
                                   'recent.pem.zz99yy.tmp'), 'fresh\n')
        old = time.time() - 3 * 24 * 3600
        for path in (stale_py, stale_sh):
            os.utime(path, (old, old))

        result = self.call('cert_publish "$1" "$2" "$3"',
                           self.src_cert, self.src_key, self.live_pem)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        self.assertFalse(os.path.exists(stale_py),
                         'a stale Python-side staging temp was never reaped')
        self.assertFalse(os.path.exists(stale_sh),
                         'a stale shell-side staging temp was never reaped')
        self.assertTrue(os.path.exists(fresh),
                        'the reaper deleted a temp a concurrent publisher may '
                        'still be writing')

    def test_validation_of_a_live_pem_being_republished_is_not_spurious(self):
        """cert_bundle_valid must judge ONE snapshot of the file.

        cert_publish() calls cert_bundle_valid() on the LIVE pem (step (e), to
        decide whether it is worth backing up) while another publisher may be
        renaming a new bundle over it. The function used to open the file six
        times, so `openssl x509` could read the outgoing bundle and `openssl
        pkey` the incoming one - and report "private key does not match the
        certificate" about two files that were each perfectly fine. That ERROR
        goes into the log monitor-errors.sh watches, which makes it a page.

        The two bundles alternated below are each internally valid but carry
        DIFFERENT key material. That matters: NEW_BUNDLE and PREVIOUS_BUNDLE
        share a cert and a key, so alternating those two could never produce a
        mismatch no matter how badly the reads were interleaved - the test
        would model a world in which the bug cannot happen and pass forever.
        """
        write(self.live_pem, NEW_BUNDLE)
        a = write(os.path.join(self.tmp, 'churn-a.pem'), NEW_BUNDLE)
        b = write(os.path.join(self.tmp, 'churn-b.pem'), OTHER_BUNDLE)

        # A publisher renaming over the live pem as fast as it can. Staged
        # outside the certs dir, then renamed, exactly like cert_publish().
        churn = subprocess.Popen(
            ['bash', '-c',
             'end=$((SECONDS+8)); s="$4"; while [ $SECONDS -lt $end ]; do '
             '  cp "$1" "$s"; mv -f "$s" "$2"; '
             '  cp "$3" "$s"; mv -f "$s" "$2"; '
             'done', '_', a, self.live_pem, b,
             os.path.join(self.tmp, 'churn-staged.pem')],
            env=self.env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def _stop():
            churn.kill()
            churn.wait()
        self.addCleanup(_stop)

        result = subprocess.run(
            ['bash', '-c',
             '. "$1"; for i in $(seq 1 200); do cert_bundle_valid "$2" || exit 1; done',
             '_', LIB, self.live_pem],
            env=self.env(), capture_output=True, text=True, timeout=120)
        _stop()

        output = result.stdout + result.stderr
        self.assertNotIn('does not match the certificate', output,
                         'two valid bundles were reported as a mismatched pair '
                         'because the checks read different files')
        self.assertEqual(0, result.returncode,
                         f'a concurrent republish made validation fail: {output}')

    def a_dir_on_another_filesystem(self):
        certs_dev = os.stat(self.certs_dir).st_dev
        for candidate in ('/dev/shm', '/run', '/var/tmp', '/tmp', '/'):
            try:
                if (os.path.isdir(candidate)
                        and os.access(candidate, os.W_OK)
                        and os.stat(candidate).st_dev != certs_dev):
                    path = tempfile.mkdtemp(prefix='cert-xdev-', dir=candidate)
                    self.addCleanup(shutil.rmtree, path, True)
                    return path
            except OSError:
                continue
        self.skipTest('no writable directory on a second filesystem available')

    def test_haproxy_config_ok_follows_the_validator(self):
        self.assertEqual(self.call('haproxy_config_ok').returncode, 0)
        write(self.haproxy_cfg, GOOD_HAPROXY_CFG + BROKEN_TOKEN + '\n')
        self.assertNotEqual(self.call('haproxy_config_ok').returncode, 0)

    def _openssl_free_path(self, name):
        """A PATH directory with the library's tools but no openssl.

        Symlinks, so this directory must never be walked with a chmod that
        follows them - see _cleanup_tmp().
        """
        fake_path = os.path.join(self.tmp, name)
        os.makedirs(fake_path)
        for tool in ('cat', 'grep', 'mktemp', 'mv', 'cp', 'rm', 'mkdir',
                     'basename', 'dirname', 'find', 'date', 'chmod', 'stat'):
            real = shutil.which(tool)
            if real:
                os.symlink(real, os.path.join(fake_path, tool))
        return fake_path

    def test_missing_openssl_is_a_hard_failure(self):
        """The pairing check is MANDATORY: no openssl, no publication.

        This used to assert the opposite - that a missing openssl warns and
        publishes anyway - justified by "the image does not necessarily install
        the openssl CLI". The image does: openssl 3.x arrives with
        ca-certificates, which certbot needs, and generate_self_signed_cert()
        already runs `openssl req` with check=True at first-run setup. So the
        fail-open never actually fired, and structural checks alone accept a
        bundle of empty pem blocks (see test_empty_pem_blocks_are_rejected).
        """
        fake_path = self._openssl_free_path('no-openssl-bin')
        path = write(os.path.join(self.tmp, 'ok.pem'), NEW_BUNDLE)

        # bash by absolute path: the stripped PATH cannot resolve it.
        result = subprocess.run(
            [shutil.which('bash'), '-c', '. "$1"; cert_bundle_valid "$2"',
             '_', LIB, path],
            env=self.env(PATH=fake_path), capture_output=True, text=True)

        self.assert_rejected(result, 'openssl binary not found')
        self.assertIn('REFUSING', result.stdout + result.stderr,
                      'a broken image must be reported as a broken image')

    def test_missing_openssl_stops_a_publish_rather_than_weakening_it(self):
        """cert_publish must inherit the refusal, and not touch the live pem."""
        fake_path = self._openssl_free_path('no-openssl-bin2')
        self.seed_previous_bundle()
        before = read(self.live_pem)

        result = subprocess.run(
            [shutil.which('bash'), '-c',
             '. "$1"; cert_publish "$2" "$3" "$4"',
             '_', LIB, self.src_cert, self.src_key, self.live_pem],
            env=self.env(PATH=fake_path), capture_output=True, text=True)

        self.assert_rejected(result, 'openssl binary not found')
        self.assertEqual(read(self.live_pem), before,
                         'the live pem was disturbed by a refused publish')
        self.assert_certs_dir_is_clean()
        self.assert_no_staging_leftovers()


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
