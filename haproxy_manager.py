import sqlite3
import os
from flask import Flask, request, jsonify, render_template, send_file
from pathlib import Path
import subprocess
import jinja2
import socket
import psutil
import functools
import logging
from datetime import datetime, timedelta
import json
import ipaddress
import shutil
import stat
import tempfile
import threading
import time
import re
import fcntl

# ---------------------------------------------------------------------------
# Bounded subprocess execution (incident 2026-07-07)
# ---------------------------------------------------------------------------
# Every external command this manager runs — certbot ACME issuance/renewal,
# `socat` reloads over the haproxy admin socket, `haproxy -c` validation — is a
# potential hang. The management API runs under gunicorn gthread workers, and a
# subprocess.run() with NO timeout blocks its worker thread forever if the
# command stalls (e.g. an ACME/upstream that stops responding mid-read).
# gunicorn's --timeout does not rescue this: for gthread it only kills a worker
# whose *main* thread stops heart-beating, but the main thread keeps polling
# while pool threads are wedged. Enough stalled calls exhaust the 4-thread pool
# and the whole API stops responding — "healthy" health-check, every request
# 30s-timeouts — which is exactly what stalled WHP site updates on 2026-07-07.
#
# Fix: give EVERY subprocess.run() a default timeout unless the caller passes
# one explicitly. On expiry Python kills the child and raises
# subprocess.TimeoutExpired (a subclass of Exception); the existing per-endpoint
# try/except turns that into a clean error AND releases the worker thread.
# Bounding by default (instead of editing ~30 call sites) means no site can be
# missed and any future call is protected automatically.
DEFAULT_SUBPROCESS_TIMEOUT = int(os.environ.get('HAPROXY_MGR_SUBPROCESS_TIMEOUT', '180'))
_unbounded_subprocess_run = subprocess.run


def _bounded_subprocess_run(*args, **kwargs):
    if kwargs.get('timeout') is None:
        kwargs['timeout'] = DEFAULT_SUBPROCESS_TIMEOUT
    return _unbounded_subprocess_run(*args, **kwargs)


subprocess.run = _bounded_subprocess_run

app = Flask(__name__)

# Default page server (port 8080) — served to HAProxy clients whose request hit
# an unconfigured domain OR whose IP is blocked. Defined at module level so
# gunicorn can import it from start-up.sh; previously this was created inside
# the __main__ block, which prevented out-of-process WSGI servers from reaching
# it. Routes accept ALL HTTP methods because HAProxy proxies the original
# request verb unchanged — a POST to a blocked domain would otherwise 405,
# which is just log noise.
default_app = Flask('haproxy_default')
default_app.template_folder = 'templates'

_ANY_METHOD = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']


@default_app.route('/', methods=_ANY_METHOD)
def default_page():
    """Serve the default page for unmatched domains."""
    return render_template(
        'default_page.html',
        page_title=os.environ.get('HAPROXY_DEFAULT_PAGE_TITLE', 'Site Not Configured'),
        main_message=os.environ.get(
            'HAPROXY_DEFAULT_MAIN_MESSAGE',
            'This domain has not been configured yet. Please contact your '
            'system administrator to set up this website.'
        ),
        secondary_message=os.environ.get(
            'HAPROXY_DEFAULT_SECONDARY_MESSAGE',
            'If you believe this is an error, please check the domain name '
            'and try again.'
        ),
    )


@default_app.route('/blocked-ip', methods=_ANY_METHOD)
def blocked_ip_page():
    """Serve the blocked IP page for blocked clients (HTTP 403)."""
    return render_template('blocked_ip_page.html'), 403


@default_app.route('/suspended', methods=_ANY_METHOD)
def suspended_page():
    """Serve the suspended-site page (HTTP 503) for hosts listed in
    /etc/haproxy/suspended_domains.list. Routed here via the frontend
    path-rewrite ACL when HAPROXY_SUSPENSION_ENABLED=true."""
    return render_template('suspended_page.html'), 503


# Configuration
DB_FILE = '/etc/haproxy/haproxy_config.db'
TEMPLATE_DIR = Path('templates')
HAPROXY_CONFIG_PATH = '/etc/haproxy/haproxy.cfg'
HAPROXY_BACKUP_PATH = '/etc/haproxy/haproxy.cfg.backup'
BLOCKED_IPS_MAP_PATH = '/etc/haproxy/blocked_ips.map'
BLOCKED_IPS_MAP_BACKUP_PATH = '/etc/haproxy/blocked_ips.map.backup'
# Coraza SPOE engine file. `haproxy -c` parses this too (the frontend's
# `filter spoe engine coraza config <path>` line points at it), so it is part
# of the same restorable config set as haproxy.cfg — rolling back haproxy.cfg
# while leaving a broken coraza-spoe.cfg behind still fails validation.
CORAZA_SPOE_CONFIG_PATH = '/etc/haproxy/coraza-spoe.cfg'
CORAZA_SPOE_BACKUP_PATH = '/etc/haproxy/coraza-spoe.cfg.backup'
HAPROXY_SOCKET_PATH = '/var/run/haproxy.sock'
# HAProxy loads this path as a DIRECTORY (`bind ... ssl crt /etc/haproxy/certs`),
# which means it tries to load EVERY file it finds in here. Nothing but final,
# validated `<name>.pem` bundles may ever exist in this directory - no temp
# files, no `.backup` copies. Staging and backups live in the sibling
# directories below, on the same filesystem so os.replace() stays atomic.
# See publish_pem_bundle().
SSL_CERTS_DIR = '/etc/haproxy/certs'
# Stable per-host secret for QUIC Retry/address-validation tokens. Lives in the
# /etc/haproxy named volume so it survives container recreates; self-healed on
# first config render. See get_or_create_cluster_secret().
CLUSTER_SECRET_PATH = '/etc/haproxy/cluster-secret'
API_KEY = os.environ.get('HAPROXY_API_KEY')  # Optional API key for authentication

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/haproxy-manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def require_api_key(f):
    """Decorator to require API key authentication if API_KEY is set"""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if API_KEY:
            auth_header = request.headers.get('Authorization')
            if not auth_header or auth_header != f'Bearer {API_KEY}':
                return jsonify({'error': 'Unauthorized - Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

def log_operation(operation, success=True, error_message=None):
    """Log operations for monitoring and alerting"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'operation': operation,
        'success': success,
        'error': error_message
    }
    
    if success:
        logger.info(f"Operation {operation} completed successfully")
    else:
        logger.error(f"Operation {operation} failed: {error_message}")
        # Here you could add additional alerting (email, webhook, etc.)
        # For now, we'll just log to a dedicated error log
        with open('/var/log/haproxy-manager-errors.log', 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    
    return log_entry

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Create domains table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY,
                domain TEXT UNIQUE NOT NULL,
                ssl_enabled BOOLEAN DEFAULT 0,
                ssl_cert_path TEXT,
                template_override TEXT
            )
        ''')

        # Create backends table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backends (
                id INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                domain_id INTEGER,
                settings TEXT,
                FOREIGN KEY (domain_id) REFERENCES domains (id)
            )
        ''')

        # Create backend_servers table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backend_servers (
                id INTEGER PRIMARY KEY,
                backend_id INTEGER,
                server_name TEXT NOT NULL,
                server_address TEXT NOT NULL,
                server_port INTEGER NOT NULL,
                server_options TEXT,
                FOREIGN KEY (backend_id) REFERENCES backends (id)
            )
        ''')

        # Create blocked_ips table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY,
                ip_address TEXT UNIQUE NOT NULL,
                reason TEXT,
                blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blocked_by TEXT
            )
        ''')
        # Migration: add is_wildcard column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE domains ADD COLUMN is_wildcard BOOLEAN DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # Column already exists

        conn.commit()

def validate_ip_address(ip_string):
    """Validate if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip_string)
        return True
    except ValueError:
        return False

# Certbot uses fasteners (fcntl-based) to serialize concurrent invocations.
# When a previous certbot run is SIGKILLed mid-execution (container restart,
# OOM, manual kill), the kernel releases the fcntl lock automatically — but
# the LOCK FILE on disk persists. Subsequent runs sometimes report
# "Another instance of Certbot is already running" anyway, blocking SSL
# issuance until someone manually clears the files.
#
# Our hung-process scenario (observed 2026-05-09 during the bundling rollout):
# certbot from a previous attempt sat in defunct state holding the lock fd.
# Once the process eventually exited, the locks were physically removable but
# the symptoms persisted across multiple subsequent attempts.
#
# This helper probes each known lock path with fcntl.LOCK_NB. If we get the
# lock, no real process holds it and the file is stale — we delete it. If we
# DON'T get the lock, a real certbot is running and we leave it alone (so we
# never accidentally trigger concurrent certbot runs).
CERTBOT_LOCK_PATHS = (
    '/etc/letsencrypt/.certbot.lock',
    '/var/lib/letsencrypt/.certbot.lock',
    '/var/log/letsencrypt/.certbot.lock',
)

def clear_stale_certbot_locks():
    """Remove stale certbot lock files. Safe to call before any ACME run.
    Returns {'cleared': [paths...], 'held': [paths...]} for logging.
    """
    cleared, held = [], []
    for path in CERTBOT_LOCK_PATHS:
        if not os.path.exists(path):
            continue
        try:
            fd = os.open(path, os.O_RDWR)
        except FileNotFoundError:
            continue
        except Exception as e:
            held.append(f'{path} (open: {e})')
            continue
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # A real process holds it; do not touch.
            os.close(fd)
            held.append(path)
            continue
        try:
            # We hold the lock now. Release before unlinking so the lock
            # state is clean if someone races us.
            fcntl.flock(fd, fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            os.close(fd)
        except Exception:
            pass
        try:
            os.remove(path)
            cleared.append(path)
        except FileNotFoundError:
            cleared.append(path)
        except Exception as e:
            held.append(f'{path} (unlink: {e})')
    return {'cleared': cleared, 'held': held}

def find_certbot_live_dir(base_domain):
    """Find the most recent certbot live directory for a domain.
    Certbot creates -NNNN suffixed dirs for repeated requests."""
    live_dir = '/etc/letsencrypt/live'
    if not os.path.isdir(live_dir):
        return None
    candidates = []
    for entry in os.listdir(live_dir):
        if entry == base_domain or re.match(rf'^{re.escape(base_domain)}-\d{{4}}$', entry):
            full_path = os.path.join(live_dir, entry)
            fullchain = os.path.join(full_path, 'fullchain.pem')
            if os.path.exists(fullchain):
                candidates.append((full_path, os.path.getmtime(fullchain)))
    if not candidates:
        return None
    # Return the most recently modified
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]

# ---------------------------------------------------------------------------
# Certificate publishing
# ---------------------------------------------------------------------------
# Until 2026-08 every code path that refreshed a combined PEM did this:
#
#     with open(combined_path, 'w') as combined:            # TRUNCATES the file
#         subprocess.run(['cat', cert, key], stdout=combined)   # rc ignored
#
# `combined_path` is the live bundle HAProxy is serving. open(...,'w') empties
# it BEFORE a single byte of source material has been read, and the `cat` exit
# status was never checked. Any failure in between - source unreadable, disk
# full, container killed, certbot lineage half-written - left a truncated or
# key-less PEM in place. HAProxy loads /etc/haproxy/certs as a directory, so one
# unusable file there fails the whole `bind ... ssl crt` and takes down HTTPS
# for every site on the host. Unlike a bad haproxy.cfg this is NOT recoverable
# by config rollback, and re-issuing hits Let's Encrypt rate limits.
#
# Everything below exists to make publishing a bundle all-or-nothing:
#   assemble in a staging dir -> validate -> back up the old one -> os.replace()
# The live file is only ever swapped for a complete, validated replacement.


class CertificatePublishError(Exception):
    """A certificate bundle could not be published. The live PEM is untouched."""


def _cert_sibling_dir(name):
    """A directory next to SSL_CERTS_DIR (NOT inside it).

    HAProxy loads SSL_CERTS_DIR as a crt directory and tries to load every file
    in it, so staging and backup copies must live outside. Siblings share the
    /etc/haproxy filesystem, which is what keeps os.replace() atomic.

    Derived at call time so tests that repoint SSL_CERTS_DIR get matching
    staging/backup dirs, the same pattern as _config_backup_pairs().
    """
    parent = os.path.dirname(SSL_CERTS_DIR.rstrip('/')) or '/'
    return os.path.join(parent, name)


def cert_staging_dir():
    """Directory where bundles are assembled and validated before publishing."""
    return _cert_sibling_dir('cert-staging')


def cert_backup_dir():
    """Directory holding the previous copy of each published bundle.

    Mirrors the config backup on the parent branch (one `.backup` alongside
    haproxy.cfg): one copy per cert, overwritten on each successful publish, so
    an operator always has a manual path back to the bundle that was being
    served before the last change.
    """
    return _cert_sibling_dir('cert-backups')


# ENCRYPTED PRIVATE KEY is deliberately absent: HAProxy cannot use a
# passphrase-protected key from a crt file, so a bundle containing one is not
# publishable, and the structural layer is the only layer that names the
# problem ("no complete private key block") rather than reporting it as an
# unreadable key.
_PEM_KEY_LABELS = ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY')


def _pem_labels(text):
    """Labels of well-formed PEM blocks in text, in order.

    A block counts only if its BEGIN line is followed by the matching END line,
    so a bundle truncated in the middle of a block yields no label for it -
    which is exactly the corruption we are guarding against.
    """
    labels = []
    open_label = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('-----BEGIN ') and line.endswith('-----'):
            open_label = line[len('-----BEGIN '):-len('-----')].strip()
        elif line.startswith('-----END ') and line.endswith('-----'):
            end_label = line[len('-----END '):-len('-----')].strip()
            if open_label is not None and end_label == open_label:
                labels.append(end_label)
            open_label = None
    return labels


def validate_pem_structure(text):
    """Structural check on an assembled bundle. Returns (ok, message).

    Pure Python and therefore ALWAYS available - it can never be skipped for
    lack of a tool. It catches every failure mode the truncation bug produced:
    empty file, certificate without a key, key without a certificate, and a
    block cut off mid-write.

    It is NOT sufficient on its own, which is why _openssl_pairing_status() is
    mandatory rather than best-effort: a bundle of EMPTY pem blocks (a BEGIN
    line immediately followed by its END line, no base64 between them) passes
    every check here and is rejected only by openssl.
    """
    if not text.strip():
        return False, 'bundle is empty'
    labels = _pem_labels(text)
    if not labels:
        return False, 'bundle contains no complete PEM block (truncated?)'
    if 'CERTIFICATE' not in labels:
        return False, 'bundle contains no complete CERTIFICATE block'
    if not any(label in _PEM_KEY_LABELS for label in labels):
        return False, 'bundle contains no complete private key block'
    return True, None


def _openssl_pairing_status(path):
    """Does the private key in `path` match the leaf certificate in `path`?

    Returns (status, message) with status 'valid' | 'invalid' | 'unavailable'.

    `openssl x509` reads the FIRST certificate in the file (our bundles are
    fullchain-then-key, so that is the leaf) and `openssl pkey` scans past the
    certificate blocks to the first private key, so both run against the
    assembled bundle directly. Comparing the two public keys proves the pair.

    'unavailable' means the openssl BINARY is absent - a verdict about our
    tooling, not about the bundle. validate_pem_bundle() treats it as a HARD
    FAILURE.

    That is a deliberate reversal. This docstring used to say "the Dockerfile
    installs haproxy, certbot, socat and curl but not the openssl CLI, so this
    is a real possibility", and callers accepted the bundle on the structural
    checks alone. The premise is false: openssl 3.x IS in the image, as a
    dependency of ca-certificates (which certbot requires), and
    generate_self_signed_cert() below already runs `openssl req` with
    check=True during first-run setup - so no container has ever reached a
    publish without it. The 'unavailable' branch never fired, which means the
    pairing check has in fact always run, and THAT is what made the fail-open
    harmless - not the stated reasoning. Structural validation on its own is
    weak: a bundle of empty pem blocks passes validate_pem_structure() and is
    caught only here.

    So an absent openssl now means the image is broken, and we say so and stop
    instead of quietly downgrading to the weaker check. The cost is that a
    hypothetical openssl-less image stops publishing renewals - but it does so
    immediately and loudly, in the monitored error log, at the first renewal,
    rather than 90 days later; and publishing an unverified bundle can take the
    whole :443 bind, i.e. every site on the host, down at the next reload.

    There is no python `cryptography` fallback on purpose: this process runs on
    /usr/local/bin/python3 (the base image's 3.12), where cryptography is not
    importable. It is installed for Debian's /usr/bin/python3 as a certbot
    dependency, and reaching for that interpreter would be a second unverified
    premise of exactly the kind this comment is correcting.
    """
    try:
        cert_pub = subprocess.run(
            ['openssl', 'x509', '-in', path, '-noout', '-pubkey'],
            capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return 'unavailable', 'openssl binary not found'
    except Exception as e:
        return 'unavailable', f'could not run openssl: {e}'
    if cert_pub.returncode != 0:
        return 'invalid', ('leaf certificate is unreadable: '
                           f'{(cert_pub.stderr or "").strip()[:200]}')
    try:
        # -passin pass: plus a closed stdin so an (unexpected) encrypted key
        # fails fast instead of blocking on a passphrase prompt.
        key_pub = subprocess.run(
            ['openssl', 'pkey', '-in', path, '-pubout', '-passin', 'pass:'],
            capture_output=True, text=True, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return 'unavailable', 'openssl binary not found'
    except Exception as e:
        return 'unavailable', f'could not run openssl: {e}'
    if key_pub.returncode != 0:
        return 'invalid', ('private key is unreadable: '
                           f'{(key_pub.stderr or "").strip()[:200]}')
    if cert_pub.stdout.strip() != key_pub.stdout.strip():
        return 'invalid', 'private key does not match the leaf certificate'
    return 'valid', None


def validate_pem_bundle(path):
    """Validate a bundle file on disk. Returns (ok, message).

    Structural validation AND the cryptographic pairing check, both mandatory -
    see _openssl_pairing_status() for why a missing openssl is a failure rather
    than a downgrade to structure-only.
    """
    try:
        with open(path, 'r') as fh:
            text = fh.read()
    except (OSError, UnicodeDecodeError) as e:
        # UnicodeDecodeError, not just OSError: a bundle corrupted into binary
        # is unreadable as text but reads perfectly well as bytes, so `except
        # OSError` let the decode error escape as an unhandled traceback.
        return False, f'cannot read assembled bundle: {e}'

    ok, msg = validate_pem_structure(text)
    if not ok:
        return False, msg

    status, pair_msg = _openssl_pairing_status(path)
    if status == 'invalid':
        return False, pair_msg
    if status == 'unavailable':
        logger.error(
            "Certificate key/leaf pairing check could not run for %s (%s) - "
            "REFUSING to publish. openssl is required; structural validation "
            "alone cannot tell a real bundle from empty pem blocks.",
            path, pair_msg)
        return False, (f'cert/key pairing check unavailable ({pair_msg}); '
                       'refusing to publish on structural checks alone')
    return True, None


def backup_existing_pem(dest_path):
    """Copy the currently published bundle aside before it is replaced.

    Only a bundle that still validates is promoted to backup: overwriting a
    good backup with an already-corrupt live file would turn "restore the
    backup" into "restore different garbage". Same require_valid reasoning as
    create_backup() for haproxy.cfg.

    Never fatal - failing to take a backup must not stop us replacing a cert
    with a validated one - but always logged.
    """
    if not os.path.exists(dest_path):
        return None
    try:
        with open(dest_path, 'r') as fh:
            ok, msg = validate_pem_structure(fh.read())
    except (OSError, UnicodeDecodeError) as e:
        # UnicodeDecodeError, not just OSError. A live pem corrupted into
        # BINARY (the exact state a republish is meant to heal) raises
        # UnicodeDecodeError here, and with only OSError caught it escaped all
        # the way out of publish_pem_bundle() - so the one operation that would
        # have put a working certificate back blew up on the way to taking a
        # backup of the broken one. The shell half recovers from this fine;
        # this is the only reason the Python half did not.
        ok, msg = False, str(e)
    backup_path = os.path.join(cert_backup_dir(), os.path.basename(dest_path))
    if not ok:
        logger.warning(
            "Not backing up %s before replacing it: the file on disk is not a "
            "valid bundle (%s). Keeping any previous backup at %s.",
            dest_path, msg, backup_path)
        return None
    try:
        os.makedirs(cert_backup_dir(), exist_ok=True)
        shutil.copy2(dest_path, backup_path)
        return backup_path
    except Exception as e:
        logger.error("Failed to back up %s to %s: %s",
                     dest_path, backup_path, e)
        return None


def publish_pem_bundle(dest_path, source_paths):
    """Publish cert+key as a combined PEM at dest_path, atomically.

    source_paths are concatenated in order (fullchain first, then privkey) into
    a staging file OUTSIDE the crt directory, validated there, and only then
    moved into place with os.replace(). If anything fails, the exception is
    raised and dest_path still holds the previous, working bundle - the live
    PEM is never opened for writing at any point.

    Returns the path of the backup taken (or None). Raises
    CertificatePublishError on any failure.
    """
    for src in source_paths:
        if not os.path.exists(src):
            raise CertificatePublishError(
                f'source certificate material missing: {src}')

    parts = []
    for src in source_paths:
        try:
            with open(src, 'r') as fh:
                data = fh.read()
        except (OSError, UnicodeDecodeError) as e:
            # Binary-corrupt source material must be a clean, reported refusal,
            # not an unhandled UnicodeDecodeError out of the request handler.
            raise CertificatePublishError(f'cannot read {src}: {e}')
        if not data.strip():
            raise CertificatePublishError(f'source file is empty: {src}')
        if not data.endswith('\n'):
            # Guard against a cert whose last line runs into the key's BEGIN
            # line; certbot always ends with a newline, but a hand-placed file
            # might not.
            data += '\n'
        parts.append(data)
    content = ''.join(parts)

    ok, msg = validate_pem_structure(content)
    if not ok:
        raise CertificatePublishError(
            f'assembled bundle for {dest_path} is not usable: {msg}')

    dest_dir = os.path.dirname(dest_path) or '.'
    try:
        os.makedirs(dest_dir, exist_ok=True)
        os.makedirs(cert_staging_dir(), exist_ok=True)
    except OSError as e:
        raise CertificatePublishError(f'cannot prepare directories: {e}')

    # os.replace() is only atomic within one filesystem. Checking up front
    # turns an EXDEV rename failure into an operator-readable message; the
    # outcome is the same either way (nothing published, live PEM untouched)
    # because staging inside the crt directory is not an acceptable fallback.
    try:
        if os.stat(cert_staging_dir()).st_dev != os.stat(dest_dir).st_dev:
            raise CertificatePublishError(
                f'{cert_staging_dir()} and {dest_dir} are on different '
                'filesystems, so a certificate cannot be swapped in atomically')
    except OSError as e:
        raise CertificatePublishError(f'cannot stat certificate dirs: {e}')

    backup_path = backup_existing_pem(dest_path)

    def _validate_staged(staged_path):
        return validate_pem_bundle(staged_path)

    try:
        write_config_atomically(dest_path, content,
                                staging_dir=cert_staging_dir(),
                                validate=_validate_staged)
    except Exception as e:
        raise CertificatePublishError(
            f'refused to publish {dest_path}: {e}. The previously served '
            'certificate is still in place.')
    logger.info("Published validated certificate bundle to %s%s", dest_path,
                f' (previous copy backed up to {backup_path})'
                if backup_path else '')
    return backup_path


def certbot_register():
    """Register with Let's Encrypt using the certbot client and agree to the terms of service"""
    result = subprocess.run(['certbot', 'show_account'],  capture_output=True)
    if result.returncode != 0:
        subprocess.run(['certbot', 'register', '--agree-tos', '--register-unsafely-without-email', '--no-eff-email'])

def generate_self_signed_cert(ssl_certs_dir):
    """Generate a self-signed certificate for a domain."""
    self_sign_cert = os.path.join(ssl_certs_dir, "default_self_signed_cert.pem")
    print(self_sign_cert)
    if os.path.exists(self_sign_cert):
        print("Self Signed Cert Found")
        return True
    try:
        os.mkdir(ssl_certs_dir)
    except FileExistsError:
        pass
    DOMAIN = socket.gethostname()
    # Generate private key and certificate
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
        '-keyout', '/tmp/key.pem',
        '-out', '/tmp/cert.pem',
        '-days', '3650',
        '-nodes',  # No passphrase
        '-subj', f'/CN={DOMAIN}'
    ], check=True)

    # Combine cert and key for HAProxy. Same publisher as every other bundle:
    # this file lands in the crt directory, so a half-written one would break
    # the TLS bind for every site on the host, and because the function
    # short-circuits on "file exists" a corrupt one would never be regenerated.
    try:
        publish_pem_bundle(self_sign_cert, ['/tmp/cert.pem', '/tmp/key.pem'])
    except CertificatePublishError as e:
        # do_initial_setup() calls this unguarded, so raising here would abort
        # container startup before HAProxy is ever launched. Refusing to write
        # an unusable default cert is right; taking the whole container down
        # over it is not - start_haproxy() already degrades gracefully.
        logger.critical("Could not publish the default self-signed certificate "
                        "to %s: %s", self_sign_cert, e)
        return False
    finally:
        for file in ['/tmp/cert.pem', '/tmp/key.pem']:
            try:
                os.remove(file)  # Clean up temporary files
            except OSError:
                pass
    generate_config()
    return True

def is_process_running(process_name):
    for process in psutil.process_iter(['name']):
        if process.info['name'] == process_name:
            return True
    return False

# Initialize template engine
template_loader = jinja2.FileSystemLoader(TEMPLATE_DIR)
template_env = jinja2.Environment(loader=template_loader)

@app.route('/api/domains', methods=['GET'])
@require_api_key
def get_domains():
    try:
        with sqlite3.connect(DB_FILE) as conn:
          conn.row_factory = sqlite3.Row
          cursor = conn.cursor()
          cursor.execute('''
            SELECT d.*, b.name as backend_name
            FROM domains d
            LEFT JOIN backends b ON d.id = b.domain_id
        ''')
        domains = [dict(row) for row in cursor.fetchall()]
        log_operation('get_domains', True)
        return jsonify(domains)
    except Exception as e:
        log_operation('get_domains', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    try:
        # Check if HAProxy is running
        haproxy_running = is_process_running('haproxy')

        # Check if database is accessible
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT 1')
            cursor.fetchone()

        return jsonify({
            'status': 'healthy',
            'haproxy_status': 'running' if haproxy_running else 'stopped',
            'database': 'connected'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/api/regenerate', methods=['GET'])
@require_api_key
def regenerate_conf():
    try:
        generate_config()
        log_operation('regenerate_config', True)
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        log_operation('regenerate_config', False, str(e))
        return jsonify({
            'status': 'failed',
            'error': str(e)
        }), 500
    
@app.route('/api/reload', methods=['GET'])
@require_api_key
def reload_haproxy():
    try:
        if is_process_running('haproxy'):
            # Use a proper shell command string when shell=True is set
            result = subprocess.run('echo "reload" | socat stdio /tmp/haproxy-cli',
                                   check=True, capture_output=True, text=True, shell=True)
            print(f"Reload result: {result.stdout}, {result.stderr}, {result.returncode}")
            log_operation('reload_haproxy', True)
            return jsonify({'status': 'success'}), 200
        else:
            # Start HAProxy if it's not running
            result = subprocess.run(
                ['haproxy', '-W', '-S', '/tmp/haproxy-cli,level,admin', '-f', HAPROXY_CONFIG_PATH],
                check=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print("HAProxy started successfully")
                log_operation('start_haproxy', True)
                return jsonify({'status': 'success'}), 200
            else:
                error_msg = f"HAProxy start command returned: {result.stdout}\nError output: {result.stderr}"
                print(error_msg)
                log_operation('start_haproxy', False, error_msg)
                return jsonify({'status': 'failed', 'error': error_msg}), 500
    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to start HAProxy: {e.stdout}\n{e.stderr}"
        print(error_msg)
        log_operation('reload_haproxy', False, error_msg)
        return jsonify({'status': 'failed', 'error': error_msg}), 500

@app.route('/api/domain', methods=['POST'])
@require_api_key
def add_domain():
    data = request.get_json()
    domain = data.get('domain')
    template_override = data.get('template_override')
    backend_name = data.get('backend_name')
    servers = data.get('servers', [])
    is_wildcard = data.get('is_wildcard', False)

    if not domain or not backend_name:
        log_operation('add_domain', False, 'Domain and backend_name are required')
        return jsonify({'status': 'error', 'message': 'Domain and backend_name are required'}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()

            # Check if domain already exists
            cursor.execute('SELECT id, ssl_enabled, ssl_cert_path FROM domains WHERE domain = ?', (domain,))
            existing_domain = cursor.fetchone()

            if existing_domain:
                # Domain exists - update it while preserving SSL settings
                domain_id = existing_domain[0]
                ssl_enabled = existing_domain[1]
                ssl_cert_path = existing_domain[2]

                cursor.execute('''
                    UPDATE domains
                    SET template_override = ?, is_wildcard = ?
                    WHERE id = ?
                ''', (template_override, 1 if is_wildcard else 0, domain_id))

                # Update backend or create if doesn't exist
                cursor.execute('SELECT id FROM backends WHERE domain_id = ?', (domain_id,))
                backend_result = cursor.fetchone()

                if backend_result:
                    backend_id = backend_result[0]
                    # Update existing backend name
                    cursor.execute('UPDATE backends SET name = ? WHERE id = ?', (backend_name, backend_id))
                    # Remove old servers
                    cursor.execute('DELETE FROM backend_servers WHERE backend_id = ?', (backend_id,))
                else:
                    # Create new backend
                    cursor.execute('INSERT INTO backends (name, domain_id) VALUES (?, ?)',
                                  (backend_name, domain_id))
                    backend_id = cursor.lastrowid

                logger.info(f"Updated existing domain {domain} (preserved SSL: enabled={ssl_enabled}, cert={ssl_cert_path})")
            else:
                # New domain - insert it
                cursor.execute('INSERT INTO domains (domain, template_override, is_wildcard) VALUES (?, ?, ?)',
                              (domain, template_override, 1 if is_wildcard else 0))
                domain_id = cursor.lastrowid

                # Add backend
                cursor.execute('INSERT INTO backends (name, domain_id) VALUES (?, ?)',
                              (backend_name, domain_id))
                backend_id = cursor.lastrowid

                logger.info(f"Added new domain {domain}")

            # Add/update backend servers
            for server in servers:
                cursor.execute('''
                    INSERT INTO backend_servers
                    (backend_id, server_name, server_address, server_port, server_options)
                    VALUES (?, ?, ?, ?, ?)
                ''', (backend_id, server['name'], server['address'],
                     server['port'], server.get('options')))

        # Close cursor and connection
        cursor.close()
        conn.close()
        generate_config()
        log_operation('add_domain', True, f'Domain {domain} configured successfully')
        return jsonify({'status': 'success', 'domain_id': domain_id})
    except Exception as e:
        log_operation('add_domain', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/default-page')
def default_page():
    """Serve the default page for unmatched domains"""
    admin_email = os.environ.get('HAPROXY_ADMIN_EMAIL', 'admin@example.com')
    
    return render_template('default_page.html',
        page_title=os.environ.get('HAPROXY_DEFAULT_PAGE_TITLE', 'Site Not Configured'),
        main_message=os.environ.get('HAPROXY_DEFAULT_MAIN_MESSAGE', 'This domain has not been configured yet. Please contact your system administrator to set up this website.'),
        secondary_message=os.environ.get('HAPROXY_DEFAULT_SECONDARY_MESSAGE', 'If you believe this is an error, please check the domain name and try again.')
    )

@app.route('/api/ssl', methods=['POST'])
@require_api_key
def request_ssl():
    """Legacy endpoint for requesting SSL certificate for a single domain"""
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        log_operation('request_ssl', False, 'Domain not provided')
        return jsonify({'status': 'error', 'message': 'Domain is required'}), 400

    try:
        # Defensive: clear any stale lock left by a SIGKILLed prior run.
        clear_stale_certbot_locks()

        # Request Let's Encrypt certificate
        result = subprocess.run([
            'certbot', 'certonly', '-n', '--standalone',
            '--preferred-challenges', 'http', '--http-01-port=8688',
            '-d', domain
        ], capture_output=True, text=True)

        if result.returncode == 0:
            # Find the certbot live directory (handles -NNNN suffixes)
            live_dir = find_certbot_live_dir(domain)
            if not live_dir:
                error_msg = f'Certificate obtained but live directory not found for {domain}'
                log_operation('request_ssl', False, error_msg)
                return jsonify({'status': 'error', 'message': error_msg}), 500

            cert_path = os.path.join(live_dir, 'fullchain.pem')
            key_path = os.path.join(live_dir, 'privkey.pem')
            combined_path = f'{SSL_CERTS_DIR}/{domain}.pem'

            # Ensure SSL certs directory exists
            os.makedirs(SSL_CERTS_DIR, exist_ok=True)

            try:
                publish_pem_bundle(combined_path, [cert_path, key_path])
            except CertificatePublishError as e:
                # Nothing was written: any previously served bundle for this
                # name is untouched and HAProxy is not reloaded.
                error_msg = f'Certificate issued but not published: {e}'
                logger.critical(error_msg)
                log_operation('request_ssl', False, error_msg)
                return jsonify({'status': 'error', 'message': error_msg}), 500

            # Update database
            with sqlite3.connect(DB_FILE) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE domains
                    SET ssl_enabled = 1, ssl_cert_path = ?
                    WHERE domain = ?
                ''', (combined_path, domain))
            # Close cursor and connection
            cursor.close()
            conn.close()
            generate_config()
            log_operation('request_ssl', True, f'SSL certificate obtained for {domain}')
            return jsonify({
                'status': 'success',
                'domain': domain,
                'cert_path': combined_path,
                'message': 'Certificate obtained successfully'
            })
        else:
            error_msg = f'Failed to obtain SSL certificate: {result.stderr}'
            log_operation('request_ssl', False, error_msg)
            return jsonify({'status': 'error', 'message': error_msg}), 500
    except Exception as e:
        log_operation('request_ssl', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

def _quarantine_superseded_certs(keep_path, keep_lineage, bundle_names):
    """Move aside cert files that the just-issued bundle supersedes.

    A `.pem` in /etc/haproxy/certs/ is "superseded" iff its certificate's CN
    is one of the bundle's names AND the file isn't the bundle's own combined
    file. We don't look at SANs of the OLD certs — being the CN is enough,
    since that's what HAProxy SNI-matches against and what the file
    convention names it after.

    This used to os.remove() the file and immediately `certbot delete` the
    lineage, both BEFORE anything had checked that the replacement bundle was
    usable — destroying the only two copies of a working certificate on the
    strength of a `cat` whose exit status nobody read. Now:

      * the superseded file is MOVED to the cert backup directory instead of
        unlinked, so an operator can put it back by hand;
      * the certbot lineage is left alone here. Deleting it is irreversible
        (archive, live and renewal config all go) and recovering means fresh,
        rate-limited ACME orders, so it happens only in
        _delete_superseded_lineages(), after HAProxy has actually loaded the
        replacement.

    Moving still solves the problem the removal existed for: the old file no
    longer sits in the crt directory shadowing the new bundle's SNI match.

    Returns a summary dict for logging / API response. Entries in 'removed'
    carry the lineage name for the deletion phase.
    """
    summary = {'removed': [], 'errors': [], 'skipped': []}

    if not os.path.isdir(SSL_CERTS_DIR):
        return summary

    keep_basename = os.path.basename(keep_path)

    for fname in sorted(os.listdir(SSL_CERTS_DIR)):
        if not fname.endswith('.pem'):
            continue
        if fname == keep_basename:
            continue
        fpath = os.path.join(SSL_CERTS_DIR, fname)
        try:
            cn_proc = subprocess.run(
                ['openssl', 'x509', '-in', fpath, '-noout', '-subject', '-nameopt', 'multiline'],
                capture_output=True, text=True
            )
            if cn_proc.returncode != 0:
                summary['skipped'].append({'file': fname, 'reason': 'openssl read failed'})
                continue
            # `-nameopt multiline` lays out the subject one RDN per line; CN is
            # the row matching `commonName`. Robust against unusual subject orderings.
            cn = None
            for line in cn_proc.stdout.splitlines():
                line = line.strip()
                if line.startswith('commonName'):
                    # format: "commonName                = example.com"
                    parts = line.split('=', 1)
                    if len(parts) == 2:
                        cn = parts[1].strip()
                    break
            if not cn:
                summary['skipped'].append({'file': fname, 'reason': 'no CN found'})
                continue
        except Exception as e:
            summary['skipped'].append({'file': fname, 'reason': f'inspect failed: {e}'})
            continue

        if cn not in bundle_names:
            continue  # not superseded — different domain group

        # This file's CN is now part of our new bundle — supersede it.
        lineage_name = fname[:-len('.pem')]
        if lineage_name == keep_lineage:
            # Defensive: shouldn't happen because of keep_basename check, but
            # don't accidentally drop the lineage we just wrote.
            continue

        try:
            os.makedirs(cert_backup_dir(), exist_ok=True)
            quarantine_path = os.path.join(cert_backup_dir(), fname)
            # Move, not unlink: out of the crt directory (so it stops shadowing
            # the new bundle) but still on disk for manual recovery.
            shutil.move(fpath, quarantine_path)
            summary['removed'].append({
                'file': fname,
                'cn': cn,
                'lineage': lineage_name,
                'moved_to': quarantine_path,
                'lineage_deleted': False,
            })
        except Exception as e:
            summary['errors'].append({'file': fname, 'error': str(e)})

    return summary


def _delete_superseded_lineages(summary):
    """`certbot delete` the lineages quarantined by _quarantine_superseded_certs().

    IRREVERSIBLE: certbot removes the lineage's archive, live symlinks and
    renewal config. If it turns out we needed that certificate, the only way
    back is a fresh ACME order, which Let's Encrypt rate-limits — an outage
    measured in hours. So this is gated hardest of anything in this module: it
    runs only after the replacement bundle has been assembled, validated,
    published, AND loaded by a HAProxy that reloaded successfully.

    Mutates `summary` in place. Best-effort: some files have no corresponding
    lineage (e.g. self-signed dev certs) and a failure here is harmless — a
    dead lineage merely wastes a renewal attempt on the next 12h cron tick.
    """
    for entry in summary.get('removed', []):
        lineage_name = entry.get('lineage')
        if not lineage_name:
            continue
        try:
            cb_proc = subprocess.run(
                ['certbot', 'delete', '--cert-name', lineage_name, '-n'],
                capture_output=True, text=True
            )
            entry['lineage_deleted'] = (cb_proc.returncode == 0)
            if cb_proc.returncode != 0:
                entry['certbot_stderr'] = (cb_proc.stderr or '').strip()[:200]
        except Exception as e:
            entry['certbot_error'] = str(e)
    return summary

@app.route('/api/ssl/bundle', methods=['POST'])
@require_api_key
def request_ssl_bundle():
    """Issue a single Let's Encrypt cert covering multiple SANs.

    Used by WHP's per-site bundling: one ACME order, one combined .pem,
    one DB row update per included name. Replaces N separate single-domain
    /api/ssl calls when a site has multiple domains.

    Body:
      {"primary": "example.com", "sans": ["www.example.com", ...]}

    The cert lineage uses --cert-name <primary>, so renewal under the same
    name doesn't proliferate -0001/-0002 dirs (the issue we hit with the
    legacy single-domain flow). The combined PEM is written to
    /etc/haproxy/certs/<primary>.pem; HAProxy matches SNI against the cert's
    SAN list, so this single file serves all included names.
    """
    data = request.get_json() or {}
    primary = (data.get('primary') or '').strip()
    sans = data.get('sans') or []

    if not primary:
        log_operation('request_ssl_bundle', False, 'primary not provided')
        return jsonify({'status': 'error', 'message': '"primary" is required'}), 400

    # Basic shape validation. certbot will hard-validate the rest.
    domain_re = re.compile(
        r'^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
        re.IGNORECASE,
    )
    if not domain_re.match(primary):
        return jsonify({'status': 'error', 'message': f'invalid primary: {primary!r}'}), 400

    # Build the unique ordered name list — primary first, then de-duped SANs.
    if not isinstance(sans, list):
        return jsonify({'status': 'error', 'message': '"sans" must be a list'}), 400
    cleaned_sans = []
    for s in sans:
        if not isinstance(s, str):
            return jsonify({'status': 'error', 'message': f'invalid SAN entry: {s!r}'}), 400
        s = s.strip()
        if not s:
            continue
        if not domain_re.match(s):
            return jsonify({'status': 'error', 'message': f'invalid SAN: {s!r}'}), 400
        cleaned_sans.append(s)

    seen = {primary}
    names = [primary]
    for s in cleaned_sans:
        if s not in seen:
            names.append(s)
            seen.add(s)

    # Let's Encrypt allows up to 100 names per cert.
    if len(names) > 100:
        return jsonify({
            'status': 'error',
            'message': f'Too many SANs ({len(names)}); Let\'s Encrypt limit is 100',
        }), 400

    cmd = [
        'certbot', 'certonly', '-n', '--standalone',
        '--preferred-challenges', 'http', '--http-01-port=8688',
        '--cert-name', primary,
    ]
    for n in names:
        cmd.extend(['-d', n])

    try:
        # Defensive: clear any stale lock left by a SIGKILLed prior run.
        clear_stale_certbot_locks()

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            stderr_excerpt = (result.stderr or '').strip()[:800]
            error_msg = f'Failed to obtain SSL bundle for {primary}: {stderr_excerpt}'
            log_operation('request_ssl_bundle', False, error_msg)
            return jsonify({
                'status': 'error',
                'message': error_msg,
                'primary': primary,
                'attempted_names': names,
            }), 500

        # Locate the lineage. With --cert-name primary, this should be a
        # stable directory name (no -NNNN suffix on the first issuance).
        live_dir = find_certbot_live_dir(primary)
        if not live_dir:
            error_msg = f'Bundle issued but live dir not found for {primary}'
            log_operation('request_ssl_bundle', False, error_msg)
            return jsonify({'status': 'error', 'message': error_msg}), 500

        cert_path = os.path.join(live_dir, 'fullchain.pem')
        key_path = os.path.join(live_dir, 'privkey.pem')
        combined_path = f'{SSL_CERTS_DIR}/{primary}.pem'

        os.makedirs(SSL_CERTS_DIR, exist_ok=True)
        try:
            publish_pem_bundle(combined_path, [cert_path, key_path])
        except CertificatePublishError as e:
            # Publishing is all-or-nothing, so at this point nothing has been
            # written, no old certificate has been touched and no lineage has
            # been deleted. Stop before any of that becomes untrue.
            error_msg = f'Bundle issued but not published for {primary}: {e}'
            logger.critical(error_msg)
            log_operation('request_ssl_bundle', False, error_msg)
            return jsonify({'status': 'error', 'message': error_msg,
                            'primary': primary, 'names': names}), 500

        # Mark every name in the bundle as ssl_enabled, all pointing at the
        # same combined .pem. HAProxy serves one file for many SNI hostnames.
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            for n in names:
                cursor.execute('''
                    UPDATE domains
                    SET ssl_enabled = 1, ssl_cert_path = ?
                    WHERE domain = ?
                ''', (combined_path, n))
            conn.commit()
            cursor.close()

        # Clean up superseded lineages. When the bundle covers names that were
        # previously each in their own single-SAN -0001/-0002 lineage, those
        # older .pem files coexist in /etc/haproxy/certs/ and get loaded by the
        # `bind ... ssl crt /etc/haproxy/certs` directive. HAProxy then picks
        # one of them by alphabetical/load order — frequently the older
        # single-SAN file — and the new bundle has no effect on what's served.
        # This block moves those superseded files out of the crt directory
        # before the generate_config() reload so HAProxy picks up the bundle.
        # It only runs once publish_pem_bundle() above has validated the
        # replacement and put it in place, so the old certificate is never the
        # only copy we have.
        cleanup_summary = _quarantine_superseded_certs(
            keep_path=combined_path,
            keep_lineage=primary,
            bundle_names=set(names),
        )

        # Raises if the config does not validate or HAProxy does not reload;
        # the certbot lineages below are therefore only deleted once the new
        # bundle is genuinely being served.
        try:
            generate_config()
        except Exception:
            if cleanup_summary['removed']:
                logger.critical(
                    "HAProxy did not reload after publishing the bundle for "
                    "%s. The superseded certificate files were moved to %s and "
                    "their certbot lineages were NOT deleted, so they can be "
                    "restored by hand: %s",
                    primary, cert_backup_dir(),
                    [e['file'] for e in cleanup_summary['removed']])
            raise

        _delete_superseded_lineages(cleanup_summary)

        log_operation(
            'request_ssl_bundle', True,
            f'SSL bundle issued for {primary} covering {len(names)} names; '
            f'cleaned up {len(cleanup_summary["removed"])} superseded lineage(s)'
        )
        return jsonify({
            'status': 'success',
            'primary': primary,
            'names': names,
            'cert_path': combined_path,
            'cleanup': cleanup_summary,
            'message': f'Bundled certificate obtained for {len(names)} names',
        })
    except Exception as e:
        log_operation('request_ssl_bundle', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/certificates/renew', methods=['POST'])
@require_api_key
def renew_certificates():
    """Renew all certificates and reload HAProxy"""
    try:
        # Defensive: clear any stale lock left by a SIGKILLed prior run.
        clear_stale_certbot_locks()

        # Run certbot renew. Explicit long timeout (overrides the module
        # default): `renew` walks every lineage and can legitimately make many
        # ACME round-trips when several certs are actually due.
        result = subprocess.run([
            'certbot', 'renew', '--quiet'
        ], capture_output=True, text=True, timeout=900)
        
        if result.returncode == 0:
            # Check if any certificates were renewed
            if 'Congratulations' in result.stdout or 'renewed' in result.stdout:
                # Update combined certificates for HAProxy
                publish_failures = []
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT domain, ssl_cert_path FROM domains WHERE ssl_enabled = 1')
                    domains = cursor.fetchall()

                    for domain, cert_path in domains:
                        if cert_path and os.path.exists(cert_path):
                            # For wildcard domains, strip *. prefix for directory lookup
                            lookup_domain = domain[2:] if domain.startswith('*.') else domain
                            live_dir = find_certbot_live_dir(lookup_domain)
                            if live_dir:
                                letsencrypt_cert = os.path.join(live_dir, 'fullchain.pem')
                                letsencrypt_key = os.path.join(live_dir, 'privkey.pem')

                                if os.path.exists(letsencrypt_cert) and os.path.exists(letsencrypt_key):
                                    # A failure here leaves the currently
                                    # served bundle in place. That certificate
                                    # is still valid (renewal runs ~30 days
                                    # before expiry and retries every 12h), so
                                    # keeping it is strictly better than
                                    # replacing it with something unverified.
                                    try:
                                        publish_pem_bundle(
                                            cert_path,
                                            [letsencrypt_cert, letsencrypt_key])
                                    except CertificatePublishError as e:
                                        logger.critical(
                                            "Renewed certificate for %s was NOT "
                                            "published: %s", domain, e)
                                        publish_failures.append(
                                            {'domain': domain, 'error': str(e)})

                # Regenerate config and reload HAProxy. Safe to do with
                # publish failures present: those certificates were left
                # untouched, so nothing unvalidated is being loaded.
                generate_config()
                reload_result = subprocess.run('echo "reload" | socat stdio /tmp/haproxy-cli',
                                             capture_output=True, text=True, shell=True)
                
                if reload_result.returncode == 0:
                    if publish_failures:
                        error_msg = (
                            f'{len(publish_failures)} renewed certificate(s) could '
                            'not be published and are still being served from '
                            'their previous bundle')
                        log_operation('renew_certificates', False, error_msg)
                        return jsonify({'status': 'partial_success',
                                        'message': error_msg,
                                        'failures': publish_failures}), 500
                    log_operation('renew_certificates', True, 'Certificates renewed and HAProxy reloaded')
                    return jsonify({'status': 'success', 'message': 'Certificates renewed and HAProxy reloaded'})
                else:
                    error_msg = f'Certificates renewed but HAProxy reload failed: {reload_result.stderr}'
                    log_operation('renew_certificates', False, error_msg)
                    return jsonify({'status': 'partial_success', 'message': error_msg}), 500
            else:
                log_operation('renew_certificates', True, 'No certificates needed renewal')
                return jsonify({'status': 'success', 'message': 'No certificates needed renewal'})
        else:
            error_msg = f'Certificate renewal failed: {result.stderr}'
            log_operation('renew_certificates', False, error_msg)
            return jsonify({'status': 'error', 'message': error_msg}), 500
    except Exception as e:
        log_operation('renew_certificates', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/certificates/<domain>/download', methods=['GET'])
@require_api_key
def download_certificate(domain):
    """Download the combined certificate file for a domain"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ssl_cert_path FROM domains WHERE domain = ? AND ssl_enabled = 1', (domain,))
            result = cursor.fetchone()
            
            if not result or not result[0]:
                return jsonify({'status': 'error', 'message': 'Certificate not found for domain'}), 404
            
            cert_path = result[0]
            if not os.path.exists(cert_path):
                return jsonify({'status': 'error', 'message': 'Certificate file not found'}), 404
            
            log_operation('download_certificate', True, f'Certificate downloaded for {domain}')
            return send_file(cert_path, as_attachment=True, download_name=f'{domain}.pem')
    except Exception as e:
        log_operation('download_certificate', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/certificates/<domain>/key', methods=['GET'])
@require_api_key
def download_private_key(domain):
    """Download the private key for a domain"""
    try:
        lookup_domain = domain[2:] if domain.startswith('*.') else domain
        live_dir = find_certbot_live_dir(lookup_domain)
        if not live_dir:
            return jsonify({'status': 'error', 'message': 'Private key not found for domain'}), 404
        key_path = os.path.join(live_dir, 'privkey.pem')
        if not os.path.exists(key_path):
            return jsonify({'status': 'error', 'message': 'Private key not found for domain'}), 404
        
        log_operation('download_private_key', True, f'Private key downloaded for {domain}')
        return send_file(key_path, as_attachment=True, download_name=f'{domain}_key.pem')
    except Exception as e:
        log_operation('download_private_key', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/certificates/<domain>/cert', methods=['GET'])
@require_api_key
def download_cert_only(domain):
    """Download only the certificate (without private key) for a domain"""
    try:
        lookup_domain = domain[2:] if domain.startswith('*.') else domain
        live_dir = find_certbot_live_dir(lookup_domain)
        if not live_dir:
            return jsonify({'status': 'error', 'message': 'Certificate not found for domain'}), 404
        cert_path = os.path.join(live_dir, 'fullchain.pem')
        if not os.path.exists(cert_path):
            return jsonify({'status': 'error', 'message': 'Certificate not found for domain'}), 404
        
        log_operation('download_cert_only', True, f'Certificate (only) downloaded for {domain}')
        return send_file(cert_path, as_attachment=True, download_name=f'{domain}_cert.pem')
    except Exception as e:
        log_operation('download_cert_only', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/certificates/status', methods=['GET'])
@require_api_key
def get_certificate_status():
    """Get status of all certificates including expiration dates"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT domain, ssl_enabled, ssl_cert_path FROM domains WHERE ssl_enabled = 1')
            domains = cursor.fetchall()
            
            cert_status = []
            for domain, ssl_enabled, cert_path in domains:
                status = {
                    'domain': domain,
                    'ssl_enabled': bool(ssl_enabled),
                    'cert_path': cert_path,
                    'expires': None,
                    'days_until_expiry': None
                }
                
                if cert_path and os.path.exists(cert_path):
                    # Check certificate expiration using openssl
                    try:
                        result = subprocess.run([
                            'openssl', 'x509', '-in', cert_path, '-noout', '-dates'
                        ], capture_output=True, text=True)
                        
                        if result.returncode == 0:
                            # Parse the notAfter date
                            for line in result.stdout.split('\n'):
                                if 'notAfter=' in line:
                                    expiry_date_str = line.split('=')[1].strip()
                                    from datetime import datetime
                                    expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                                    status['expires'] = expiry_date.isoformat()
                                    
                                    # Calculate days until expiry
                                    days_until = (expiry_date - datetime.now()).days
                                    status['days_until_expiry'] = days_until
                                    break
                    except Exception as e:
                        status['error'] = str(e)
                
                cert_status.append(status)
            
            log_operation('get_certificate_status', True)
            return jsonify({'certificates': cert_status})
    except Exception as e:
        log_operation('get_certificate_status', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/certificates/request', methods=['POST'])
@require_api_key
def request_certificates():
    """Request certificate generation for one or more domains"""
    data = request.get_json()
    domains = data.get('domains', [])
    force_renewal = data.get('force_renewal', False)
    include_www = data.get('include_www', True)
    
    if not domains:
        log_operation('request_certificates', False, 'No domains provided')
        return jsonify({'status': 'error', 'message': 'At least one domain is required'}), 400
    
    if not isinstance(domains, list):
        domains = [domains]  # Convert single domain to list
    
    results = []
    success_count = 0
    error_count = 0
    
    for domain in domains:
        try:
            # Prepare domain list for certbot (include www subdomain if requested)
            certbot_domains = [domain]
            if include_www and not domain.startswith('www.'):
                certbot_domains.append(f'www.{domain}')
            
            # Build certbot command
            cmd = [
                'certbot', 'certonly', '-n', '--standalone',
                '--preferred-challenges', 'http', '--http-01-port=8688'
            ]
            
            if force_renewal:
                cmd.append('--force-renewal')
            
            # Add domains
            for d in certbot_domains:
                cmd.extend(['-d', d])
            
            # Request certificate
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Find the certbot live directory (handles -NNNN suffixes)
                live_dir = find_certbot_live_dir(domain)
                if not live_dir:
                    error_msg = f'Certificate obtained but live directory not found for {domain}'
                    results.append({
                        'domain': domain,
                        'status': 'error',
                        'message': error_msg
                    })
                    error_count += 1
                    continue

                cert_path = os.path.join(live_dir, 'fullchain.pem')
                key_path = os.path.join(live_dir, 'privkey.pem')
                combined_path = f'{SSL_CERTS_DIR}/{domain}.pem'

                # Ensure SSL certs directory exists
                os.makedirs(SSL_CERTS_DIR, exist_ok=True)

                try:
                    publish_pem_bundle(combined_path, [cert_path, key_path])
                except CertificatePublishError as e:
                    error_msg = f'Certificate issued but not published: {e}'
                    logger.critical('%s (%s)', error_msg, domain)
                    results.append({
                        'domain': domain,
                        'status': 'error',
                        'message': error_msg,
                    })
                    error_count += 1
                    continue

                # Update database (add domain if it doesn't exist)
                with sqlite3.connect(DB_FILE) as conn:
                    cursor = conn.cursor()
                    
                    # Check if domain exists
                    cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
                    domain_exists = cursor.fetchone()
                    
                    if domain_exists:
                        # Update existing domain
                        cursor.execute('''
                            UPDATE domains
                            SET ssl_enabled = 1, ssl_cert_path = ?
                            WHERE domain = ?
                        ''', (combined_path, domain))
                    else:
                        # Add new domain with SSL enabled
                        cursor.execute('''
                            INSERT INTO domains (domain, ssl_enabled, ssl_cert_path)
                            VALUES (?, 1, ?)
                        ''', (domain, combined_path))
                
                results.append({
                    'domain': domain,
                    'status': 'success',
                    'message': 'Certificate obtained successfully',
                    'cert_path': combined_path,
                    'domains_covered': certbot_domains
                })
                success_count += 1
                
            else:
                error_msg = f'Failed to obtain certificate for {domain}: {result.stderr}'
                results.append({
                    'domain': domain,
                    'status': 'error',
                    'message': error_msg,
                    'stderr': result.stderr
                })
                error_count += 1
                
        except Exception as e:
            error_msg = f'Exception while processing {domain}: {str(e)}'
            results.append({
                'domain': domain,
                'status': 'error',
                'message': error_msg
            })
            error_count += 1
    
    # Regenerate HAProxy config if any certificates were successful
    if success_count > 0:
        try:
            generate_config()
            log_operation('request_certificates', True, f'Successfully obtained {success_count} certificates, {error_count} failed')
        except Exception as e:
            log_operation('request_certificates', False, f'Certificates obtained but config generation failed: {str(e)}')
    
    # Return results
    response = {
        'status': 'completed',
        'summary': {
            'total': len(domains),
            'successful': success_count,
            'failed': error_count
        },
        'results': results
    }
    
    if error_count == 0:
        return jsonify(response), 200
    elif success_count > 0:
        return jsonify(response), 207  # Multi-status (some succeeded, some failed)
    else:
        return jsonify(response), 500  # All failed

@app.route('/api/domain', methods=['DELETE'])
@require_api_key
def remove_domain():
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        log_operation('remove_domain', False, 'Domain is required')
        return jsonify({'status': 'error', 'message': 'Domain is required'}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()

            # Get domain ID and SSL status
            cursor.execute('SELECT id, ssl_enabled, ssl_cert_path FROM domains WHERE domain = ?', (domain,))
            domain_result = cursor.fetchone()

            if not domain_result:
                log_operation('remove_domain', False, f'Domain {domain} not found')
                return jsonify({'status': 'error', 'message': 'Domain not found'}), 404

            domain_id, ssl_enabled, ssl_cert_path = domain_result

            # Get backend IDs associated with this domain
            cursor.execute('SELECT id FROM backends WHERE domain_id = ?', (domain_id,))
            backend_ids = [row[0] for row in cursor.fetchall()]

            # Delete backend servers
            for backend_id in backend_ids:
                cursor.execute('DELETE FROM backend_servers WHERE backend_id = ?', (backend_id,))

            # Delete backends
            cursor.execute('DELETE FROM backends WHERE domain_id = ?', (domain_id,))

            # Delete domain
            cursor.execute('DELETE FROM domains WHERE id = ?', (domain_id,))

        # Delete SSL certificate from HAProxy certs directory
        if ssl_enabled and ssl_cert_path:
            try:
                os.remove(ssl_cert_path)
                logger.info(f"Removed HAProxy certificate file: {ssl_cert_path}")
            except OSError as e:
                logger.warning(f"Failed to remove certificate file {ssl_cert_path}: {e}")

        # Remove certificate from certbot
        if ssl_enabled:
            try:
                result = subprocess.run(
                    ['certbot', 'delete', '--cert-name', domain, '--non-interactive'],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    logger.info(f"Removed Let's Encrypt certificate for {domain}")
                else:
                    logger.warning(f"Failed to remove Let's Encrypt certificate for {domain}: {result.stderr}")
            except Exception as e:
                logger.warning(f"Error removing Let's Encrypt certificate for {domain}: {e}")

        # Regenerate HAProxy config
        generate_config()

        log_operation('remove_domain', True, f'Domain {domain} removed successfully')
        return jsonify({'status': 'success', 'message': 'Domain configuration removed'})

    except Exception as e:
        log_operation('remove_domain', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blocked-ips', methods=['GET'])
@require_api_key
def get_blocked_ips():
    """Get all blocked IP addresses"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM blocked_ips ORDER BY blocked_at DESC')
            blocked_ips = [dict(row) for row in cursor.fetchall()]
            log_operation('get_blocked_ips', True)
            return jsonify(blocked_ips)
    except Exception as e:
        log_operation('get_blocked_ips', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blocked-ips', methods=['POST'])
@require_api_key
def add_blocked_ip():
    """Add an IP address to the blocked list"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    reason = data.get('reason', 'No reason provided')
    blocked_by = data.get('blocked_by', 'API')

    if not ip_address:
        log_operation('add_blocked_ip', False, 'IP address is required')
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)',
                          (ip_address, reason, blocked_by))
            blocked_ip_id = cursor.lastrowid

        # Update map file and add to runtime (no full reload needed)
        if not update_blocked_ips_map():
            log_operation('add_blocked_ip', False, f'Failed to update map file for {ip_address}')
            return jsonify({'status': 'error', 'message': 'Failed to update blocked IPs map file'}), 500
        
        # Add to runtime map for immediate effect
        add_ip_to_runtime_map(ip_address)
        
        # Reload HAProxy to ensure consistency
        try:
            if is_process_running('haproxy'):
                if os.path.exists(HAPROXY_SOCKET_PATH):
                    socket_path = HAPROXY_SOCKET_PATH
                else:
                    socket_path = '/tmp/haproxy-cli'
                
                reload_result = subprocess.run(f'echo "reload" | socat stdio {socket_path}',
                                             capture_output=True, text=True, shell=True)
                if reload_result.returncode != 0:
                    logger.warning(f"HAProxy reload failed after blocking IP {ip_address}: {reload_result.stderr}")
        except Exception as e:
            logger.warning(f"Error reloading HAProxy after blocking IP {ip_address}: {e}")
        
        log_operation('add_blocked_ip', True, f'IP {ip_address} blocked successfully')
        return jsonify({'status': 'success', 'blocked_ip_id': blocked_ip_id, 'message': f'IP {ip_address} has been blocked'})
    except sqlite3.IntegrityError:
        log_operation('add_blocked_ip', False, f'IP {ip_address} is already blocked')
        return jsonify({'status': 'error', 'message': 'IP address is already blocked'}), 409
    except Exception as e:
        log_operation('add_blocked_ip', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blocked-ips', methods=['DELETE'])
@require_api_key
def remove_blocked_ip():
    """Remove an IP address from the blocked list"""
    data = request.get_json()
    ip_address = data.get('ip_address')

    if not ip_address:
        log_operation('remove_blocked_ip', False, 'IP address is required')
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM blocked_ips WHERE ip_address = ?', (ip_address,))
            ip_result = cursor.fetchone()
            
            if not ip_result:
                log_operation('remove_blocked_ip', False, f'IP {ip_address} not found in blocked list')
                return jsonify({'status': 'error', 'message': 'IP address not found in blocked list'}), 404

            cursor.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip_address,))

        # Update map file and remove from runtime (no full reload needed)
        if not update_blocked_ips_map():
            log_operation('remove_blocked_ip', False, f'Failed to update map file for {ip_address}')
            return jsonify({'status': 'error', 'message': 'Failed to update blocked IPs map file'}), 500
        
        # Remove from runtime map for immediate effect
        remove_ip_from_runtime_map(ip_address)
        
        # Reload HAProxy to ensure consistency
        try:
            if is_process_running('haproxy'):
                if os.path.exists(HAPROXY_SOCKET_PATH):
                    socket_path = HAPROXY_SOCKET_PATH
                else:
                    socket_path = '/tmp/haproxy-cli'
                
                reload_result = subprocess.run(f'echo "reload" | socat stdio {socket_path}',
                                             capture_output=True, text=True, shell=True)
                if reload_result.returncode != 0:
                    logger.warning(f"HAProxy reload failed after unblocking IP {ip_address}: {reload_result.stderr}")
        except Exception as e:
            logger.warning(f"Error reloading HAProxy after unblocking IP {ip_address}: {e}")
        
        log_operation('remove_blocked_ip', True, f'IP {ip_address} unblocked successfully')
        return jsonify({'status': 'success', 'message': f'IP {ip_address} has been unblocked'})
    except Exception as e:
        log_operation('remove_blocked_ip', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/config/reload', methods=['POST'])
@require_api_key
def reload_config_safely():
    """Safely reload HAProxy configuration with validation and rollback"""
    try:
        # Regenerate config files including map
        generate_config()
        
        log_operation('reload_config_safely', True, 'Configuration reloaded safely')
        return jsonify({'status': 'success', 'message': 'HAProxy configuration reloaded safely'})
    except Exception as e:
        log_operation('reload_config_safely', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/blocked-ips/sync', methods=['POST'])
@require_api_key
def sync_blocked_ips():
    """Sync blocked IPs from database to runtime map"""
    try:
        # Update map file
        if not update_blocked_ips_map():
            return jsonify({'status': 'error', 'message': 'Failed to update map file'}), 500
        
        # Clear and reload runtime map
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ip_address FROM blocked_ips ORDER BY ip_address')
            blocked_ips = [row[0] for row in cursor.fetchall()]
        
        # Try to clear all entries from runtime map (might fail if empty, that's ok)
        try:
            if os.path.exists(HAPROXY_SOCKET_PATH):
                socket_path = HAPROXY_SOCKET_PATH
            else:
                socket_path = '/tmp/haproxy-cli'
            
            subprocess.run(f'echo "clear map #0" | socat stdio {socket_path}', 
                         shell=True, capture_output=True)
        except:
            pass  # Clear might fail if map is empty
        
        # Add all IPs to runtime map
        success_count = 0
        for ip in blocked_ips:
            if add_ip_to_runtime_map(ip):
                success_count += 1
        
        log_operation('sync_blocked_ips', True, f'Synced {success_count}/{len(blocked_ips)} IPs to runtime map')
        return jsonify({
            'status': 'success', 
            'message': f'Synced {success_count}/{len(blocked_ips)} IPs to runtime map',
            'total_ips': len(blocked_ips),
            'synced_ips': success_count
        })
    except Exception as e:
        log_operation('sync_blocked_ips', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ---------------------------------------------------------------------------
# HAProxy runtime API (stick tables)
#
# WHY THIS SECTION IS SO DEFENSIVE
# --------------------------------
# The previous /api/security/stats read `gpc0` and `gpc1` out of `show table
# web` and reported them as "scan count" / "offense count" / "blocked". No
# stick table in this repo has EVER stored a general-purpose counter — see
# STICK_TABLE_FIELD_CONTRACT below and the `store` clauses in
# templates/hap_listener.tpl and templates/hap_security_tables.tpl. Three
# separate silences let that survive:
#
#   1. `int(parts[3])` on a positional split raised ValueError on `exp=368842`
#      and the loop just `continue`d, so every row was skipped and the endpoint
#      always answered `active_threats: 0` with an empty list. An operator
#      reading that saw "no threats" and could not tell it apart from "the
#      parser is broken".
#   2. The command was sent WITHOUT a worker prefix. /tmp/haproxy-cli is the
#      MASTER socket; `show table web` there is answered with "Unknown command:
#      'show', but maybe one of the following ones is a better match: ..." --
#      and socat still exits 0, so `result.returncode != 0` never fired. The
#      reported `total_tracked_ips` was literally the number of lines in that
#      help text minus one (8), while the real table held 388 entries.
#   3. The shell consumers defaulted every missing field to 0 (`${gpc0:-0}`),
#      so a field that does not exist rendered as a confident zero.
#
# Rules for anything added here, all three aimed at the same failure mode:
#   * Read the CONTRACT, not positions. Stick-table output is `name=value` /
#     `name(window)=value` pairs whose order and presence follow the template's
#     `store` clause. Positional indexing silently reads the wrong column the
#     moment that clause changes.
#   * NEVER default a missing field to a number. A field the table does not
#     store must surface as an error naming the field, not as 0.
#   * NEVER trust socat's exit status. HAProxy reports command errors in the
#     response BODY and the socket still closes cleanly. Use haproxy_cli().
#
# scripts/test-stick-table-contract.py holds STICK_TABLE_FIELD_CONTRACT, the
# rendered templates and the shell consumers to each other, and fails if any
# one of them drifts.
# ---------------------------------------------------------------------------

# What each stick table ACTUALLY stores, per its `store` clause. The single
# source of truth for every consumer in this repo. Keep in sync with the
# templates -- the contract test enforces that, in both directions.
STICK_TABLE_FIELD_CONTRACT = {
    'web': ('conn_cur', 'conn_rate', 'http_req_rate', 'http_err_rate'),
    'wp_bruteforce': ('http_req_rate',),
    'xmlrpc_bruteforce': ('http_req_rate',),
}

# Metadata every stick-table entry carries regardless of the `store` clause.
STICK_TABLE_ENTRY_META = ('key', 'use', 'exp', 'shard')

# HAProxy answers a rejected runtime command in the response body and the
# socket still closes 0. These are the prefixes it uses.
_HAPROXY_CLI_ERROR_MARKERS = (
    'Unknown command',
    'No such table',
    'Permission denied',
    "Can't find the specified process",
    'unknown process',
    'Missing ',
)

_STICK_TABLE_TOKEN_RE = re.compile(r'^([a-z_][a-z0-9_]*)(?:\(([^)]*)\))?=(.*)$')
_STICK_TABLE_HEADER_RE = re.compile(
    r'^#\s*table:\s*(?P<name>[^,]+),\s*type:\s*(?P<type>[^,]+),\s*'
    r'size:\s*(?P<size>\d+),\s*used:\s*(?P<used>\d+)')


class HaproxyCliError(RuntimeError):
    """A runtime-API command was rejected, timed out, or answered nothing.

    Exists so a rejected command cannot be mistaken for an empty result. That
    distinction is the whole point of this module's stick-table code.
    """


def _haproxy_socket_path():
    return HAPROXY_SOCKET_PATH if os.path.exists(HAPROXY_SOCKET_PATH) else '/tmp/haproxy-cli'


def _cli_response_is_error(text):
    if text is None:
        return True
    head = text.lstrip()
    return any(head.startswith(marker) for marker in _HAPROXY_CLI_ERROR_MARKERS)


def _cli_send(command, socket_path, timeout):
    proc = subprocess.run(
        ['socat', 'stdio', socket_path],
        input=command + '\n', capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise HaproxyCliError(
            'socat failed talking to %s (exit %d): %s'
            % (socket_path, proc.returncode, (proc.stderr or '').strip()))
    return proc.stdout


def haproxy_cli(command, worker=False, timeout=None):
    """Send one runtime-API command and return its response, or raise.

    `worker=True` marks a command that only the WORKER answers (show table,
    show map, add map, ...). On this deployment the socket is HAProxy's MASTER
    CLI, where those need an `@1` prefix; on a plain stats socket they must NOT
    have one. Rather than guessing from configuration that can change under us,
    try the prefixed form and fall back -- and raise if BOTH are rejected,
    instead of returning HAProxy's help text as if it were data.
    """
    socket_path = _haproxy_socket_path()
    timeout = timeout if timeout is not None else DEFAULT_SUBPROCESS_TIMEOUT
    attempts = (['@1 ' + command, command] if worker else [command])
    failures = []
    for attempt in attempts:
        try:
            out = _cli_send(attempt, socket_path, timeout)
        except subprocess.TimeoutExpired:
            raise HaproxyCliError('timed out after %ss running %r on %s'
                                  % (timeout, attempt, socket_path))
        if out.strip() and not _cli_response_is_error(out):
            return out
        failures.append('%r -> %r' % (attempt, out.strip()[:200] or '<empty response>'))
    raise HaproxyCliError(
        'HAProxy rejected %r on %s (socat exited 0 -- the rejection is in the '
        'response body, which is exactly why this is checked): %s'
        % (command, socket_path, '; '.join(failures)))


def parse_stick_table_entry(line):
    """{field: {'value': str, 'window_ms': int|None}} for one `show table` row.

    Parses `name=value` / `name(window)=value` pairs by NAME. The leading
    `0x...:` allocation pointer is skipped -- reading it as the key is how the
    old code came to report memory addresses as IP addresses.
    """
    fields = {}
    for token in line.split():
        m = _STICK_TABLE_TOKEN_RE.match(token)
        if not m:
            continue  # the 0x...: pointer, or anything else unnamed
        name, window, value = m.group(1), m.group(2), m.group(3)
        fields[name] = {
            'value': value,
            'window_ms': int(window) if window and window.isdigit() else None,
        }
    return fields


def read_stick_table(table):
    """(header dict, [(raw line, parsed fields)]) for a stick table.

    Raises HaproxyCliError if the response is not a stick-table dump, or if any
    row is missing a field the contract says the table stores. A field the
    table does not carry is an ERROR here, never a zero.
    """
    expected = STICK_TABLE_FIELD_CONTRACT.get(table)
    if expected is None:
        raise HaproxyCliError(
            'no field contract for stick table %r; add it to '
            'STICK_TABLE_FIELD_CONTRACT (and to the templates) first' % table)

    raw = haproxy_cli('show table %s' % table, worker=True)
    lines = raw.strip().split('\n')
    header = _STICK_TABLE_HEADER_RE.match(lines[0]) if lines else None
    if not header:
        raise HaproxyCliError(
            'response to `show table %s` is not a stick-table dump; first line '
            'was %r' % (table, lines[0][:200] if lines else ''))

    entries = []
    for line in lines[1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        fields = parse_stick_table_entry(line)
        if 'key' not in fields:
            raise HaproxyCliError(
                'stick-table row for %r has no key= field: %r' % (table, line[:200]))
        missing = [f for f in expected if f not in fields]
        if missing:
            raise HaproxyCliError(
                'stick table %r no longer stores %s -- STICK_TABLE_FIELD_CONTRACT '
                'and the `store` clause in templates/hap_listener.tpl have drifted '
                'apart. Present: %s. Offending row: %r'
                % (table, ', '.join(missing),
                   ', '.join(sorted(fields)), line[:200]))
        entries.append((line, fields))

    return {
        'name': header.group('name'),
        'type': header.group('type'),
        'size': int(header.group('size')),
        'used': int(header.group('used')),
    }, entries


@app.route('/api/security/stats', methods=['GET'])
@require_api_key
def get_security_stats():
    """Per-source connection and request rates from the `web` stick table.

    Reports ONLY what the table stores: conn_cur, conn_rate, http_req_rate and
    http_err_rate, each with the window HAProxy is actually counting over. It
    deliberately does NOT classify a "threat level" or report a "blocked" flag:
    the thresholds live in templates/hap_listener.tpl and a copy here would be
    a second source of truth free to drift, which is the class of bug this
    endpoint used to be. Sources at or over a limit are visible from the rates
    themselves, and the enforcement that actually happened -- 429s, tarpits
    (termination state PT), WAF denials -- is in the edge access log on the
    HOST at /var/log/haproxy.log, which records per-request outcomes the stick
    table never held.

    Query params:
      limit         max sources returned (default 50)
      min_req_rate  only sources at or above this http_req_rate (default 1,
                    i.e. sources with current activity; pass 0 for all)
    """
    try:
        limit = max(1, min(int(request.args.get('limit', 50)), 1000))
        min_req_rate = max(0, int(request.args.get('min_req_rate', 1)))
    except ValueError:
        return jsonify({'status': 'error',
                        'message': 'limit and min_req_rate must be integers'}), 400

    try:
        header, entries = read_stick_table('web')
    except HaproxyCliError as e:
        log_operation('get_security_stats', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 502
    except Exception as e:
        log_operation('get_security_stats', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

    counters = STICK_TABLE_FIELD_CONTRACT['web']
    windows = {}
    sources = []
    active = 0
    for line, fields in entries:
        row = {'ip': fields['key']['value']}
        for name in counters:
            # A non-numeric counter means HAProxy's output format changed under
            # us. Say so; do not coerce it to 0 and report it as a measurement.
            try:
                row[name] = int(fields[name]['value'])
            except ValueError:
                msg = ('stick table web reported a non-numeric %s=%r; the '
                       '`show table` output format has changed. Row: %r'
                       % (name, fields[name]['value'], line[:200]))
                log_operation('get_security_stats', False, msg)
                return jsonify({'status': 'error', 'message': msg}), 502
            if fields[name]['window_ms'] is not None:
                windows.setdefault(name, fields[name]['window_ms'])
        if any(row[name] > 0 for name in counters):
            active += 1
        if row['http_req_rate'] >= min_req_rate:
            sources.append(row)

    sources.sort(key=lambda r: (r['http_req_rate'], r['http_err_rate'],
                                r['conn_rate'], r['conn_cur']), reverse=True)

    return jsonify({
        'status': 'success',
        'table': header['name'],
        'table_size': header['size'],
        'total_tracked_ips': header['used'],
        'sources_with_activity': active,
        'counters': list(counters),
        'counter_windows_ms': windows,
        'returned': len(sources[:limit]),
        'min_req_rate': min_req_rate,
        'sources': sources[:limit],
        'note': ('Current per-source rates only. The stick table stores no '
                 'history and no counter of past blocks; enforcement events '
                 'are in the edge access log on the host at /var/log/haproxy.log.'),
    })

@app.route('/api/security/temporary-block', methods=['POST'])
@require_api_key
def temporary_block():
    """Temporarily block an IP address (auto-unblocks after specified time)"""
    data = request.get_json()
    ip_address = data.get('ip_address')
    duration_minutes = data.get('duration_minutes', 60)  # Default 1 hour

    if not ip_address:
        return jsonify({'status': 'error', 'message': 'IP address is required'}), 400

    if not validate_ip_address(ip_address):
        return jsonify({'status': 'error', 'message': 'Invalid IP address format'}), 400

    try:
        # Add to blocked IPs with expiration time
        expiry_time = datetime.now() + timedelta(minutes=duration_minutes)

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Check if table has expiry column, add if not
            cursor.execute("PRAGMA table_info(blocked_ips)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'expiry_time' not in columns:
                cursor.execute('ALTER TABLE blocked_ips ADD COLUMN expiry_time TEXT')

            # Add or update the blocked IP with expiry
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips (ip_address, reason, expiry_time)
                VALUES (?, ?, ?)
            ''', (ip_address, f'Temporary block for {duration_minutes} minutes', expiry_time.isoformat()))

        # Update map file and add to runtime
        if not update_blocked_ips_map():
            return jsonify({'status': 'error', 'message': 'Failed to update map file'}), 500

        add_ip_to_runtime_map(ip_address)

        log_operation('temporary_block', True, f'Temporarily blocked {ip_address} for {duration_minutes} minutes')
        return jsonify({
            'status': 'success',
            'message': f'IP {ip_address} temporarily blocked for {duration_minutes} minutes',
            'expires_at': expiry_time.isoformat()
        })
    except Exception as e:
        log_operation('temporary_block', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/security/clear-expired', methods=['POST'])
@require_api_key
def clear_expired_blocks():
    """Remove expired temporary IP blocks"""
    try:
        current_time = datetime.now()
        expired_ips = []

        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()

            # Check if expiry_time column exists
            cursor.execute("PRAGMA table_info(blocked_ips)")
            columns = [column[1] for column in cursor.fetchall()]

            if 'expiry_time' in columns:
                # Find and remove expired blocks
                cursor.execute('''
                    SELECT ip_address FROM blocked_ips
                    WHERE expiry_time IS NOT NULL AND expiry_time < ?
                ''', (current_time.isoformat(),))

                expired_ips = [row[0] for row in cursor.fetchall()]

                # Remove expired IPs
                for ip in expired_ips:
                    cursor.execute('DELETE FROM blocked_ips WHERE ip_address = ?', (ip,))
                    remove_ip_from_runtime_map(ip)

        # Update map file if any IPs were removed
        if expired_ips:
            update_blocked_ips_map()

        log_operation('clear_expired_blocks', True, f'Cleared {len(expired_ips)} expired IP blocks')
        return jsonify({
            'status': 'success',
            'message': f'Cleared {len(expired_ips)} expired IP blocks',
            'cleared_ips': expired_ips
        })
    except Exception as e:
        log_operation('clear_expired_blocks', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ssl/dns-challenge/request', methods=['POST'])
@require_api_key
def dns_challenge_request():
    """Start DNS-01 challenge for wildcard certificate"""
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        return jsonify({'success': False, 'error': 'Domain is required'}), 400

    # Extract base domain (strip *. prefix if present)
    base_domain = domain
    if base_domain.startswith('*.'):
        base_domain = base_domain[2:]

    # Validate base_domain format
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', base_domain):
        return jsonify({'success': False, 'error': 'Invalid domain format'}), 400

    # Clean up any previous challenge files
    token_file = f'/tmp/dns-challenge-{base_domain}.token'
    proceed_file = f'/tmp/dns-challenge-{base_domain}.proceed'
    for f in [token_file, proceed_file]:
        if os.path.exists(f):
            os.remove(f)

    # Start certbot in background thread
    def run_certbot():
        try:
            auth_hook = '/haproxy/scripts/dns-challenge-auth-hook.sh'
            cleanup_hook = '/haproxy/scripts/dns-challenge-cleanup-hook.sh'
            logger.info(f"Starting certbot DNS-01 for *.{base_domain} with auth_hook={auth_hook}")
            result = subprocess.run([
                'certbot', 'certonly', '-n',
                '--manual', '--preferred-challenges', 'dns-01',
                '-d', f'*.{base_domain}',
                '--manual-auth-hook', auth_hook,
                '--manual-cleanup-hook', cleanup_hook
            ], capture_output=True, text=True, timeout=600)
            logger.info(f"DNS-01 certbot stdout for *.{base_domain}: {result.stdout}")
            if result.returncode == 0:
                logger.info(f"DNS-01 certbot completed successfully for *.{base_domain}")
            else:
                logger.error(f"DNS-01 certbot failed for *.{base_domain} (rc={result.returncode}): {result.stderr}")
        except subprocess.TimeoutExpired:
            logger.error(f"DNS-01 certbot timed out for *.{base_domain}")
        except Exception as e:
            logger.error(f"DNS-01 certbot error for *.{base_domain}: {e}")

    certbot_thread = threading.Thread(target=run_certbot, daemon=True)
    certbot_thread.start()

    # Poll for the auth hook to write the challenge token
    max_wait = 30
    poll_interval = 0.5
    elapsed = 0
    while elapsed < max_wait:
        if os.path.exists(token_file):
            try:
                with open(token_file, 'r') as f:
                    challenge_token = f.read().strip()
                if challenge_token:
                    log_operation('dns_challenge_request', True, f'Challenge token obtained for *.{base_domain}')
                    return jsonify({
                        'success': True,
                        'data': {
                            'challenge_token': challenge_token,
                            'base_domain': base_domain
                        }
                    })
            except Exception as e:
                logger.warning(f"Error reading token file: {e}")
        time.sleep(poll_interval)
        elapsed += poll_interval

    log_operation('dns_challenge_request', False, f'Timed out waiting for challenge token for *.{base_domain}')
    return jsonify({'success': False, 'error': 'Timed out waiting for challenge token from certbot'}), 504

@app.route('/api/ssl/dns-challenge/verify', methods=['POST'])
@require_api_key
def dns_challenge_verify():
    """Signal certbot to proceed after DNS record is set, wait for cert"""
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        return jsonify({'success': False, 'error': 'Domain is required'}), 400

    # Extract base domain (strip *. prefix if present)
    base_domain = domain
    if base_domain.startswith('*.'):
        base_domain = base_domain[2:]

    # Validate base_domain format
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', base_domain):
        return jsonify({'success': False, 'error': 'Invalid domain format'}), 400

    # Create proceed signal file so the auth hook can continue
    proceed_file = f'/tmp/dns-challenge-{base_domain}.proceed'
    try:
        with open(proceed_file, 'w') as f:
            f.write('proceed')
    except Exception as e:
        log_operation('dns_challenge_verify', False, f'Failed to create proceed file: {e}')
        return jsonify({'success': False, 'error': f'Failed to signal certbot: {e}'}), 500

    # Wait for certbot to finish and produce the certificate
    max_wait = 120
    poll_interval = 1
    elapsed = 0
    live_dir = None

    while elapsed < max_wait:
        live_dir = find_certbot_live_dir(base_domain)
        if live_dir:
            cert_path = os.path.join(live_dir, 'fullchain.pem')
            key_path = os.path.join(live_dir, 'privkey.pem')
            if os.path.exists(cert_path) and os.path.exists(key_path):
                # Check that files were recently modified (within last 5 minutes)
                cert_mtime = os.path.getmtime(cert_path)
                if (time.time() - cert_mtime) < 300:
                    break
        time.sleep(poll_interval)
        elapsed += poll_interval

    if elapsed >= max_wait or not live_dir:
        log_operation('dns_challenge_verify', False, f'Timed out waiting for certificate for *.{base_domain}')
        return jsonify({'success': False, 'error': 'Timed out waiting for certificate from certbot'}), 504

    # Combine fullchain + privkey into HAProxy cert
    cert_path = os.path.join(live_dir, 'fullchain.pem')
    key_path = os.path.join(live_dir, 'privkey.pem')
    try:
        os.makedirs(SSL_CERTS_DIR, exist_ok=True)
        combined_path = f'{SSL_CERTS_DIR}/_wildcard_.{base_domain}.pem'

        try:
            publish_pem_bundle(combined_path, [cert_path, key_path])
        except CertificatePublishError as e:
            error_msg = f'Wildcard certificate obtained but not published: {e}'
            logger.critical(error_msg)
            log_operation('dns_challenge_verify', False, error_msg)
            return jsonify({'success': False, 'error': error_msg}), 500

        # Update database
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            # Match wildcard domain entry (stored as *.domain.tld)
            cursor.execute('''
                UPDATE domains
                SET ssl_enabled = 1, ssl_cert_path = ?
                WHERE domain = ? OR domain = ?
            ''', (combined_path, f'*.{base_domain}', base_domain))

        # Regenerate config and reload HAProxy
        generate_config()

        log_operation('dns_challenge_verify', True, f'Wildcard certificate obtained for *.{base_domain}')
        return jsonify({
            'success': True,
            'data': {
                'domain': f'*.{base_domain}',
                'cert_path': combined_path,
                'message': 'Wildcard certificate obtained and HAProxy updated'
            }
        })
    except Exception as e:
        log_operation('dns_challenge_verify', False, str(e))
        return jsonify({'success': False, 'error': str(e)}), 500

def get_or_create_cluster_secret():
    """Return a stable secret for QUIC token derivation, generating it once.

    HAProxy uses `cluster-secret` to key QUIC Retry/address-validation tokens.
    Without a stable value it picks a random one each (re)start and logs a
    notice; tokens then don't survive reloads. We persist one in the
    /etc/haproxy named volume so it's stable across container recreates.
    Exclusive-create avoids a race if two renders run concurrently. Failure to
    read/write is non-fatal: we fall back to an empty string and the template
    simply omits the directive (HAProxy reverts to its random-per-process
    behaviour), so QUIC still works.
    """
    try:
        if os.path.exists(CLUSTER_SECRET_PATH):
            with open(CLUSTER_SECRET_PATH, 'r') as f:
                secret = f.read().strip()
                if secret:
                    return secret
            # File exists but is blank — e.g. a create that died between
            # open() and write(), or a volume restored empty. Without healing
            # it here we fall through to the O_EXCL create below, which fails
            # with FileExistsError, and the handler re-reads the same blank
            # file: this function would return '' forever and the host would
            # never get the stable secret its docstring promises.
            #
            # Rewrite in place under an exclusive lock rather than unlinking
            # and recreating: the file is never momentarily absent, and two
            # workers healing at once serialise instead of racing to install
            # two different secrets.
            try:
                fd = os.open(CLUSTER_SECRET_PATH, os.O_RDWR)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    # Re-read under the lock: another worker may have healed it
                    # while we were waiting.
                    existing = os.read(fd, 4096).decode(errors='replace').strip()
                    if existing:
                        return existing
                    secret = os.urandom(32).hex()
                    os.ftruncate(fd, 0)
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.write(fd, secret.encode())
                    os.fchmod(fd, 0o600)
                    logger.warning(
                        "Healed empty QUIC cluster-secret at %s",
                        CLUSTER_SECRET_PATH)
                    return secret
                finally:
                    os.close(fd)
            except Exception as e:
                logger.error("Failed to heal empty cluster-secret: %s", e)
                return ''
        # Generate and persist exclusively (0600). hex => config-safe charset.
        secret = os.urandom(32).hex()
        fd = os.open(CLUSTER_SECRET_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(fd, secret.encode())
        finally:
            os.close(fd)
        logger.info("Generated new QUIC cluster-secret at %s", CLUSTER_SECRET_PATH)
        return secret
    except FileExistsError:
        # Lost the create race — another render just wrote it; read it back.
        try:
            with open(CLUSTER_SECRET_PATH, 'r') as f:
                return f.read().strip()
        except Exception as e:
            logger.error("Failed to read cluster-secret after race: %s", e)
            return ''
    except Exception as e:
        logger.error("Failed to get/create cluster-secret: %s", e)
        return ''

def generate_config():
    try:
        conn = sqlite3.connect(DB_FILE)
        # Enable dictionary-like access to rows
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = '''
            SELECT
                d.id as domain_id,
                d.domain,
                d.ssl_enabled,
                d.ssl_cert_path,
                d.template_override,
                d.is_wildcard,
                b.id as backend_id,
                b.name as backend_name
            FROM domains d
            LEFT JOIN backends b ON d.id = b.domain_id
        '''
        cursor.execute(query)

        # Fetch and immediately convert to list of dicts to avoid any cursor issues
        domains = [dict(domain) for domain in cursor.fetchall()]
        
        # Get blocked IPs
        cursor.execute('SELECT ip_address FROM blocked_ips')
        blocked_ips = [row[0] for row in cursor.fetchall()]
        
        config_parts = []

        # Snapshot the last-known-good config BEFORE anything below touches a
        # file in /etc/haproxy. Everything this function writes (haproxy.cfg,
        # blocked_ips.map, coraza-spoe.cfg) is validated as one set by
        # `haproxy -c`, so the rollback point has to predate the first of them.
        # Taking it here (rather than inside reload_haproxy_safely(), which runs
        # after the writes) is what makes rollback real - see create_backup().
        backup_ok, backup_status = create_backup()
        if not backup_ok:
            # Could not even attempt a snapshot (I/O error). Writing a new
            # config now would leave us with no way back, so refuse.
            raise Exception(
                "Refusing to regenerate config: failed to back up the current "
                "configuration, so a failed change could not be rolled back"
            )

        # Optional Coraza WAF integration. When HAPROXY_CORAZA_SPOE_BACKEND is
        # set on the haproxy-manager container, we render an extra TCP backend
        # pointing at a coraza-spoa sidecar AND inject a `filter spoe ...` line
        # into the frontend via hap_listener.tpl. Unset (the default for
        # standalone deployments, home networks, and any non-WHP use of this
        # image) -> the generated haproxy.cfg is byte-identical to today's.
        coraza_spoe_backend = os.environ.get('HAPROXY_CORAZA_SPOE_BACKEND')

        # Optional site-suspension routing. When HAPROXY_SUSPENSION_ENABLED is
        # set (any truthy value), the frontend gets an ACL that rewrites the
        # path to /suspended and routes through default-backend for any host
        # listed in /etc/haproxy/suspended_domains.list. The /suspended Flask
        # route in this same process returns HTTP 503 + a static page — no
        # separate container needed (mirrors the existing /blocked-ip pattern).
        # Same opt-in shape as Coraza: unset -> config byte-identical to today.
        # We just ensure the list file exists (haproxy refuses to start with
        # `-f` pointing at a missing file).
        suspension_raw = os.environ.get('HAPROXY_SUSPENSION_ENABLED', '').strip().lower()
        suspension_enabled = suspension_raw in ('1', 'true', 'yes', 'on')
        if suspension_enabled:
            suspended_list_path = '/etc/haproxy/suspended_domains.list'
            if not os.path.exists(suspended_list_path):
                try:
                    with open(suspended_list_path, 'w') as f:
                        f.write('')
                    os.chmod(suspended_list_path, 0o644)
                    logger.info(f"Created empty {suspended_list_path}")
                except Exception as e:
                    logger.error(f"Failed to create {suspended_list_path}: {e}")

        # Access-log destination for the `log` line in the global section.
        # Default 172.18.0.1:514 is the docker bridge gateway for WHP's
        # `client-net`, i.e. the host, where rsyslog's imudp listener is bound
        # by setup-haproxy-logrotate.sh. Overridable so this image stays usable
        # on standalone/home deployments with a different bridge subnet or a
        # remote log collector -- set HAPROXY_SYSLOG_TARGET to `<ip>:<port>`.
        # UDP, so an absent listener drops log lines and never affects request
        # handling.
        syslog_target = os.environ.get('HAPROXY_SYSLOG_TARGET', '172.18.0.1:514').strip()

        # Add Haproxy Default Headers
        default_headers = template_env.get_template('hap_header.tpl').render(
            cluster_secret = get_or_create_cluster_secret(),
            syslog_target = syslog_target,
        )
        config_parts.append(default_headers)

        # Update blocked IPs map file first. promote_backup=False: the rollback
        # snapshot was taken a few lines above and this map is part of the
        # not-yet-validated change, so refreshing the backup copy here would
        # overwrite the bytes rollback needs - the same class of bug as backing
        # up after the write.
        update_blocked_ips_map(promote_backup=False)

        # Add Listener Block
        listener_block = template_env.get_template('hap_listener.tpl').render(
            crt_path = SSL_CERTS_DIR,
            coraza_spoe_backend = coraza_spoe_backend,
            suspension_enabled = suspension_enabled,
        )
        config_parts.append(listener_block)

        # Add Let's Encrypt
        letsencrypt_acl = template_env.get_template('hap_letsencrypt.tpl').render()
        config_parts.append(letsencrypt_acl)
        config_acls = []
        config_backends = []
        
        # Add default backend rule (will be used when no domain matches)
        default_rule = "    # Default backend for unmatched domains\n    default_backend default-backend\n"
        config_parts.append(default_rule)
        
        # Split domains into exact and wildcard for ACL ordering
        exact_domains = [d for d in domains if not d.get('is_wildcard')]
        wildcard_domains = [d for d in domains if d.get('is_wildcard')]

        # Helper to generate backend config for a domain
        def generate_backend_for_domain(domain):
            try:
                cursor.execute('''
                    SELECT * FROM backend_servers WHERE backend_id = ?
                ''', (domain['backend_id'],))
                servers = [dict(server) for server in cursor.fetchall()]

                if not servers:
                    logger.warning(f"No servers found for backend {domain['backend_name']}")
                    return

                if domain['template_override'] is not None:
                    logger.info(f"Template Override is set to: {domain['template_override']}")
                    template_file = domain['template_override'] + ".tpl"
                    backend_block = template_env.get_template(template_file).render(
                        name=domain['backend_name'],
                        servers=servers
                    )
                else:
                    backend_block = template_env.get_template('hap_backend.tpl').render(
                        name=domain['backend_name'],
                        ssl_enabled=domain['ssl_enabled'],
                        servers=servers
                    )
                config_backends.append(backend_block)
                logger.info(f"Added backend block for: {domain['backend_name']}")
            except Exception as e:
                logger.error(f"Error generating backend block for {domain['backend_name']}: {e}")

        # First pass: exact domain ACLs (higher priority - evaluated first)
        for domain in exact_domains:
            if not domain['backend_name']:
                # Expected for domains registered without a proxy backend (e.g. the
                # panel's own hostname, present only for certificate management).
                # Log at INFO — not WARNING — so it doesn't trip log monitors as an
                # error; it recurs on every generate_config by design.
                logger.info(f"Skipping domain {domain['domain']} - no proxy backend (cert/management-only)")
                continue

            try:
                domain_acl = template_env.get_template('hap_subdomain_acl.tpl').render(
                    domain=domain['domain'],
                    name=domain['backend_name']
                )
                config_acls.append(domain_acl)
                logger.info(f"Added ACL for domain: {domain['domain']}")
            except Exception as e:
                logger.error(f"Error generating domain ACL for {domain['domain']}: {e}")
                continue

            generate_backend_for_domain(domain)

        # Second pass: wildcard domain ACLs (lower priority - evaluated after exact matches)
        for domain in wildcard_domains:
            if not domain['backend_name']:
                # See note above — INFO, not WARNING; expected for cert/management-only domains.
                logger.info(f"Skipping wildcard domain {domain['domain']} - no proxy backend (cert/management-only)")
                continue

            try:
                # Strip *. prefix to get base domain for hdr_end matching
                base_domain = domain['domain']
                if base_domain.startswith('*.'):
                    base_domain = base_domain[2:]

                domain_acl = template_env.get_template('hap_wildcard_acl.tpl').render(
                    domain=domain['domain'],
                    name=domain['backend_name'],
                    base_domain=base_domain
                )
                config_acls.append(domain_acl)
                logger.info(f"Added wildcard ACL for domain: {domain['domain']}")
            except Exception as e:
                logger.error(f"Error generating wildcard ACL for {domain['domain']}: {e}")
                continue

            generate_backend_for_domain(domain)

        # Add ACLS
        config_parts.append('\n' .join(config_acls))
        # Add LetsEncrypt Backend
        letsencrypt_backend = template_env.get_template('hap_letsencrypt_backend.tpl').render()
        config_parts.append(letsencrypt_backend)

        # Add Security Tables
        try:
            security_tables = template_env.get_template('hap_security_tables.tpl').render()
            config_parts.append(security_tables)
        except Exception as e:
            logger.warning(f"Security tables template not found: {e}")

        # Add Default Backend
        try:
            default_backend = template_env.get_template('hap_default_backend.tpl').render()
            config_parts.append(default_backend)
        except Exception as e:
            logger.error(f"Error generating default backend: {e}")
            # Fallback to a simple default backend
            fallback_backend = '''# Default backend for unmatched domains
backend default-backend
    mode http
    option http-server-close
    server default-page 127.0.0.1:8080'''
            config_parts.append(fallback_backend)
        # Add Backends
        config_parts.append('\n' .join(config_backends) + '\n')

        # Coraza WAF backend + SPOE engine config file (only when env var set).
        # Writing /etc/haproxy/coraza-spoe.cfg here keeps it in sync with the
        # filter line that hap_listener.tpl just rendered into the frontend.
        # Explicit trailing '\n' because this is now the LAST config_part —
        # HAProxy fails parse with "Missing LF on last line" otherwise.
        if coraza_spoe_backend:
            coraza_backend_block = template_env.get_template(
                'hap_coraza_spoa_backend.tpl'
            ).render(agent_target=coraza_spoe_backend)
            config_parts.append(coraza_backend_block + '\n')

            coraza_spoe_cfg = template_env.get_template(
                'hap_coraza_spoe_engine.tpl'
            ).render()
            # HAProxy also rejects this file without a trailing LF
            # ("Missing LF on last line"). Belt-and-suspenders — even if the
            # template ends with a newline, Jinja2 can trim it depending on
            # how the file was authored.
            if not coraza_spoe_cfg.endswith('\n'):
                coraza_spoe_cfg += '\n'
            write_config_atomically(CORAZA_SPOE_CONFIG_PATH, coraza_spoe_cfg)
            logger.info(f"Coraza SPOE engine config written to "
                        f"{CORAZA_SPOE_CONFIG_PATH} "
                        f"(SPOA target: {coraza_spoe_backend})")

        config_content = '\n'.join(config_parts)
        logger.debug("Generated HAProxy configuration")

        # Write new configuration to file (atomically - a truncated haproxy.cfg
        # is as fatal as an invalid one). The rollback point was taken above,
        # before this write.
        write_config_atomically(HAPROXY_CONFIG_PATH, config_content)

        # Use safe reload with validation and rollback
        success, message = reload_haproxy_safely(backup_status=backup_status)
        if success:
            logger.info("Configuration generated and HAProxy reloaded safely")
            log_operation('generate_config', True, 'Configuration generated and HAProxy reloaded safely')
        else:
            error_msg = f"Safe reload failed: {message}"
            logger.error(error_msg)
            log_operation('generate_config', False, error_msg)
            raise Exception(error_msg)
    except Exception as e:
        error_msg = f"Error generating config: {e}"
        logger.error(error_msg)
        log_operation('generate_config', False, error_msg)
        import traceback
        traceback.print_exc()
        raise

# ---------------------------------------------------------------------------
# Config backup / rollback
# ---------------------------------------------------------------------------
# Rollback only works if the backup predates the write it is supposed to undo.
# Until 2026-08 create_backup() ran from inside reload_haproxy_safely(), i.e.
# AFTER generate_config() had already overwritten haproxy.cfg — so the "backup"
# was a copy of the new (possibly broken) config and restore_backup() restored
# the same broken bytes. The advertised rollback was a no-op and a fatal
# haproxy.cfg persisted on disk, where start_haproxy() refuses to launch (the
# June 2026 missing-template incident). create_backup() must now be called by
# the writer, BEFORE the first byte is written.

# Statuses returned by create_backup() that mean a rollback target exists.
_ROLLBACK_AVAILABLE_STATUSES = ('created', 'kept_previous')


def _files_identical(path_a, path_b):
    """Byte-compare two files.

    Deliberately not filecmp.cmp(): it memoises on (size, mtime), and
    shutil.copy2() preserves mtime, so a stale cache entry could report a
    changed config as unchanged. These files are small; read them.
    """
    try:
        if os.path.getsize(path_a) != os.path.getsize(path_b):
            return False
        with open(path_a, 'rb') as fa, open(path_b, 'rb') as fb:
            while True:
                chunk_a = fa.read(65536)
                chunk_b = fb.read(65536)
                if chunk_a != chunk_b:
                    return False
                if not chunk_a:
                    return True
    except OSError:
        return False


def _config_set_matches_backup():
    """True if every live config file is byte-identical to its backup copy.

    After a successful reload the live set has already been recorded as
    known-good (see promote_current_config_to_backup()), which is the common
    case at the start of the next generation. Recognising it lets create_backup()
    skip both the re-validation and the copy - worth doing because
    `haproxy -c` on an edge with hundreds of certificates is not free and
    generate_config() runs synchronously inside customer-facing API calls.
    """
    for live_path, backup_path in _config_backup_pairs():
        if os.path.exists(live_path) != os.path.exists(backup_path):
            return False
        if (os.path.exists(live_path)
                and not _files_identical(live_path, backup_path)):
            return False
    return True


def _config_backup_pairs():
    """(live, backup) pairs forming one restorable config set.

    Built at call time rather than at import so the module-level path constants
    stay patchable (tests, alternate deployments).
    """
    return (
        (HAPROXY_CONFIG_PATH, HAPROXY_BACKUP_PATH),
        (BLOCKED_IPS_MAP_PATH, BLOCKED_IPS_MAP_BACKUP_PATH),
        (CORAZA_SPOE_CONFIG_PATH, CORAZA_SPOE_BACKUP_PATH),
    )


def write_config_atomically(path, content, staging_dir=None, validate=None):
    """Write content to path via temp file + rename.

    A half-written haproxy.cfg (disk full, container killed mid-write) is just
    as fatal as an invalid one and is invisible to the caller. os.replace() is
    atomic within a filesystem, so the file on disk is always either the whole
    old config or the whole new one — never a truncated hybrid. This also keeps
    the "existing config is already broken" case from being self-inflicted.

    The same guarantee is what certificate bundles need, so this is the single
    atomic publisher for both (see publish_pem_bundle()); the two extra
    arguments exist for that caller:

    staging_dir: where the temp file is created. Defaults to the destination's
        own directory, which is right for /etc/haproxy but WRONG for
        /etc/haproxy/certs — HAProxy loads that path as a crt directory and
        tries to load every file in it, so a `.tmp` there (or one leaked by a
        crash) can break the whole TLS bind. Must be on the same filesystem as
        `path` or os.replace() cannot be atomic; if it is not, the rename fails
        loudly and the destination is left untouched, which is the safe outcome.

    validate: optional callable(temp_path) -> (ok, message), run on the staged
        file BEFORE it is moved into place. Returning False aborts the publish
        with the temp file removed and `path` still holding its previous
        contents. This is the only ordering that lets us validate the
        replacement without having destroyed the original first.
    """
    directory = staging_dir or os.path.dirname(path) or '.'
    # Preserve the mode of the file we are replacing; mkstemp defaults to 0600
    # and HAProxy config files are conventionally 0644.
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        mode = 0o644
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=os.path.basename(path) + '.', suffix='.tmp'
    )
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, mode)
        if validate is not None:
            ok, message = validate(tmp_path)
            if not ok:
                raise ValueError(f'staged file failed validation: {message}')
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def create_backup(require_valid=True):
    """Snapshot the CURRENT on-disk config set as the rollback point.

    MUST be called BEFORE the new configuration is written — see the module
    comment above. Calling it afterwards silently disarms rollback.

    require_valid=True (default) refuses to promote a config that HAProxy
    already rejects. Backing up a broken config would make "rollback" mean
    "restore a different broken config"; keeping the older, validated backup
    instead means a rollback always lands on something HAProxy will actually
    start with. Cost is one `haproxy -c` run per config generation.

    Returns (ok, status):
      ok=False, status='error'      - the copy itself failed; caller decides.
      status='created'              - backup now holds the current config.
      status='kept_previous'        - current config missing or invalid; the
                                      existing (older, good) backup was kept.
      status='unavailable'          - nothing to roll back to at all (first
                                      run, or broken config and no prior
                                      backup). Rollback is NOT possible.
    """
    try:
        snapshot_ok = True
        reason = None

        if not os.path.exists(HAPROXY_CONFIG_PATH):
            snapshot_ok = False
            reason = 'no existing HAProxy config on disk (first run?)'
        elif _config_set_matches_backup():
            # The backup already IS the current config, recorded when it last
            # loaded successfully. Nothing to copy and nothing to re-validate.
            logger.debug("Config backup already matches the live config")
            return True, 'created'
        elif require_valid:
            status, msg = validate_config_file(HAPROXY_CONFIG_PATH)
            if status == 'invalid':
                snapshot_ok = False
                reason = f'current config on disk does not validate: {msg}'
            elif status == 'unavailable':
                # The validator itself could not run (no haproxy binary, etc).
                # That is NOT evidence the config is bad, and refusing to back
                # up would leave us with no rollback target at all, so fall
                # back to last-written semantics and say so loudly.
                logger.warning(
                    f"Could not verify current config before backup ({msg}); "
                    "backing it up unverified"
                )

        if not snapshot_ok:
            if os.path.exists(HAPROXY_BACKUP_PATH):
                logger.warning(
                    f"Not refreshing config backup: {reason}. Keeping the "
                    f"existing backup at {HAPROXY_BACKUP_PATH} as the rollback "
                    "target."
                )
                return True, 'kept_previous'
            logger.error(
                f"No config backup could be taken: {reason}, and no previous "
                f"backup exists at {HAPROXY_BACKUP_PATH}. ROLLBACK IS NOT "
                "AVAILABLE for this configuration change."
            )
            return True, 'unavailable'

        for live_path, backup_path in _config_backup_pairs():
            if os.path.exists(live_path):
                shutil.copy2(live_path, backup_path)
        logger.info("Backup of last-known-good config created successfully")
        return True, 'created'
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return False, 'error'

def promote_current_config_to_backup():
    """Record the live config as the known-good rollback target.

    Called ONLY after the config has both validated and been loaded by HAProxy,
    so "backup" really means "the last configuration this box was running".
    Must never be called before a reload attempt: doing so would make the
    backup a copy of the config we may still have to roll back from - the same
    class of bug as backing up after the write.

    Without this, a box whose very first generation succeeded has no rollback
    target at all until its second successful generation, and any corruption of
    haproxy.cfg in between leaves nothing to recover to.
    """
    try:
        for live_path, backup_path in _config_backup_pairs():
            if os.path.exists(live_path):
                shutil.copy2(live_path, backup_path)
        logger.debug("Known-good config backup updated after successful reload")
        return True
    except Exception as e:
        # Non-fatal: the config is live and working, we just failed to record
        # it. Loud, because the next change now has a staler rollback target.
        logger.error(f"Failed to record known-good config backup: {e}")
        return False


def restore_backup():
    """Restore the backed-up config set over the live files.

    Returns (restored, message). restored=False means NOTHING was rolled back
    and the live config is still whatever the failed change left on disk —
    callers MUST surface that difference, it is the difference between "we
    recovered" and "this edge is sitting on a config HAProxy will not load".
    """
    if not os.path.exists(HAPROXY_BACKUP_PATH):
        msg = (f"No config backup at {HAPROXY_BACKUP_PATH} - cannot roll back; "
               f"{HAPROXY_CONFIG_PATH} still holds the failed configuration")
        logger.critical(msg)
        return False, msg
    try:
        for live_path, backup_path in _config_backup_pairs():
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, live_path)
        msg = f"Configuration restored from backup ({HAPROXY_BACKUP_PATH})"
        logger.info(msg)
        return True, msg
    except Exception as e:
        msg = (f"Failed to restore backup: {e} - {HAPROXY_CONFIG_PATH} may hold "
               "a broken configuration")
        logger.critical(msg)
        return False, msg


def validate_config_file(config_path):
    """Run `haproxy -c` against config_path.

    Returns (status, message) with status one of:
      'valid'       - HAProxy parsed the file successfully
      'invalid'     - HAProxy rejected it (message carries stderr)
      'unavailable' - the validator could not be run at all (binary missing,
                      timeout, ...). Deliberately distinct from 'invalid':
                      it tells us nothing about the config.
    """
    try:
        result = subprocess.run(['haproxy', '-c', '-f', config_path],
                                capture_output=True, text=True)
    except Exception as e:
        return 'unavailable', f"Error validating HAProxy config: {e}"
    if result.returncode == 0:
        return 'valid', None
    return 'invalid', f"HAProxy configuration validation failed: {result.stderr}"


def validate_haproxy_config():
    """Validate the live HAProxy configuration file. Returns (is_valid, error).

    NOTE the invalid/unavailable distinction validate_config_file() draws does
    NOT survive here: this returns a bare bool, so a validator that could not
    run is reported the same as a rejected config and the reload path rolls
    back, logging "Config validation failed". That is deliberate - without a
    working validator we cannot claim the new config is safe, and the reload
    path is the one place where guessing wrong takes the edge down. The
    distinction is only acted on inside create_backup(), where treating
    "cannot check" as "bad" would mean refusing to keep any rollback target at
    all. (The 2026-08 commit message said flatly that "a missing haproxy binary
    is not read as a bad config"; that is true of create_backup() only.)
    """
    status, message = validate_config_file(HAPROXY_CONFIG_PATH)
    if status == 'valid':
        logger.info("HAProxy configuration validation passed")
        return True, None
    logger.error(message)
    return False, message

def reload_haproxy_safely(backup_status=None):
    """Safely reload HAProxy with validation and rollback.

    PRECONDITION: the caller must already have called create_backup() BEFORE
    writing the new config, and pass the status it returned. This function runs
    after the new config is on disk, so it cannot take a meaningful backup
    itself — doing so is exactly the bug this contract exists to prevent.

    backup_status=None means the caller did not take a pre-write backup. We do
    NOT create one here (that would overwrite a genuinely good backup with the
    unverified new config); we log it and fall back to whatever backup already
    exists on disk.
    """
    try:
        if backup_status is None:
            logger.error(
                "reload_haproxy_safely() called without a pre-write backup "
                "status - rollback will fall back to whatever backup already "
                "exists on disk. Callers must call create_backup() BEFORE "
                "writing the new configuration."
            )
        elif backup_status not in _ROLLBACK_AVAILABLE_STATUSES:
            logger.warning(
                f"Proceeding with reload without a rollback target "
                f"(backup status: {backup_status})"
            )

        # Validate new configuration
        is_valid, error_msg = validate_haproxy_config()
        if not is_valid:
            # Restore backup on validation failure
            restored, restore_msg = restore_backup()
            if not restored:
                logger.critical(
                    "Config validation failed AND rollback was not possible - "
                    f"{HAPROXY_CONFIG_PATH} holds an invalid configuration that "
                    "HAProxy will refuse to start with"
                )
                return False, (f"Config validation failed: {error_msg} | "
                               f"ROLLBACK FAILED: {restore_msg}")
            return False, f"Config validation failed: {error_msg}"

        # Attempt reload
        if is_process_running('haproxy'):
            # Use HAProxy stats socket for graceful reload
            try:
                if os.path.exists(HAPROXY_SOCKET_PATH):
                    reload_result = subprocess.run(
                        f'echo "reload" | socat stdio {HAPROXY_SOCKET_PATH}',
                        capture_output=True, text=True, shell=True
                    )
                else:
                    # Fallback to old socket path
                    reload_result = subprocess.run(
                        'echo "reload" | socat stdio /tmp/haproxy-cli',
                        capture_output=True, text=True, shell=True
                    )
                
                if reload_result.returncode == 0:
                    logger.info("HAProxy reloaded successfully")
                    # Now - and only now - is this config known good.
                    promote_current_config_to_backup()
                    return True, "HAProxy reloaded successfully"
                else:
                    # Reload failed, restore backup
                    restored, restore_msg = restore_backup()
                    if restored:
                        # Try to reload with the restored (known-good) config
                        subprocess.run(
                            'echo "reload" | socat stdio /tmp/haproxy-cli',
                            shell=True, capture_output=True)
                    error_msg = f"HAProxy reload failed: {reload_result.stderr}"
                    if not restored:
                        error_msg += f" | ROLLBACK FAILED: {restore_msg}"
                    logger.error(error_msg)
                    return False, error_msg
            except Exception as e:
                # Critical error during reload, restore backup
                restored, restore_msg = restore_backup()
                error_msg = f"Critical error during reload: {e}"
                if not restored:
                    error_msg += f" | ROLLBACK FAILED: {restore_msg}"
                logger.error(error_msg)
                return False, error_msg
        else:
            # HAProxy not running, start it
            try:
                result = subprocess.run(
                    ['haproxy', '-W', '-S', '/tmp/haproxy-cli,level,admin', '-f', HAPROXY_CONFIG_PATH],
                    check=True, capture_output=True, text=True
                )
                logger.info("HAProxy started successfully")
                # Now - and only now - is this config known good.
                promote_current_config_to_backup()
                return True, "HAProxy started successfully"
            except subprocess.CalledProcessError as e:
                # Start failed, restore backup
                restored, restore_msg = restore_backup()
                error_msg = f"Failed to start HAProxy: {e.stderr}"
                if not restored:
                    error_msg += f" | ROLLBACK FAILED: {restore_msg}"
                logger.error(error_msg)
                return False, error_msg
    except Exception as e:
        # KNOWN GAP (pre-existing, unchanged by the 2026-08 backup-ordering
        # fix): this outer handler does NOT roll back. The window is narrow -
        # everything after the validation gate has its own handler - but an
        # exception raised between the gate and those handlers leaves the new
        # config on disk. Left as-is deliberately; rolling back from here would
        # also undo changes that had in fact loaded.
        error_msg = f"Critical error in reload process: {e}"
        logger.error(error_msg)
        return False, error_msg

def _blocked_ips_map_is_wellformed(path):
    """True if every key in a blocked-IPs map is one HAProxy will parse.

    map_ip() rejects the ENTIRE configuration if a single key is not an IP or
    CIDR ("'198.51.10' is not a valid IPv4 or IPv6 address at line 2 of file
    ..."), so this is the property that decides whether the file is safe to
    record as a rollback target. Pure Python over a small file - deliberately
    not another `haproxy -c`, which is the cost this check exists to avoid.
    """
    try:
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                ipaddress.ip_network(line.split()[0], strict=False)
    except (OSError, ValueError, IndexError):
        return False
    return True


def _promote_blocked_ips_map_to_backup():
    """Keep blocked_ips.map.backup in step with the map just written.

    The /api/blocked-ips routes call update_blocked_ips_map() OUTSIDE
    generate_config(): the map write IS the whole change there, published
    against a config HAProxy is already running. Without promoting it, the live
    map drifts from its backup, create_backup() misses its fast path on the
    NEXT config change, and an edge that blocks IPs automatically (this fleet
    does) pays an extra `haproxy -c` on the following customer-facing domain
    add - permanently, since every block re-opens the drift.

    Guarded twice:
      * a config backup set must already exist - never fabricate a rollback
        target out of nothing (see restore_backup()); and
      * the map must be well-formed, so promoting it cannot leave a "rollback
        target" HAProxy refuses to load. That would be this module's own bug
        on a different file.
    When either fails we leave the older backup map alone and the next
    create_backup() takes the slow, `haproxy -c`-validated path - i.e. the
    behaviour before this function existed. Nothing here can lose data.

    Note the map is promoted after the write rather than after the caller's
    reload: the routes only warn on a failed reload and carry on, so there is
    no reload result to gate on. A well-formed map that HAProxy has not loaded
    yet is still a loadable rollback target, which is the guarantee that
    matters.
    """
    if not os.path.exists(HAPROXY_BACKUP_PATH):
        return False
    if not _blocked_ips_map_is_wellformed(BLOCKED_IPS_MAP_PATH):
        logger.warning(
            f"Not recording {BLOCKED_IPS_MAP_PATH} as known-good: it contains "
            "an entry HAProxy cannot parse, which would make the whole "
            "configuration invalid. Keeping the previous backup map."
        )
        return False
    try:
        shutil.copy2(BLOCKED_IPS_MAP_PATH, BLOCKED_IPS_MAP_BACKUP_PATH)
        return True
    except OSError as e:
        logger.warning(f"Could not update the backup blocked IPs map: {e}")
        return False


def update_blocked_ips_map(promote_backup=True):
    """Update the blocked IPs map file from database.

    promote_backup=False is for callers that are in the middle of an
    unvalidated configuration change - generate_config() has already taken the
    rollback snapshot by the time it gets here, so refreshing the backup map
    would overwrite the very bytes rollback needs.
    """
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ip_address FROM blocked_ips ORDER BY ip_address')
            blocked_ips = [row[0] for row in cursor.fetchall()]

        # Write map file in HAProxy map format: <key> <value>
        # For IP blocking, we use: <ip_or_cidr> 1
        # This allows map_ip() to work with both single IPs and CIDR ranges
        os.makedirs(os.path.dirname(BLOCKED_IPS_MAP_PATH), exist_ok=True)
        # Atomically, for the same reason haproxy.cfg is: `haproxy -c` LOADS
        # this file (hap_listener.tpl matches on
        # map_ip(/etc/haproxy/blocked_ips.map,0)), and a half-written final
        # line is a FATAL config error rather than one dropped entry - verified
        # against HAProxy 2.8. A truncated map is therefore exactly the failure
        # this module's backup ordering exists to prevent, on a different file.
        write_config_atomically(
            BLOCKED_IPS_MAP_PATH,
            ''.join(f"{ip} 1\n" for ip in blocked_ips)
        )

        if promote_backup:
            _promote_blocked_ips_map_to_backup()

        logger.info(f"Updated blocked IPs map file with {len(blocked_ips)} IPs")
        return True
    except Exception as e:
        logger.error(f"Failed to update blocked IPs map: {e}")
        return False

def add_ip_to_runtime_map(ip_address):
    """Add IP to HAProxy runtime map without reload"""
    try:
        if os.path.exists(HAPROXY_SOCKET_PATH):
            socket_path = HAPROXY_SOCKET_PATH
        else:
            socket_path = '/tmp/haproxy-cli'

        # Add to runtime map (map file ID 0 for blocked IPs)
        # Format: add map #<id> <key> <value>
        # For IP blocking, value is always "1"
        cmd = f'echo "add map #0 {ip_address} 1" | socat stdio {socket_path}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            logger.info(f"Added IP {ip_address} to runtime map")
            return True
        else:
            logger.warning(f"Failed to add IP to runtime map: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error adding IP to runtime map: {e}")
        return False

def remove_ip_from_runtime_map(ip_address):
    """Remove IP from HAProxy runtime map without reload"""
    try:
        if os.path.exists(HAPROXY_SOCKET_PATH):
            socket_path = HAPROXY_SOCKET_PATH
        else:
            socket_path = '/tmp/haproxy-cli'
        
        # Remove from runtime map (map file ID 0 for blocked IPs)
        cmd = f'echo "del map #0 {ip_address}" | socat stdio {socket_path}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"Removed IP {ip_address} from runtime map")
            return True
        else:
            logger.warning(f"Failed to remove IP from runtime map: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error removing IP from runtime map: {e}")
        return False

def start_haproxy():
    if not is_process_running('haproxy'):
        try:
            # First check if the config file exists and is valid
            if not os.path.exists(HAPROXY_CONFIG_PATH):
                logger.warning("HAProxy config file not found, skipping HAProxy start")
                return
            
            # Test the configuration before starting
            test_result = subprocess.run(
                ['haproxy', '-c', '-f', HAPROXY_CONFIG_PATH],
                capture_output=True,
                text=True
            )
            
            if test_result.returncode != 0:
                logger.error(f"HAProxy configuration is invalid: {test_result.stderr}")
                logger.warning("Attempting to regenerate configuration...")
                
                # Try to regenerate the configuration
                try:
                    generate_config()
                    logger.info("Configuration regenerated successfully")
                except Exception as gen_error:
                    logger.error(f"Failed to regenerate configuration: {gen_error}")
                    logger.warning("HAProxy will not start due to configuration errors")
                    log_operation('start_haproxy', False, f"Invalid config: {test_result.stderr}")
                    return
                
                # Test the configuration again
                test_result = subprocess.run(
                    ['haproxy', '-c', '-f', HAPROXY_CONFIG_PATH],
                    capture_output=True,
                    text=True
                )
                
                if test_result.returncode != 0:
                    logger.error(f"HAProxy configuration is still invalid after regeneration: {test_result.stderr}")
                    logger.warning("HAProxy will not start due to configuration errors")
                    log_operation('start_haproxy', False, f"Invalid config: {test_result.stderr}")
                    return
            
            # Configuration is valid, start HAProxy
            result = subprocess.run(
                ['haproxy', '-W', '-S', '/tmp/haproxy-cli,level,admin', '-f', HAPROXY_CONFIG_PATH],
                check=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                logger.info("HAProxy started successfully")
                log_operation('start_haproxy', True, 'HAProxy started successfully')
            else:
                error_msg = f"HAProxy start command returned: {result.stdout}\nError output: {result.stderr}"
                logger.error(error_msg)
                log_operation('start_haproxy', False, error_msg)
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to start HAProxy: {e.stdout}\n{e.stderr}"
            logger.error(error_msg)
            log_operation('start_haproxy', False, error_msg)
            # Don't raise the exception - let the container continue without HAProxy
            logger.warning("Container will continue without HAProxy running")
        except Exception as e:
            error_msg = f"Unexpected error starting HAProxy: {e}"
            logger.error(error_msg)
            log_operation('start_haproxy', False, error_msg)
            logger.warning("Container will continue without HAProxy running")

def do_initial_setup():
    """One-time container-startup setup: DB schema, certbot account, fresh
    self-signed cert, config generation, and HAProxy launch. Idempotent;
    safe to re-run, but in prod it should run exactly once per container
    instance (via scripts/init.py before gunicorn workers spawn) so that
    start_haproxy() doesn't race with itself across forks.
    """
    init_db()
    # Clear any stale certbot locks left from a previous container instance
    # that didn't shut down cleanly. Safe — only removes locks that no live
    # process holds (verified via fcntl probe).
    _stale = clear_stale_certbot_locks()
    if _stale['cleared']:
        logger.info(f"Cleared stale certbot lock(s) at startup: {_stale['cleared']}")
    if _stale['held']:
        logger.warning(f"certbot lock(s) actively held at startup: {_stale['held']}")
    certbot_register()
    generate_self_signed_cert(SSL_CERTS_DIR)

    # Always regenerate config before starting HAProxy to ensure compatibility
    try:
        generate_config()
        logger.info("Configuration generated successfully before startup")
    except Exception as e:
        logger.error(f"Failed to generate initial configuration: {e}")
        # Continue anyway, HAProxy will fail to start but the service will be available

    start_haproxy()
    certbot_register()


if __name__ == '__main__':
    # Direct-invocation path: `python haproxy_manager.py`. Used for local dev
    # and as a fallback. In the container this runs only when scripts/start-up.sh
    # is bypassed; production uses gunicorn after scripts/init.py.
    do_initial_setup()

    # Run both Flask apps on the werkzeug dev server. Acceptable for local
    # development but NOT production — gunicorn is the prod server, invoked
    # from scripts/start-up.sh.
    from threading import Thread
    Thread(
        target=lambda: default_app.run(host='0.0.0.0', port=8080),
        daemon=True,
    ).start()
    app.run(host='0.0.0.0', port=8000)
