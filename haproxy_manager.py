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
import tempfile
import threading
import time
import re
import fcntl

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


# Configuration
DB_FILE = '/etc/haproxy/haproxy_config.db'
TEMPLATE_DIR = Path('templates')
HAPROXY_CONFIG_PATH = '/etc/haproxy/haproxy.cfg'
HAPROXY_BACKUP_PATH = '/etc/haproxy/haproxy.cfg.backup'
BLOCKED_IPS_MAP_PATH = '/etc/haproxy/blocked_ips.map'
BLOCKED_IPS_MAP_BACKUP_PATH = '/etc/haproxy/blocked_ips.map.backup'
HAPROXY_SOCKET_PATH = '/var/run/haproxy.sock'
SSL_CERTS_DIR = '/etc/haproxy/certs'
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

    # Combine cert and key for HAProxy
    with open(self_sign_cert, 'wb') as combined:
        for file in ['/tmp/cert.pem', '/tmp/key.pem']:
            with open(file, 'rb') as f:
                combined.write(f.read())
            os.remove(file)  # Clean up temporary files
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

            with open(combined_path, 'w') as combined:
                subprocess.run(['cat', cert_path, key_path], stdout=combined)

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

def _cleanup_superseded_lineages(keep_path, keep_lineage, bundle_names):
    """Remove cert files + certbot lineages that the just-issued bundle supersedes.

    A `.pem` in /etc/haproxy/certs/ is "superseded" iff its certificate's CN
    is one of the bundle's names AND the file isn't the bundle's own combined
    file. We don't look at SANs of the OLD certs — being the CN is enough,
    since that's what HAProxy SNI-matches against and what the file
    convention names it after.

    Also drops the corresponding certbot renewal config so `certbot renew`
    stops trying to renew the dead lineage on its next 12h cron tick.

    Returns a small summary dict for logging / API response.
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
            os.remove(fpath)
            removed_entry = {'file': fname, 'cn': cn, 'lineage_deleted': False}
            # Best-effort certbot lineage delete. Some files may not have a
            # corresponding lineage (e.g. self-signed dev certs); ignore those.
            try:
                cb_proc = subprocess.run(
                    ['certbot', 'delete', '--cert-name', lineage_name, '-n'],
                    capture_output=True, text=True
                )
                removed_entry['lineage_deleted'] = (cb_proc.returncode == 0)
                if cb_proc.returncode != 0:
                    removed_entry['certbot_stderr'] = (cb_proc.stderr or '').strip()[:200]
            except Exception as e:
                removed_entry['certbot_error'] = str(e)
            summary['removed'].append(removed_entry)
        except Exception as e:
            summary['errors'].append({'file': fname, 'error': str(e)})

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
        with open(combined_path, 'w') as combined:
            subprocess.run(['cat', cert_path, key_path], stdout=combined)

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
        # This block deletes those superseded files (and their certbot lineage)
        # before the generate_config() reload so HAProxy picks up the bundle.
        cleanup_summary = _cleanup_superseded_lineages(
            keep_path=combined_path,
            keep_lineage=primary,
            bundle_names=set(names),
        )

        generate_config()
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

        # Run certbot renew
        result = subprocess.run([
            'certbot', 'renew', '--quiet'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            # Check if any certificates were renewed
            if 'Congratulations' in result.stdout or 'renewed' in result.stdout:
                # Update combined certificates for HAProxy
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
                                    with open(cert_path, 'w') as combined:
                                        subprocess.run(['cat', letsencrypt_cert, letsencrypt_key], stdout=combined)
                
                # Regenerate config and reload HAProxy
                generate_config()
                reload_result = subprocess.run('echo "reload" | socat stdio /tmp/haproxy-cli',
                                             capture_output=True, text=True, shell=True)
                
                if reload_result.returncode == 0:
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

                with open(combined_path, 'w') as combined:
                    subprocess.run(['cat', cert_path, key_path], stdout=combined)
                
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

@app.route('/api/security/stats', methods=['GET'])
@require_api_key
def get_security_stats():
    """Get current security statistics from HAProxy stick table"""
    try:
        if os.path.exists(HAPROXY_SOCKET_PATH):
            socket_path = HAPROXY_SOCKET_PATH
        else:
            socket_path = '/tmp/haproxy-cli'

        # Get stick table data
        cmd = f'echo "show table web" | socat stdio {socket_path}'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            return jsonify({'status': 'error', 'message': 'Failed to get stick table data'}), 500

        # Parse stick table output
        lines = result.stdout.strip().split('\n')
        threats = []

        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 8:
                ip = parts[0]
                try:
                    gpc0 = int(parts[3]) if len(parts) > 3 else 0
                    gpc1 = int(parts[4]) if len(parts) > 4 else 0
                    req_rate = int(parts[5]) if len(parts) > 5 else 0
                    err_rate = int(parts[6]) if len(parts) > 6 else 0
                    conn_rate = int(parts[7]) if len(parts) > 7 else 0

                    # Only include IPs with significant activity
                    if gpc0 > 0 or gpc1 > 0 or req_rate > 30 or err_rate > 5 or conn_rate > 10:
                        threat_level = 'low'
                        if gpc1 > 2:
                            threat_level = 'critical'
                        elif gpc0 > 0 or err_rate > 10:
                            threat_level = 'high'
                        elif req_rate > 40 or conn_rate > 15:
                            threat_level = 'medium'

                        threats.append({
                            'ip': ip,
                            'blocked': gpc0 > 0,
                            'repeat_offender': gpc1 > 2,
                            'offense_count': gpc1,
                            'request_rate': req_rate,
                            'error_rate': err_rate,
                            'connection_rate': conn_rate,
                            'threat_level': threat_level
                        })
                except (ValueError, IndexError):
                    continue

        # Sort by threat level
        threats.sort(key=lambda x: (x['offense_count'], x['error_rate'], x['request_rate']), reverse=True)

        return jsonify({
            'status': 'success',
            'total_tracked_ips': len(lines) - 1,
            'active_threats': len(threats),
            'threats': threats[:50]  # Limit to top 50
        })
    except Exception as e:
        log_operation('get_security_stats', False, str(e))
        return jsonify({'status': 'error', 'message': str(e)}), 500

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

        with open(combined_path, 'w') as combined:
            with open(cert_path, 'r') as cf:
                combined.write(cf.read())
            with open(key_path, 'r') as kf:
                combined.write(kf.read())

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

        # Add Haproxy Default Headers
        default_headers = template_env.get_template('hap_header.tpl').render()
        config_parts.append(default_headers)

        # Update blocked IPs map file first
        update_blocked_ips_map()
        
        # Add Listener Block
        listener_block = template_env.get_template('hap_listener.tpl').render(
            crt_path = SSL_CERTS_DIR
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
                logger.warning(f"Skipping domain {domain['domain']} - no backend name")
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
                logger.warning(f"Skipping wildcard domain {domain['domain']} - no backend name")
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
        # Write complete configuration to tmp
        temp_config_path = "/etc/haproxy/haproxy.cfg"

        config_content = '\n'.join(config_parts)
        logger.debug("Generated HAProxy configuration")

        # Write complete configuration to tmp
        # Write new configuration to file
        with open(HAPROXY_CONFIG_PATH, 'w') as f:
            f.write(config_content)
        
        # Use safe reload with validation and rollback
        success, message = reload_haproxy_safely()
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

def create_backup():
    """Create backup of current config and map files"""
    try:
        if os.path.exists(HAPROXY_CONFIG_PATH):
            shutil.copy2(HAPROXY_CONFIG_PATH, HAPROXY_BACKUP_PATH)
        if os.path.exists(BLOCKED_IPS_MAP_PATH):
            shutil.copy2(BLOCKED_IPS_MAP_PATH, BLOCKED_IPS_MAP_BACKUP_PATH)
        logger.info("Backups created successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        return False

def restore_backup():
    """Restore from backup files"""
    try:
        if os.path.exists(HAPROXY_BACKUP_PATH):
            shutil.copy2(HAPROXY_BACKUP_PATH, HAPROXY_CONFIG_PATH)
        if os.path.exists(BLOCKED_IPS_MAP_BACKUP_PATH):
            shutil.copy2(BLOCKED_IPS_MAP_BACKUP_PATH, BLOCKED_IPS_MAP_PATH)
        logger.info("Backups restored successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to restore backup: {e}")
        return False

def validate_haproxy_config():
    """Validate HAProxy configuration file"""
    try:
        result = subprocess.run(['haproxy', '-c', '-f', HAPROXY_CONFIG_PATH], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            logger.info("HAProxy configuration validation passed")
            return True, None
        else:
            error_msg = f"HAProxy configuration validation failed: {result.stderr}"
            logger.error(error_msg)
            return False, error_msg
    except Exception as e:
        error_msg = f"Error validating HAProxy config: {e}"
        logger.error(error_msg)
        return False, error_msg

def reload_haproxy_safely():
    """Safely reload HAProxy with validation and rollback"""
    try:
        # Create backup before changes
        if not create_backup():
            return False, "Failed to create backup"
        
        # Validate new configuration
        is_valid, error_msg = validate_haproxy_config()
        if not is_valid:
            # Restore backup on validation failure
            restore_backup()
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
                    return True, "HAProxy reloaded successfully"
                else:
                    # Reload failed, restore backup
                    restore_backup()
                    # Try to reload with backup config
                    subprocess.run('echo "reload" | socat stdio /tmp/haproxy-cli', 
                                 shell=True, capture_output=True)
                    error_msg = f"HAProxy reload failed: {reload_result.stderr}"
                    logger.error(error_msg)
                    return False, error_msg
            except Exception as e:
                # Critical error during reload, restore backup
                restore_backup()
                error_msg = f"Critical error during reload: {e}"
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
                return True, "HAProxy started successfully"
            except subprocess.CalledProcessError as e:
                # Start failed, restore backup
                restore_backup()
                error_msg = f"Failed to start HAProxy: {e.stderr}"
                logger.error(error_msg)
                return False, error_msg
    except Exception as e:
        error_msg = f"Critical error in reload process: {e}"
        logger.error(error_msg)
        return False, error_msg

def update_blocked_ips_map():
    """Update the blocked IPs map file from database"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT ip_address FROM blocked_ips ORDER BY ip_address')
            blocked_ips = [row[0] for row in cursor.fetchall()]

        # Write map file in HAProxy map format: <key> <value>
        # For IP blocking, we use: <ip_or_cidr> 1
        # This allows map_ip() to work with both single IPs and CIDR ranges
        os.makedirs(os.path.dirname(BLOCKED_IPS_MAP_PATH), exist_ok=True)
        with open(BLOCKED_IPS_MAP_PATH, 'w') as f:
            for ip in blocked_ips:
                f.write(f"{ip} 1\n")

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
