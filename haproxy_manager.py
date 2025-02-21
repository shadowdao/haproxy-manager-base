import sqlite3
import os
from flask import Flask, request, jsonify
from pathlib import Path
import subprocess
import jinja2
import socket
import psutil

app = Flask(__name__)

DB_FILE = '/etc/haproxy/haproxy_config.db'
TEMPLATE_DIR = Path('templates')
HAPROXY_CONFIG_PATH = '/etc/haproxy/haproxy.cfg'
SSL_CERTS_DIR = '/etc/haproxy/certs'

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
        conn.commit()

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
def regenerate_conf():
    try:
        generate_config()
        return jsonify({'status': 'success'}), 200
    except Exception as e:
        return jsonify({
            'status': 'failed',
            'error': str(e)
        }), 500

@app.route('/api/domain', methods=['POST'])
def add_domain():
    data = request.get_json()
    domain = data.get('domain')
    template_override = data.get('template_override')
    backend_name = data.get('backend_name')
    servers = data.get('servers', [])

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Add domain
        cursor.execute('INSERT INTO domains (domain, template_override) VALUES (?, ?)', (domain, template_override))
        domain_id = cursor.lastrowid

        # Add backend
        cursor.execute('INSERT INTO backends (name, domain_id) VALUES (?, ?)',
                      (backend_name, domain_id))
        backend_id = cursor.lastrowid

        # Add servers
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
    return jsonify({'status': 'success', 'domain_id': domain_id})

@app.route('/api/ssl', methods=['POST'])
def request_ssl():
    data = request.get_json()
    domain = data.get('domain')

    # Request Let's Encrypt certificate
    result = subprocess.run([
        'certbot', 'certonly', '-n', '--standalone',
        '--preferred-challenges', 'http', '--http-01-port=8688',
        '-d', domain 
    ])

    if result.returncode == 0:
        # Combine cert files and copy to HAProxy certs directory
        cert_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
        key_path = f'/etc/letsencrypt/live/{domain}/privkey.pem'
        combined_path = f'{SSL_CERTS_DIR}/{domain}.pem'

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
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'message': 'Failed to obtain SSL certificate'})

@app.route('/api/domain', methods=['DELETE'])
def remove_domain():
    data = request.get_json()
    domain = data.get('domain')

    if not domain:
        return jsonify({'status': 'error', 'message': 'Domain is required'}), 400

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            
            # Get domain ID and check if it exists
            cursor.execute('SELECT id FROM domains WHERE domain = ?', (domain,))
            domain_result = cursor.fetchone()
            
            if not domain_result:
                return jsonify({'status': 'error', 'message': 'Domain not found'}), 404
                
            domain_id = domain_result[0]

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

            # Delete SSL certificate if it exists
            cursor.execute('SELECT ssl_cert_path FROM domains WHERE id = ? AND ssl_enabled = 1', (domain_id,))
            cert_result = cursor.fetchone()
            if cert_result and cert_result[0]:
                try:
                    os.remove(cert_result[0])
                except OSError:
                    pass  # Ignore errors if file doesn't exist

        # Regenerate HAProxy config
        generate_config()

        return jsonify({'status': 'success', 'message': 'Domain configuration removed'})

    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

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
                b.id as backend_id,
                b.name as backend_name
            FROM domains d
            LEFT JOIN backends b ON d.id = b.domain_id
        '''
        cursor.execute(query)

        # Fetch and immediately convert to list of dicts to avoid any cursor issues
        domains = [dict(domain) for domain in cursor.fetchall()]
        config_parts = []

        # Add Haproxy Default Headers
        default_headers = template_env.get_template('hap_header.tpl').render()
        config_parts.append(default_headers)

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
# Add domain configurations
        for domain in domains:
            if not domain['backend_name']:
                print(f"Skipping domain {domain['domain']} - no backend name")  # Debug log
                continue

            # Add domain ACL
            try:
                domain_acl = template_env.get_template('hap_subdomain_acl.tpl').render(
                    domain=domain['domain'],
                    name=domain['backend_name']
                )
                config_acls.append(domain_acl)
                print(f"Added ACL for domain: {domain['domain']}")  # Debug log
            except Exception as e:
                print(f"Error generating domain ACL for {domain['domain']}: {e}")
                continue

            # Add backend configuration
            try:
                cursor.execute('''
                    SELECT * FROM backend_servers WHERE backend_id = ?
                ''', (domain['backend_id'],))
                servers = [dict(server) for server in cursor.fetchall()]

                if not servers:
                    print(f"No servers found for backend {domain['backend_name']}")  # Debug log
                    continue

                if domain['template_override']:
                    backend_block = template_env.get_template(domain['template_override' + '.tpl']).render(
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
                print(f"Added backend block for: {domain['backend_name']}")  # Debug log
            except Exception as e:
                print(f"Error generating backend block for {domain['backend_name']}: {e}")
                continue
        
        # Add ACLS
        config_parts.append('\n' .join(config_acls))
        # Add LetsEncrypt Backend
        letsencrypt_backend = template_env.get_template('hap_letsencrypt_backend.tpl').render()
        config_parts.append(letsencrypt_backend)
        # Add Backends
        config_parts.append('\n' .join(config_backends) + '\n')
        # Write complete configuration to tmp 
        temp_config_path = "/etc/haproxy/haproxy.cfg"

        config_content = '\n'.join(config_parts)
        print("Final config content:", config_content)  # Debug log

        # Write complete configuration to tmp
        # Check HAProxy Configuration, and reload if it works
        with open(temp_config_path, 'w') as f:
            f.write(config_content)
        result = subprocess.run(['haproxy', '-c', '-f', temp_config_path], capture_output=True)
        if result.returncode == 0:
            print("HAProxy configuration check passed")
            if is_process_running('haproxy'):
                subprocess.run(['echo', '"reload"', '|', 'socat', 'stdio', '/tmp/haproxy-cli'])
            else:
                try:
                    result = subprocess.run(
                        ['haproxy', '-W', '-S', '/tmp/haproxy-cli,level,admin', '-f', HAPROXY_CONFIG_PATH],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    if result.returncode == 0:
                        print("HAProxy started successfully")
                    else:
                        print(f"HAProxy start command returned: {result.stdout}")
                        print(f"Error output: {result.stderr}")
                except subprocess.CalledProcessError as e:
                    print(f"Failed to start HAProxy: {e.stdout}\n{e.stderr}")
                    raise
    except Exception as e:
        print(f"Error generating config: {e}")
        import traceback
        traceback.print_exc()
        raise

def start_haproxy():
    if not is_process_running('haproxy'):
        try:
            result = subprocess.run(
                ['haproxy', '-W', '-S', '/tmp/haproxy-cli,level,admin', '-f', HAPROXY_CONFIG_PATH],
                check=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print("HAProxy started successfully")
            else:
                print(f"HAProxy start command returned: {result.stdout}")
                print(f"Error output: {result.stderr}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to start HAProxy: {e.stdout}\n{e.stderr}")
            raise

if __name__ == '__main__':
    init_db()
    certbot_register()
    generate_self_signed_cert(SSL_CERTS_DIR)
    start_haproxy()
    certbot_register()
    app.run(host='0.0.0.0', port=8000)
