# HAProxy Manager

A Flask-based API service for managing HAProxy configurations, domains, and SSL certificates.
A Flask-based API service for managing HAProxy configurations with dynamic SSL certificate management and health monitoring.

To run the container:
```bash
# Without API key authentication (default)
docker run -d -p 80:80 -p 443:443 -p 8000:8000 -v lets-encrypt:/etc/letsencrypt -v haproxy:/etc/haproxy --name haproxy-manager your-registry.example.com/cloud-hosting-platform/haproxy-manager-base:latest

# With API key authentication (recommended for production)
docker run -d -p 80:80 -p 443:443 -p 8000:8000 -v lets-encrypt:/etc/letsencrypt -v haproxy:/etc/haproxy -e HAPROXY_API_KEY=your-secure-api-key-here --name haproxy-manager your-registry.example.com/cloud-hosting-platform/haproxy-manager-base:latest
```

## Features

- RESTful API for HAProxy configuration management
- Database-backed configuration storage using SQLite
- Automatic HAProxy configuration generation from templates
- Let's Encrypt SSL certificate integration with auto-renewal
- Health monitoring endpoint
- Dynamic backend server management
- Template override support for custom backend configurations
- Process monitoring and auto-restart capabilities
- Socket-based HAProxy runtime API integration
- **NEW**: API key authentication for secure access
- **NEW**: Certificate renewal API endpoint
- **NEW**: Certificate download endpoints for other services
- **NEW**: Comprehensive error logging and alerting system
- **NEW**: Certificate status monitoring with expiration dates
- **NEW**: Default backend page for unmatched domains

## Security

### API Key Authentication

When the `HAPROXY_API_KEY` environment variable is set, all API endpoints (except `/health` and `/`) require authentication using a Bearer token:

```bash
# Example API call with authentication
curl -H "Authorization: Bearer your-secure-api-key-here" \
     http://localhost:8000/api/domains
```

If no API key is set, the service runs without authentication (useful for development).

## Requirements

- HAProxy
- Python 3.x
- Flask
- SQLite3
- Certbot (for Let's Encrypt certificates)
- OpenSSL (for self-signed start-up certificate)

## Web UI Interface

The HAProxy Manager includes a web-based user interface accessible at port 8000, providing:
- Domain and backend server management interface
- SSL certificate status monitoring

__Do Not Expose port 8000 to the open internet__
If you need to have it exposed to the internet, restrict it to an IP Address via IPTABLES or other firewalls.
```bash
# Allow access from the specific IP address (replace 192.168.1.100 with your IP)
iptables -A INPUT -p tcp --dport 8000 -s {YOUR_PUBLIC_IP} -j ACCEPT

# Drop all other connections to port 8000
iptables -A INPUT -p tcp --dport 8000 -j DROP
```
If you need to be able to access the web interface from multiple locations, I recommend putting it behind an authenticated Proxy like Authentik

## API Endpoints

### Health Check
Check the status of the HAProxy Manager service.

```bash
GET /health

# Response
{
    "status": "healthy",
    "haproxy_status": "running",
    "database": "connected"
}
```

### Get Domains
Retrieve all configured domains and their backend information.

```bash
GET /api/domains
Authorization: Bearer your-api-key

# Response
[
    {
        "id": 1,
        "domain": "example.com",
        "ssl_enabled": 1,
        "ssl_cert_path": "/etc/haproxy/certs/example.com.pem",
        "template_override": null,
        "backend_name": "example_backend"
    }
]
```

### Add Domain
Add a new domain with backend servers configuration.

```bash
POST /api/domain
Authorization: Bearer your-api-key
Content-Type: application/json

{
    "domain": "example.com",
    "backend_name": "example_backend",
    "template_override": null,
    "servers": [
        {
            "name": "server1",
            "address": "10.0.0.1",
            "port": 8080,
            "options": "check"
        },
        {
            "name": "server2",
            "address": "10.0.0.2",
            "port": 8080,
            "options": "check backup"
        }
    ]
}

# Response
{
    "status": "success",
    "domain_id": 1
}
```

### Enable SSL
Request and configure SSL certificate for a domain using Let's Encrypt.

```bash
POST /api/ssl
Authorization: Bearer your-api-key
Content-Type: application/json

{
    "domain": "example.com"
}

# Response
{
    "status": "success"
}
```

### Remove Domain
Remove a domain and its associated backend configuration.

```bash
DELETE /api/domain
Authorization: Bearer your-api-key
Content-Type: application/json

{
    "domain": "example.com"
}

# Response
{
    "status": "success",
    "message": "Domain configuration removed"
}
```

### Regenerate Configuration
Regenerate HAProxy configuration from database.

```bash
GET /api/regenerate
Authorization: Bearer your-api-key

# Response
{
    "status": "success"
}
```

### Reload HAProxy
Reload HAProxy configuration without restart.

```bash
GET /api/reload
Authorization: Bearer your-api-key

# Response
{
    "status": "success"
}
```

## New Certificate Management Endpoints

### Request Certificate Generation
Request certificate generation for one or more domains.

```bash
POST /api/certificates/request
Authorization: Bearer your-api-key
Content-Type: application/json

{
    "domains": ["example.com", "api.example.com"],
    "force_renewal": false,
    "include_www": true
}

# Response
{
    "status": "completed",
    "summary": {
        "total": 2,
        "successful": 2,
        "failed": 0
    },
    "results": [
        {
            "domain": "example.com",
            "status": "success",
            "message": "Certificate obtained successfully",
            "cert_path": "/etc/haproxy/certs/example.com.pem",
            "domains_covered": ["example.com", "www.example.com"]
        },
        {
            "domain": "api.example.com",
            "status": "success",
            "message": "Certificate obtained successfully",
            "cert_path": "/etc/haproxy/certs/api.example.com.pem",
            "domains_covered": ["api.example.com"]
        }
    ]
}
```

### Renew All Certificates
Trigger renewal of all Let's Encrypt certificates and reload HAProxy.

```bash
POST /api/certificates/renew
Authorization: Bearer your-api-key

# Response
{
    "status": "success",
    "message": "Certificates renewed and HAProxy reloaded"
}
```

### Get Certificate Status
Get status of all certificates including expiration dates.

```bash
GET /api/certificates/status
Authorization: Bearer your-api-key

# Response
{
    "certificates": [
        {
            "domain": "example.com",
            "ssl_enabled": true,
            "cert_path": "/etc/haproxy/certs/example.com.pem",
            "expires": "2024-12-31T23:59:59",
            "days_until_expiry": 45
        }
    ]
}
```

### Download Certificate Files
Download certificate files for use by other services.

```bash
# Download combined certificate (cert + key)
GET /api/certificates/example.com/download
Authorization: Bearer your-api-key

# Download private key only
GET /api/certificates/example.com/key
Authorization: Bearer your-api-key

# Download certificate only (no private key)
GET /api/certificates/example.com/cert
Authorization: Bearer your-api-key
```

## Certificate Renewal

The HAProxy Manager includes automatic certificate renewal with multiple scheduling options:

### Automatic Renewal (Container-based)
By default, a cron job runs inside the container every 12 hours to check and renew certificates:
- Runs at minute 0 of every 12th hour (12:00 AM, 12:00 PM)
- Automatically reloads HAProxy if certificates are renewed
- Logs all renewal attempts to `/var/log/haproxy-manager.log`
- Errors logged to `/var/log/haproxy-manager-errors.log`

### Manual Renewal via API
Trigger certificate renewal manually using the API:
```bash
curl -X POST http://localhost:8000/api/certificates/renew \
  -H "Authorization: Bearer your-api-key"
```

### Host-side Renewal (Recommended for Production)
For more control over scheduling, run renewals from the host machine using the provided script:

```bash
# Make the script executable
chmod +x scripts/host-renew-certificates.sh

# Add to host crontab (edit with: crontab -e)
0 */12 * * * /path/to/haproxy-manager-base/scripts/host-renew-certificates.sh

# Or run manually
./scripts/host-renew-certificates.sh
```

The host-side script:
- Executes the renewal process inside the running container
- Maintains separate host-side logs at `/var/log/haproxy-manager-host-renewal.log`
- Automatically detects if the container is running
- Supports custom container names via `CONTAINER_NAME` environment variable

See [scripts/host-crontab-example.txt](scripts/host-crontab-example.txt) for more crontab configuration examples.

### Renewal Script Features
The renewal script ([scripts/renew-certificates.sh](scripts/renew-certificates.sh)) includes:
- Comprehensive logging with timestamps
- Retry logic for HAProxy reload (3 attempts with 5-second delays)
- HAProxy socket health checks before reload
- Proper error handling and exit codes
- Detection of whether certificates actually needed renewal

## Logging and Monitoring

The HAProxy Manager includes comprehensive logging and error tracking:

### Log Files
- `/var/log/haproxy-manager.log` - General application logs
- `/var/log/haproxy-manager-errors.log` - Error logs for alerting
- `/var/log/haproxy-manager-host-renewal.log` - Host-side renewal logs (when using host script)

### Logged Operations
All API operations are logged with timestamps and success/failure status:
- Domain management (add/remove)
- SSL certificate operations
- Configuration generation
- HAProxy reload/restart operations
- Certificate renewals

### Error Alerting
Failed operations are logged to the error log file. You can monitor this file for alerting:
```bash
# Monitor error log for alerting
tail -f /var/log/haproxy-manager-errors.log
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HAPROXY_API_KEY` | API key for authentication (optional) | None (no auth) |
| `HAPROXY_DEFAULT_PAGE_TITLE` | Title for the default page | Site Not Configured |
| `HAPROXY_DEFAULT_MAIN_MESSAGE` | Main message on the default page | This domain has not been configured yet. Please contact your system administrator to set up this website. |
| `HAPROXY_DEFAULT_SECONDARY_MESSAGE` | Secondary message on the default page | If you believe this is an error, please check the domain name and try again. |

## Default Backend Configuration

When a domain is accessed that hasn't been configured in HAProxy, the system will serve a default page instead of showing an error. This default page:

- Informs visitors that the site is not configured
- Displays the domain name and current timestamp
- Is fully customizable through environment variables

### Customizing the Default Page

You can customize the default page by setting environment variables:

```bash
docker run -d \
  -p 80:80 -p 443:443 -p 8000:8000 \
  -v lets-encrypt:/etc/letsencrypt \
  -v haproxy:/etc/haproxy \
  -e HAPROXY_API_KEY=your-secure-api-key-here \
  -e HAPROXY_DEFAULT_PAGE_TITLE="Website Coming Soon" \
  -e HAPROXY_DEFAULT_MAIN_MESSAGE="This website is currently under construction and will be available soon." \
  -e HAPROXY_DEFAULT_SECONDARY_MESSAGE="Please check back later or contact us for more information." \
  --name haproxy-manager \
  your-registry.example.com/cloud-hosting-platform/haproxy-manager-base:latest
```

## Example Usage

### Setting up with API key authentication:
```bash
# Start container with API key
docker run -d \
  -p 80:80 -p 443:443 -p 8000:8000 \
  -v lets-encrypt:/etc/letsencrypt \
  -v haproxy:/etc/haproxy \
  -e HAPROXY_API_KEY=your-secure-api-key-here \
  --name haproxy-manager \
  your-registry.example.com/cloud-hosting-platform/haproxy-manager-base:latest

# Add a domain
curl -X POST http://localhost:8000/api/domain \
  -H "Authorization: Bearer your-secure-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "backend_name": "example_backend",
    "servers": [
      {"name": "server1", "address": "10.0.0.1", "port": 8080, "options": "check"}
    ]
  }'

# Request SSL certificate
curl -X POST http://localhost:8000/api/ssl \
  -H "Authorization: Bearer your-secure-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Renew certificates
curl -X POST http://localhost:8000/api/certificates/renew \
  -H "Authorization: Bearer your-secure-api-key-here"

# Request certificate generation for another service
curl -X POST http://localhost:8000/api/certificates/request \
  -H "Authorization: Bearer your-secure-api-key-here" \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["api.example.com"],
    "force_renewal": false,
    "include_www": false
  }'

# Download certificate for another service
curl -H "Authorization: Bearer your-secure-api-key-here" \
  http://localhost:8000/api/certificates/example.com/download \
  -o example.com.pem
```
