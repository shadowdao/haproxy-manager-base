# HAProxy Manager

A Flask-based API service for managing HAProxy configurations, domains, and SSL certificates.
A Flask-based API service for managing HAProxy configurations with dynamic SSL certificate management and health monitoring.

To run the container:
```bash
docker run -d  -p 80:80 -p 443:443 -p 8000:8000 -v lets-encrypt:/etc/letsencrypt -v haproxy:/etc/haproxy --name haproxy-manager repo.anhonesthost.net/cloud-hosting-platform/haproxy-manager-base:latest
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

### Add Domain
Add a new domain with backend servers configuration.

```bash
POST /api/domain
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
