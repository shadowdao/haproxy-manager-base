# HAProxy Manager Base

A Flask-based API service for managing HAProxy configurations, domains, and SSL certificates.

To run the container:
```bash
docker run -d  -p 80:80 -p 443:443 -p 8000:8000 -v lets-encrypt:/etc/letsencrypt -v haproxy:/etc/haproxy --name haproxy-manager repo.anhonesthost.net/cloud-hosting-platform/haproxy-manager-base:latest
```

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

## Features

- Automatic HAProxy configuration generation
- Let's Encrypt SSL certificate integration
- Backend server management
- Self-signed certificate generation for development
- Health monitoring
- Database-backed configuration storage

## Requirements

- HAProxy
- Python 3.x
- Flask
- SQLite3
- Certbot (for Let's Encrypt certificates)
- OpenSSL (for self-signed certificates)
