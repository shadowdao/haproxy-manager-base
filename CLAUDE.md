# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Testing
- **API Testing**: `./scripts/test-api.sh` - Tests all API endpoints with optional authentication
- **Certificate Request Testing**: `./scripts/test-certificate-request.sh` - Tests certificate generation endpoints
- **Manual Testing**: Run `curl` commands against `http://localhost:8000` endpoints as shown in README.md

### Running the Application
- **Docker Build**: `docker build -t haproxy-manager .`
- **Local Development**: `python haproxy_manager.py` (requires HAProxy, certbot, and dependencies installed)
- **Container Run**: See README.md for various docker run configurations

### Monitoring and Debugging
- **Error Monitoring**: `./scripts/monitor-errors.sh` - Monitor application error logs
- **External Monitoring**: `./scripts/monitor-errors-external.sh` - External monitoring script
- **Health Check**: `curl http://localhost:8000/health`
- **Log Files**: 
  - `/var/log/haproxy-manager.log` - General application logs
  - `/var/log/haproxy-manager-errors.log` - Error logs for alerting

## Architecture Overview

### Core Components

1. **haproxy_manager.py** - Main Flask application providing:
   - RESTful API for HAProxy configuration management
   - SQLite database integration for domain/backend storage
   - Let's Encrypt certificate automation
   - HAProxy configuration generation from Jinja2 templates
   - Optional API key authentication via `HAPROXY_API_KEY` environment variable

2. **Database Schema** - SQLite database with three main tables:
   - `domains` - Domain configurations with SSL settings
   - `backends` - Backend service definitions linked to domains  
   - `backend_servers` - Individual servers within backend groups

3. **Template System** - Jinja2 templates for HAProxy configuration generation:
   - `hap_header.tpl` - Global HAProxy settings, defaults, and HTTP/2 tuning
   - `hap_backend.tpl` - Backend server definitions
   - `hap_listener.tpl` - Frontend listener configurations with rate limiting
   - `hap_letsencrypt.tpl` - SSL certificate configurations
   - `hap_security_tables.tpl` - Stats frontend and security stick tables
   - Template override support for custom backend configurations

4. **Certificate Management** - Automated SSL certificate handling:
   - Let's Encrypt integration with certbot
   - Self-signed certificate fallback for development
   - Certificate renewal automation via cron
   - Certificate download endpoints for external services

### Configuration Flow

1. Domain added via `/api/domain` endpoint → Database updated
2. `generate_config()` function → Reads database, renders Jinja2 templates → Writes `/etc/haproxy/haproxy.cfg`
3. HAProxy reload via socket API (`/tmp/haproxy-cli`) or process restart
4. SSL certificate generation via Let's Encrypt or self-signed fallback

### Key Design Patterns

- **Template-driven configuration**: HAProxy config generated from modular Jinja2 templates
- **Database-backed state**: All configuration persisted in SQLite for reliability
- **API-first design**: All operations exposed via REST endpoints
- **Process monitoring**: Health checks and automatic HAProxy restart capabilities
- **Comprehensive logging**: Operation logging with error alerting support

### Authentication & Security

- Optional API key authentication controlled by `HAPROXY_API_KEY` environment variable
- All API endpoints (except `/health` and `/`) require Bearer token when API key is set
- Certificate private keys combined with certificates in HAProxy-compatible format
- Default backend page for unmatched domains instead of exposing HAProxy errors

### Rate Limiting & Connection Limits (hap_listener.tpl)

- **Stick table**: `type ip size 200k expire 10m` tracking `conn_cur`, `conn_rate(10s)`, `http_req_rate(10s)`, `http_err_rate(30s)`
- Tracks real client IP via `var(txn.real_ip)` to work correctly behind Cloudflare/proxies
- **Rate limit thresholds**:
  - Tarpit at 3000 req/10s (300 req/s)
  - Hard block (deny) at 5000 req/10s (500 req/s)
  - Connection rate limit: 500/10s
  - Concurrent connection limit: 500
  - Error rate limit: 100/30s
- **Whitelist bypasses** (exempt from rate limits):
  - `is_local` — RFC1918 private address ranges
  - `is_trusted_ip` — source IPs listed in `trusted_ips.list`
  - `is_whitelisted` — real IPs (from proxy headers) matched in `trusted_ips.map`

### Trusted IP Whitelist Files

- `trusted_ips.list` — Source IP whitelist for rate limit bypass (one CIDR/IP per line)
- `trusted_ips.map` — Real IP whitelist for proxy-header matching (format: `<IP> 1`)
- Both files are baked into the Docker image via `COPY` in the Dockerfile
- Currently contains phone system IP `127.0.0.1`

### Timeout Hardening (hap_header.tpl)

- `timeout http-request`: 300s -> 30s (slowloris protection)
- `timeout connect`: 120s -> 10s
- `timeout client`: 10m -> 5m
- `timeout http-keep-alive`: 120s -> 30s

### HTTP/2 Protection (hap_header.tpl)

- `tune.h2.fe.max-total-streams 2000` — limits total streams per HTTP/2 connection
- `tune.h2.fe.glitches-threshold 50` — CVE-2023-44487 Rapid Reset protection

### Stats Frontend (hap_security_tables.tpl)

- HAProxy stats page bound to `127.0.0.1:8404` (localhost only, accessible inside container)
- Template: `templates/hap_security_tables.tpl`

### Deployment Context

- Designed to run as Docker container with persistent volumes for certificates and configurations
- Exposes ports 80 (HTTP), 443 (HTTPS), and 8000 (management API/UI)
- Stats page on port 8404 (localhost only inside container)
- Management interface on port 8000 should be firewall-protected in production
- Dockerfile HEALTHCHECK verifies both port 8000 (Flask API) and port 80 (HAProxy), with `start-period=60s` and `timeout=10s`
- Supports deployment on servers with git directory at `/root/whp` and web file sync via rsync to `/docker/whp/web/`
- HAProxy is version 3.0.11