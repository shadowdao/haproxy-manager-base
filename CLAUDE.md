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
   - `hap_header.tpl` - Global HAProxy settings and defaults
   - `hap_backend.tpl` - Backend server definitions
   - `hap_listener.tpl` - Frontend listener configurations
   - `hap_letsencrypt.tpl` - SSL certificate configurations
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

### Deployment Context

- Designed to run as Docker container with persistent volumes for certificates and configurations
- Exposes ports 80 (HTTP), 443 (HTTPS), and 8000 (management API/UI)
- Management interface on port 8000 should be firewall-protected in production
- Supports deployment on servers with git directory at `/root/whp` and web file sync via rsync to `/docker/whp/web/`