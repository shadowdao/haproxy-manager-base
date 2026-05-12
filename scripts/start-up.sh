#!/usr/bin/env bash
# Container entrypoint. Two-phase startup:
#   1. One-shot init (init.py): DB schema, certbot register, config gen, start HAProxy.
#      Runs synchronously and to completion so haproxy is up before the API binds.
#   2. WSGI serving via gunicorn (replacing the Flask dev server). Two gunicorn
#      instances:
#        - port 8080 -> default_app  (default page + blocked-ip page; HAProxy
#          proxies unmatched / blocked traffic here)
#        - port 8000 -> app          (management API)
#
# Why gunicorn:
#   Flask's built-in werkzeug "development server" is single-threaded and leaks
#   workers under sustained load. It carried haproxy-manager for a long time but
#   stalled out around 24-48h uptime ("healthy" health-check, but every request
#   queued behind a stuck worker). Gunicorn with --max-requests cycles workers
#   periodically, which prevents the slow-leak failure mode entirely.

set -eo pipefail

# Ensure trusted IP whitelist files exist (volume-mounted /etc/haproxy may shadow image defaults)
mkdir -p /etc/haproxy
[ -f /etc/haproxy/trusted_ips.list ] || : > /etc/haproxy/trusted_ips.list
[ -f /etc/haproxy/trusted_ips.map ]  || : > /etc/haproxy/trusted_ips.map

cron &

# Phase 1: container init
python /haproxy/scripts/init.py

# Phase 2: WSGI servers
# Tunable via env: HAPROXY_MGR_API_WORKERS (default 1), HAPROXY_MGR_API_TIMEOUT
# (default 120 — API can do slow ACME calls), HAPROXY_MGR_MAX_REQUESTS (default
# 1000 — worker recycle frequency).
API_WORKERS="${HAPROXY_MGR_API_WORKERS:-1}"
API_TIMEOUT="${HAPROXY_MGR_API_TIMEOUT:-120}"
MAX_REQ="${HAPROXY_MGR_MAX_REQUESTS:-1000}"
MAX_REQ_JITTER="${HAPROXY_MGR_MAX_REQUESTS_JITTER:-100}"

# Default page server on :8080. Stays in the background.
# --threads 4 lets one worker handle bursts of blocked-IP/default-page hits
# without forking. --max-requests recycles the worker to bound memory drift.
gunicorn \
    --bind 0.0.0.0:8080 \
    --workers 1 --threads 4 --worker-class gthread \
    --max-requests "${MAX_REQ}" --max-requests-jitter "${MAX_REQ_JITTER}" \
    --timeout 30 \
    --access-logfile - --error-logfile - --log-level info \
    --pythonpath /haproxy \
    'haproxy_manager:default_app' &

# Main API server on :8000 in the foreground. exec so signals propagate
# correctly and the container exits if the API dies (docker --restart picks it
# up). Longer --timeout because cert issuance hits ACME and can take a while.
exec gunicorn \
    --bind 0.0.0.0:8000 \
    --workers "${API_WORKERS}" --threads 4 --worker-class gthread \
    --max-requests "${MAX_REQ}" --max-requests-jitter "${MAX_REQ_JITTER}" \
    --timeout "${API_TIMEOUT}" \
    --access-logfile - --error-logfile - --log-level info \
    --pythonpath /haproxy \
    'haproxy_manager:app'
