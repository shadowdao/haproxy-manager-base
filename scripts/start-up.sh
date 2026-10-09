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

# cloudflare_ips.list is SHIPPED DATA: it must always match what this image
# bakes in (/haproxy/defaults), so a Cloudflare range refresh actually reaches
# existing hosts instead of being permanently shadowed by the volume.
# Overwrite it from the baked copy on every start.
#
# trusted_proxies.list and wpadmin_gate_exempt.list are OPERATOR DATA:
# operators add entries directly on the server and those must survive
# restarts/recreates. Seed each from the baked copy only when it's missing;
# never overwrite an existing one.
#
# All branches fall back to an empty file if the baked default is somehow
# absent, because "acl ... -f <missing file>" is a fatal HAProxy config
# error -- the list files must exist unconditionally by the time HAProxy starts.
if [ -f /haproxy/defaults/cloudflare_ips.list ]; then
    cp /haproxy/defaults/cloudflare_ips.list /etc/haproxy/cloudflare_ips.list
else
    [ -f /etc/haproxy/cloudflare_ips.list ] || : > /etc/haproxy/cloudflare_ips.list
fi
if [ ! -f /etc/haproxy/trusted_proxies.list ]; then
    if [ -f /haproxy/defaults/trusted_proxies.list ]; then
        cp /haproxy/defaults/trusted_proxies.list /etc/haproxy/trusted_proxies.list
    else
        : > /etc/haproxy/trusted_proxies.list
    fi
fi
if [ ! -f /etc/haproxy/wpadmin_gate_exempt.list ]; then
    if [ -f /haproxy/defaults/wpadmin_gate_exempt.list ]; then
        cp /haproxy/defaults/wpadmin_gate_exempt.list /etc/haproxy/wpadmin_gate_exempt.list
    else
        : > /etc/haproxy/wpadmin_gate_exempt.list
    fi
fi

cron &

# Phase 1: container init
python /haproxy/scripts/init.py

# Phase 1.5: in-container haproxy supervisor.
# haproxy runs as a background child of PID 1 (gunicorn) with NOTHING watching
# it after init. If the haproxy master dies mid-life (e.g. SIGABRT -> exit 134,
# segfault), the container stays "up" (gunicorn is PID 1), Docker's --restart
# policy never fires, and haproxy is down until the external host watchdog
# full-restarts the whole container minutes later (dropping every connection).
# This loop revives haproxy in place within one interval. ensure_haproxy.py is
# idempotent — a cheap no-op whenever haproxy is already running.
HAPROXY_SUPERVISOR_INTERVAL="${HAPROXY_SUPERVISOR_INTERVAL:-15}"
(
    while true; do
        sleep "${HAPROXY_SUPERVISOR_INTERVAL}"
        python /haproxy/scripts/ensure_haproxy.py 2>&1 || true
    done
) &

# Phase 2: WSGI servers
# Tunable via env: HAPROXY_MGR_API_WORKERS (default 2), HAPROXY_MGR_API_TIMEOUT
# (default 120 — API can do slow ACME calls), HAPROXY_MGR_MAX_REQUESTS (default
# 1000 — worker recycle frequency).
#
# API_WORKERS default is 2 (was 1). A single worker is a single point of
# failure: if its gthread pool ever wedges (see the 2026-07-07 subprocess-hang
# incident — now bounded by DEFAULT_SUBPROCESS_TIMEOUT in haproxy_manager.py),
# the entire management API goes dark. A second worker keeps the API answering
# (config regenerate, health, SSL) while the other recycles via --max-requests.
API_WORKERS="${HAPROXY_MGR_API_WORKERS:-2}"
API_TIMEOUT="${HAPROXY_MGR_API_TIMEOUT:-120}"
MAX_REQ="${HAPROXY_MGR_MAX_REQUESTS:-1000}"
MAX_REQ_JITTER="${HAPROXY_MGR_MAX_REQUESTS_JITTER:-100}"

# Worker class (incident 2026-10-09): stock gthread makes every client socket
# fully blocking with NO timeout, so any peer that sends a few bytes and goes
# quiet (TLS hello on this plain-HTTP port, scanners -- :8000 is published on
# 0.0.0.0) pins a pool thread forever; 4 of them wedge a worker. Stock gthread
# also never reaps connections that send nothing (2x1000 of them wedge it
# permanently) and has no total header-read bound (slowloris). This subclass
# adds: a per-connection socket timeout (HAPROXY_MGR_CLIENT_TIMEOUT, 20s), a
# first-byte deadline (HAPROXY_MGR_FIRST_BYTE_TIMEOUT, 10s), a total
# request-line+headers deadline (HAPROXY_MGR_HEADER_DEADLINE, 10s), and a
# watchdog that exits a worker whose threads have ALL been stuck for
# HAPROXY_MGR_WEDGE_SECONDS (3600) so the master respawns it.
# See haproxy_gunicorn_worker.py. --timeout below does NOT cover any of these:
# for gthread it only watches the main thread's heartbeat.
WORKER_CLASS="haproxy_gunicorn_worker.TimeoutThreadWorker"

# Default page server on :8080. Stays in the background.
# --threads 4 lets one worker handle bursts of blocked-IP/default-page hits
# without forking. --max-requests recycles the worker to bound memory drift.
gunicorn \
    --bind 0.0.0.0:8080 \
    --workers 1 --threads 4 --worker-class "${WORKER_CLASS}" \
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
    --workers "${API_WORKERS}" --threads 4 --worker-class "${WORKER_CLASS}" \
    --max-requests "${MAX_REQ}" --max-requests-jitter "${MAX_REQ_JITTER}" \
    --timeout "${API_TIMEOUT}" \
    --access-logfile - --error-logfile - --log-level info \
    --pythonpath /haproxy \
    'haproxy_manager:app'
