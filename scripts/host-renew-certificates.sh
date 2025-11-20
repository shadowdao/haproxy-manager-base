#!/usr/bin/env bash

# Host-side Certificate Renewal Script
# Run this from the host machine via cron to trigger certificate renewal inside the container

set -e

# Configuration
CONTAINER_NAME="${CONTAINER_NAME:-haproxy-manager}"
LOG_FILE="${LOG_FILE:-/var/log/haproxy-manager-host-renewal.log}"

# Logging
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE"
}

log_info "Starting certificate renewal"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    log_error "Container '${CONTAINER_NAME}' is not running"
    exit 1
fi

# Run renewal script inside container
if docker exec "$CONTAINER_NAME" /haproxy/scripts/renew-certificates.sh; then
    log_info "Certificate renewal completed"
    exit 0
else
    log_error "Certificate renewal failed"
    exit 1
fi
