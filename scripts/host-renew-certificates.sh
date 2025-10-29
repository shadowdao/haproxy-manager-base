#!/usr/bin/env bash

# Host-side Certificate Renewal Script
# This script can be run from the host machine via cron to trigger certificate renewal
# inside the HAProxy Manager container using docker exec

set -e

# Configuration - Customize these values
CONTAINER_NAME="${CONTAINER_NAME:-haproxy-manager}"
LOG_FILE="${LOG_FILE:-/var/log/haproxy-manager-host-renewal.log}"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE"
}

# Main execution
log_info "Starting host-side certificate renewal process"

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    log_error "Container '${CONTAINER_NAME}' is not running"
    exit 1
fi

# Execute renewal script inside container
log_info "Executing renewal script in container '${CONTAINER_NAME}'"
if docker exec "$CONTAINER_NAME" /haproxy/scripts/renew-certificates.sh; then
    log_info "Certificate renewal completed successfully"
    exit 0
else
    log_error "Certificate renewal failed"
    exit 1
fi
