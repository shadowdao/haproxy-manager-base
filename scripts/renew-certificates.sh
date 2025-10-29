#!/usr/bin/env bash

# Certificate Renewal Script for HAProxy Manager
# This script handles Let's Encrypt certificate renewal with proper logging and error handling

set -e

# Configuration
LOG_FILE="${LOG_FILE:-/var/log/haproxy-manager.log}"
ERROR_LOG_FILE="${ERROR_LOG_FILE:-/var/log/haproxy-manager-errors.log}"
HAPROXY_SOCKET="${HAPROXY_SOCKET:-/tmp/haproxy-cli}"
MAX_RETRIES=3
RETRY_DELAY=5

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE" >> "$ERROR_LOG_FILE"
}

log_warning() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $*" | tee -a "$LOG_FILE"
}

# Check if certbot is available
if ! command -v certbot &> /dev/null; then
    log_error "certbot command not found"
    exit 1
fi

# Check if HAProxy socket exists and is accessible
check_haproxy_socket() {
    if [ ! -S "$HAPROXY_SOCKET" ]; then
        log_warning "HAProxy socket not found at $HAPROXY_SOCKET"
        return 1
    fi

    # Test socket connectivity
    if ! echo "show info" | socat stdio "$HAPROXY_SOCKET" &> /dev/null; then
        log_warning "HAProxy socket exists but is not responding"
        return 1
    fi

    return 0
}

# Reload HAProxy configuration
reload_haproxy() {
    local retry_count=0

    while [ $retry_count -lt $MAX_RETRIES ]; do
        if check_haproxy_socket; then
            log_info "Reloading HAProxy via socket"
            if echo "reload" | socat stdio "$HAPROXY_SOCKET"; then
                log_info "HAProxy reloaded successfully"
                return 0
            else
                log_warning "HAProxy reload command failed (attempt $((retry_count + 1))/$MAX_RETRIES)"
            fi
        else
            log_warning "HAProxy socket check failed (attempt $((retry_count + 1))/$MAX_RETRIES)"
        fi

        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $MAX_RETRIES ]; then
            sleep $RETRY_DELAY
        fi
    done

    log_error "Failed to reload HAProxy after $MAX_RETRIES attempts"
    return 1
}

# Main renewal process
log_info "Starting certificate renewal process"

# Run certbot renewal
if certbot renew --quiet --no-random-sleep-on-renew 2>&1 | tee -a "$LOG_FILE"; then
    RENEWAL_EXIT_CODE=${PIPESTATUS[0]}

    if [ $RENEWAL_EXIT_CODE -eq 0 ]; then
        log_info "Certificate renewal completed successfully"

        # Check if any certificates were actually renewed
        if grep -q "Cert not yet due for renewal" "$LOG_FILE" 2>/dev/null; then
            log_info "No certificates needed renewal at this time"
        else
            log_info "Certificates were renewed, reloading HAProxy"
            if reload_haproxy; then
                log_info "Certificate renewal and HAProxy reload completed successfully"
            else
                log_error "Certificate renewal succeeded but HAProxy reload failed"
                exit 1
            fi
        fi
    else
        log_error "Certificate renewal failed with exit code $RENEWAL_EXIT_CODE"
        exit $RENEWAL_EXIT_CODE
    fi
else
    log_error "Certificate renewal command failed"
    exit 1
fi

log_info "Certificate renewal process completed"
exit 0
