#!/usr/bin/env bash

# Certificate Sync Script for HAProxy Manager
# This script syncs all Let's Encrypt certificates to HAProxy format without running certbot renew

set -e

# Configuration
LOG_FILE="${LOG_FILE:-/var/log/haproxy-manager.log}"
ERROR_LOG_FILE="${ERROR_LOG_FILE:-/var/log/haproxy-manager-errors.log}"
DB_FILE="${DB_FILE:-/etc/haproxy/haproxy_config.db}"
SSL_CERTS_DIR="${SSL_CERTS_DIR:-/etc/haproxy/certs}"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE" >> "$ERROR_LOG_FILE"
}

log_info "Starting certificate sync process"

# Check if database exists
if [ ! -f "$DB_FILE" ]; then
    log_error "Database file not found at $DB_FILE"
    exit 1
fi

# Ensure SSL certs directory exists
mkdir -p "$SSL_CERTS_DIR"

# Get all SSL-enabled domains from database
DOMAINS=$(sqlite3 "$DB_FILE" "SELECT domain FROM domains WHERE ssl_enabled = 1;" 2>/dev/null)

if [ -z "$DOMAINS" ]; then
    log_info "No SSL-enabled domains found"
    exit 0
fi

# Copy certificates for each domain
UPDATED=0
FAILED=0

while read -r domain; do
    CERT_FILE="/etc/letsencrypt/live/${domain}/fullchain.pem"
    KEY_FILE="/etc/letsencrypt/live/${domain}/privkey.pem"
    COMBINED_FILE="${SSL_CERTS_DIR}/${domain}.pem"

    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        # Combine cert and key into single file for HAProxy
        if cat "$CERT_FILE" "$KEY_FILE" > "$COMBINED_FILE"; then
            log_info "Updated certificate for $domain"
            UPDATED=$((UPDATED + 1))
        else
            log_error "Failed to combine certificate for $domain"
            FAILED=$((FAILED + 1))
        fi
    else
        log_error "Certificate files not found for $domain"
        FAILED=$((FAILED + 1))
    fi
done <<< "$DOMAINS"

log_info "Certificate sync completed: $UPDATED updated, $FAILED failed"

# Reload HAProxy if any certificates were updated
if [ $UPDATED -gt 0 ]; then
    if echo "reload" | socat stdio /tmp/haproxy-cli 2>/dev/null; then
        log_info "HAProxy reloaded successfully"
    else
        log_error "Failed to reload HAProxy"
        exit 1
    fi
fi

log_info "Certificate sync process completed"
exit 0
