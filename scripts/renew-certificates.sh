#!/usr/bin/env bash

# Certificate Renewal Script for HAProxy Manager
# This script runs certbot renew and copies certificates to HAProxy format

# Configuration
LOG_FILE="${LOG_FILE:-/var/log/haproxy-manager.log}"
ERROR_LOG_FILE="${ERROR_LOG_FILE:-/var/log/haproxy-manager-errors.log}"
DB_FILE="${DB_FILE:-/etc/haproxy/haproxy_config.db}"
SSL_CERTS_DIR="${SSL_CERTS_DIR:-/etc/haproxy/certs}"
LETSENCRYPT_LIVE_DIR="${LETSENCRYPT_LIVE_DIR:-/etc/letsencrypt/live}"

# Logging functions
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$LOG_FILE" >> "$ERROR_LOG_FILE"
}

# Safe certificate publication helpers (cert_publish / cert_bundle_valid /
# haproxy_config_ok). Sourced AFTER the log_* functions above so the library
# uses this script's logging rather than its own fallbacks.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=cert-publish-lib.sh
if [ -r "${SCRIPT_DIR}/cert-publish-lib.sh" ]; then
    . "${SCRIPT_DIR}/cert-publish-lib.sh"
else
    log_error "Missing ${SCRIPT_DIR}/cert-publish-lib.sh - refusing to touch live certificates"
    exit 1
fi

log_info "Starting certificate renewal process"

# Run certbot renewal — don't exit on failure, some certs may have
# renewed successfully even if others failed (e.g., domain no longer
# pointed here). Continue to copy/combine whatever succeeded.
CERTBOT_OUTPUT=$(certbot renew --no-random-sleep-on-renew 2>&1)
CERTBOT_EXIT=$?

if [ $CERTBOT_EXIT -eq 0 ]; then
    log_info "Certbot renewal completed successfully"
else
    log_error "Certbot renewal had failures (exit code $CERTBOT_EXIT):"
    # Log the specific failures
    echo "$CERTBOT_OUTPUT" | grep -E "Failed to renew|failure" | while read -r line; do
        log_error "  $line"
    done
    log_info "Continuing to process successfully renewed certificates..."
fi

# Copy all certificates to HAProxy format
# Ensure SSL certs directory exists
mkdir -p "$SSL_CERTS_DIR"

# Get all SSL-enabled domains from database
DOMAINS=$(find "$LETSENCRYPT_LIVE_DIR/" -mindepth 1 -maxdepth 1 -type d -printf '%f\n')

if [ -z "$DOMAINS" ]; then
    log_info "No SSL-enabled domains found"
    exit 0
fi

# Copy certificates for each domain
UPDATED=0
FAILED=0

while read -r domain; do
    CERT_FILE="${LETSENCRYPT_LIVE_DIR}/${domain}/fullchain.pem"
    KEY_FILE="${LETSENCRYPT_LIVE_DIR}/${domain}/privkey.pem"
    COMBINED_FILE="${SSL_CERTS_DIR}/${domain}.pem"

    if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
        # Assemble in a staging dir and rename into place. NEVER redirect into
        # $COMBINED_FILE: the shell truncates the live pem before cat runs, and
        # HAProxy loads $SSL_CERTS_DIR as a directory, so one bad file there
        # takes down the whole ssl bind. See scripts/cert-publish-lib.sh.
        if cert_publish "$CERT_FILE" "$KEY_FILE" "$COMBINED_FILE"; then
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

log_info "Certificate update completed: $UPDATED updated, $FAILED failed"

# Reload HAProxy if any certificates were updated
if [ $UPDATED -gt 0 ]; then
    # Never reload onto unvalidated material: a reload that fails to load the
    # certs directory drops HTTPS for every site on this host.
    if ! haproxy_config_ok; then
        log_error "HAProxy configuration does not validate - refusing to reload after certificate renewal"
        exit 1
    fi

    if echo "reload" | socat stdio /tmp/haproxy-cli 2>/dev/null; then
        log_info "HAProxy reloaded successfully"
    else
        log_error "Failed to reload HAProxy"
        exit 1
    fi
fi

log_info "Certificate renewal process completed"
exit 0
