#!/usr/bin/env bash

# Certificate Renewal Script for HAProxy Manager
# This script handles Let's Encrypt certificate renewal with proper logging and error handling

set -e

# Configuration
LOG_FILE="${LOG_FILE:-/var/log/haproxy-manager.log}"
ERROR_LOG_FILE="${ERROR_LOG_FILE:-/var/log/haproxy-manager-errors.log}"
HAPROXY_SOCKET="${HAPROXY_SOCKET:-/tmp/haproxy-cli}"
DB_FILE="${DB_FILE:-/etc/haproxy/haproxy_config.db}"
SSL_CERTS_DIR="${SSL_CERTS_DIR:-/etc/haproxy/certs}"
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

# Update combined certificate files for HAProxy
update_combined_certificates() {
    log_info "Updating combined certificate files for HAProxy"

    # Check if database exists
    if [ ! -f "$DB_FILE" ]; then
        log_error "Database file not found at $DB_FILE"
        return 1
    fi

    # Check if sqlite3 is available
    if ! command -v sqlite3 &> /dev/null; then
        log_error "sqlite3 command not found"
        return 1
    fi

    # Ensure SSL certs directory exists
    mkdir -p "$SSL_CERTS_DIR"

    # Get all domains with SSL enabled from database
    local domains
    domains=$(sqlite3 "$DB_FILE" "SELECT domain, ssl_cert_path FROM domains WHERE ssl_enabled = 1;" 2>/dev/null)

    if [ -z "$domains" ]; then
        log_info "No SSL-enabled domains found in database"
        return 0
    fi

    local updated_count=0
    local error_count=0

    # Process each domain
    while IFS='|' read -r domain cert_path; do
        if [ -z "$domain" ] || [ -z "$cert_path" ]; then
            continue
        fi

        log_info "Processing certificate for domain: $domain"

        local letsencrypt_cert="/etc/letsencrypt/live/${domain}/fullchain.pem"
        local letsencrypt_key="/etc/letsencrypt/live/${domain}/privkey.pem"

        # Check if Let's Encrypt certificate files exist
        if [ ! -f "$letsencrypt_cert" ]; then
            log_warning "Certificate not found for $domain at $letsencrypt_cert"
            error_count=$((error_count + 1))
            continue
        fi

        if [ ! -f "$letsencrypt_key" ]; then
            log_warning "Private key not found for $domain at $letsencrypt_key"
            error_count=$((error_count + 1))
            continue
        fi

        # Combine certificate and key into single file for HAProxy
        # HAProxy requires fullchain.pem followed by privkey.pem in a single file
        # Write to temp file first, then move to ensure atomic update
        local temp_cert="${cert_path}.tmp"
        if cat "$letsencrypt_cert" "$letsencrypt_key" > "$temp_cert"; then
            # Verify the combined file is not empty and contains valid data
            if [ -s "$temp_cert" ]; then
                # Atomically move to final location
                if mv "$temp_cert" "$cert_path"; then
                    log_info "Updated combined certificate for $domain at $cert_path"
                    updated_count=$((updated_count + 1))
                else
                    log_error "Failed to move combined certificate for $domain to $cert_path"
                    rm -f "$temp_cert"
                    error_count=$((error_count + 1))
                fi
            else
                log_error "Combined certificate file for $domain is empty"
                rm -f "$temp_cert"
                error_count=$((error_count + 1))
            fi
        else
            log_error "Failed to combine certificate files for $domain"
            rm -f "$temp_cert"
            error_count=$((error_count + 1))
        fi
    done <<< "$domains"

    log_info "Certificate update completed: $updated_count updated, $error_count errors"

    if [ $error_count -gt 0 ]; then
        return 1
    fi

    return 0
}

# Main renewal process
log_info "Starting certificate renewal process"

# Run certbot renewal
if certbot renew --quiet --no-random-sleep-on-renew 2>&1 | tee -a "$LOG_FILE"; then
    RENEWAL_EXIT_CODE=${PIPESTATUS[0]}

    if [ $RENEWAL_EXIT_CODE -eq 0 ]; then
        log_info "Certificate renewal completed successfully"

        # Always update combined certificate files after renewal
        # (certbot may have renewed some certificates even if the message says otherwise)
        log_info "Updating combined certificate files for HAProxy"
        if update_combined_certificates; then
            log_info "Combined certificates updated successfully"

            # Reload HAProxy to pick up the updated certificates
            log_info "Reloading HAProxy"
            if reload_haproxy; then
                log_info "Certificate renewal and HAProxy reload completed successfully"
            else
                log_error "Certificate renewal succeeded but HAProxy reload failed"
                exit 1
            fi
        else
            log_warning "Certificate update completed with some errors, but attempting HAProxy reload"
            # Still try to reload HAProxy even if some certificates failed
            if reload_haproxy; then
                log_warning "HAProxy reloaded successfully despite certificate update errors"
            else
                log_error "Certificate update had errors and HAProxy reload failed"
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
