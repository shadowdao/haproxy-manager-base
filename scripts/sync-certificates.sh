#!/usr/bin/env bash

# Certificate Sync Script for HAProxy Manager
# This script syncs all Let's Encrypt certificates to HAProxy format
# Use this to update all certificates regardless of renewal status

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

# Sync all certificate files for HAProxy
sync_all_certificates() {
    log_info "Syncing all certificate files to HAProxy format"

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
    local skipped_count=0

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
            skipped_count=$((skipped_count + 1))
            continue
        fi

        if [ ! -f "$letsencrypt_key" ]; then
            log_warning "Private key not found for $domain at $letsencrypt_key"
            skipped_count=$((skipped_count + 1))
            continue
        fi

        # Get modification times to check if update is needed
        local needs_update=false
        if [ ! -f "$cert_path" ]; then
            log_info "Combined certificate does not exist for $domain, creating it"
            needs_update=true
        else
            # Check if source files are newer than the combined file
            if [ "$letsencrypt_cert" -nt "$cert_path" ] || [ "$letsencrypt_key" -nt "$cert_path" ]; then
                log_info "Let's Encrypt certificate is newer than combined file for $domain"
                needs_update=true
            else
                log_info "Certificate for $domain is already up to date"
            fi
        fi

        # Combine certificate and key into single file for HAProxy
        if [ "$needs_update" = true ]; then
            if cat "$letsencrypt_cert" "$letsencrypt_key" > "$cert_path"; then
                log_info "Updated combined certificate for $domain at $cert_path"
                updated_count=$((updated_count + 1))
            else
                log_error "Failed to combine certificate files for $domain"
                error_count=$((error_count + 1))
            fi
        fi
    done <<< "$domains"

    log_info "Certificate sync completed: $updated_count updated, $skipped_count skipped, $error_count errors"

    if [ $error_count -gt 0 ]; then
        return 1
    fi

    # Return success if we updated any certificates
    if [ $updated_count -gt 0 ]; then
        return 0
    fi

    # Return special code (2) if nothing needed updating
    return 2
}

# Main sync process
log_info "Starting certificate sync process"

if sync_all_certificates; then
    SYNC_RESULT=$?

    if [ $SYNC_RESULT -eq 0 ]; then
        log_info "Certificates were updated, reloading HAProxy"
        if reload_haproxy; then
            log_info "Certificate sync and HAProxy reload completed successfully"
            exit 0
        else
            log_error "Certificate sync succeeded but HAProxy reload failed"
            exit 1
        fi
    elif [ $SYNC_RESULT -eq 2 ]; then
        log_info "All certificates are already up to date, no reload needed"
        exit 0
    fi
else
    SYNC_RESULT=$?

    if [ $SYNC_RESULT -eq 2 ]; then
        log_info "All certificates are already up to date, no reload needed"
        exit 0
    else
        log_error "Certificate sync failed"
        exit 1
    fi
fi

log_info "Certificate sync process completed"
exit 0
