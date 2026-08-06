# shellcheck shell=bash
# cert-publish-lib.sh - safe publication of HAProxy certificate bundles.
#
# This file is SOURCED, never executed (hence no shebang / no exec bit).
#
# Why this exists
# ---------------
# renew-certificates.sh and sync-certificates.sh used to publish a bundle with
#
#     cat "$CERT_FILE" "$KEY_FILE" > "$COMBINED_FILE"
#
# where $COMBINED_FILE is the LIVE pem HAProxy is serving right now. The shell
# truncates the destination to zero bytes when it sets up the redirect, BEFORE
# cat ever runs, so any failure after that point (unreadable source, ENOSPC,
# container killed mid-write) leaves a zero-length or key-less pem in place.
# Checking cat's exit status does not help: the damage is already done.
#
# That matters more here than for an ordinary file because HAProxy loads
# $SSL_CERTS_DIR as a DIRECTORY:
#
#     bind 0.0.0.0:443 ssl crt /etc/haproxy/certs
#
# It tries to load *every* file in that directory, and one unloadable file
# fails the whole bind - i.e. HTTPS goes down for every customer on the host.
#
# Two consequences drive the design below:
#   1. Assemble somewhere else and rename into place, so the live pem is either
#      the old bundle or the new one and never a half-written one.
#   2. NEVER create a temp file, .tmp, .backup or any other non-final file
#      inside $SSL_CERTS_DIR. Staging and backups live in SIBLING directories.
#
# Directory layout (kept identical to the Python half in haproxy_manager.py):
#   staging: $(dirname $SSL_CERTS_DIR)/cert-staging   [$CERT_STAGING_DIR]
#   backups: $(dirname $SSL_CERTS_DIR)/cert-backups   [$CERT_BACKUP_DIR]
# Both siblings of the certs dir, so they are on the same filesystem and the
# final mv is a rename(2) - atomic. If the mv ever fails (EXDEV because someone
# mounted the certs dir separately, permissions, ...) we FAIL LOUDLY and leave
# the live pem alone. There is deliberately no "just write it directly" path.

# Logging: the callers define their own log_info/log_error. Only provide
# fallbacks so this library is usable standalone (e.g. from a test or a shell).
declare -F log_info >/dev/null || log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $*"
}
declare -F log_error >/dev/null || log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" >&2
}
# log_warn is not part of the callers' vocabulary; route it through log_info
# with a loud prefix so it lands in the main log without tripping the
# error-log monitors (scripts/monitor-errors.sh) for non-fatal conditions.
declare -F log_warn >/dev/null || log_warn() {
    log_info "WARNING: $*"
}

cert_staging_dir() {
    if [ -n "${CERT_STAGING_DIR:-}" ]; then
        echo "$CERT_STAGING_DIR"
    else
        echo "$(dirname "${SSL_CERTS_DIR:-/etc/haproxy/certs}")/cert-staging"
    fi
}

cert_backup_dir() {
    if [ -n "${CERT_BACKUP_DIR:-}" ]; then
        echo "$CERT_BACKUP_DIR"
    else
        echo "$(dirname "${SSL_CERTS_DIR:-/etc/haproxy/certs}")/cert-backups"
    fi
}

# cert_bundle_valid FILE
#
# Returns 0 if FILE is publishable as an HAProxy pem bundle.
#
# Layer 1 (MANDATORY, pure shell/grep, always available): structural checks.
#         A missing or failed structural check is a HARD FAIL. This layer is
#         what actually covers the truncation / partial-write / key-less
#         failure modes this library exists to prevent.
# Layer 2 (BEST EFFORT): cryptographic pairing via the openssl CLI.
#         If openssl runs and says the cert and key do not match, that is a
#         HARD FAIL. If the openssl BINARY IS ABSENT we log a loud warning and
#         accept the bundle on the structural checks alone.
#
#         Rationale for not hard-failing on a missing checker: the container
#         image (see Dockerfile) installs haproxy, certbot and socat, but not
#         necessarily the openssl CLI. Refusing to publish when the checker is
#         missing would stall every renewal fleet-wide and let certificates
#         expire - a guaranteed outage - which is strictly worse than the risk
#         it prevents, since a mismatched pair can only arise from a
#         mis-assembled source tree, whereas the truncation modes we are
#         actually defending against are fully covered by layer 1.
cert_bundle_valid() {
    local file="$1"

    if [ -z "$file" ]; then
        log_error "cert_bundle_valid: no file given"
        return 1
    fi
    if [ ! -f "$file" ]; then
        log_error "Certificate bundle $file does not exist (or is not a regular file)"
        return 1
    fi
    if [ ! -s "$file" ]; then
        log_error "Certificate bundle $file is empty"
        return 1
    fi

    # --- layer 1: structure -------------------------------------------------
    if ! grep -qF -- '-----BEGIN CERTIFICATE-----' "$file"; then
        log_error "Certificate bundle $file contains no certificate block"
        return 1
    fi
    if ! grep -qF -- '-----END CERTIFICATE-----' "$file"; then
        log_error "Certificate bundle $file has an unterminated certificate block (truncated?)"
        return 1
    fi

    local key_begin key_end
    key_begin="$(grep -m1 -oE -- '-----BEGIN (RSA |EC )?PRIVATE KEY-----' "$file")"
    if [ -z "$key_begin" ]; then
        log_error "Certificate bundle $file contains no private key block"
        return 1
    fi
    key_end="${key_begin/BEGIN/END}"
    if ! grep -qF -- "$key_end" "$file"; then
        log_error "Certificate bundle $file has an unterminated private key block (truncated?)"
        return 1
    fi

    # --- layer 2: cert/key pairing ------------------------------------------
    if ! command -v openssl >/dev/null 2>&1; then
        # Once per process: this fires per domain otherwise, and a renewal run
        # walks every certificate on the host.
        if [ -z "${_CERT_OPENSSL_WARNED:-}" ]; then
            _CERT_OPENSSL_WARNED=1
            log_warn "openssl binary not found - SKIPPING the cert/key pairing check" \
                     "(openssl x509 -pubkey vs openssl pkey -pubout);" \
                     "certificate bundles are being published on structural checks alone"
        fi
        return 0
    fi

    local cert_pub key_pub
    # </dev/null on both: openssl pkey prompts for a passphrase on an encrypted
    # key, and a prompt in a cron job is a hang, not an error.
    if ! cert_pub="$(openssl x509 -in "$file" -noout -pubkey 2>/dev/null </dev/null)" \
       || [ -z "$cert_pub" ]; then
        log_error "Certificate bundle $file: openssl could not read the certificate"
        return 1
    fi
    if ! key_pub="$(openssl pkey -in "$file" -pubout -passin pass: 2>/dev/null </dev/null)" \
       || [ -z "$key_pub" ]; then
        log_error "Certificate bundle $file: openssl could not read the private key"
        return 1
    fi
    if [ "$cert_pub" != "$key_pub" ]; then
        log_error "Certificate bundle $file: private key does not match the certificate"
        return 1
    fi

    return 0
}

# cert_publish CERT_FILE KEY_FILE DEST_FILE
#
# Assemble CERT_FILE + KEY_FILE into DEST_FILE without ever exposing a
# partially written DEST_FILE to HAProxy. Returns 0 on success.
#
# On ANY failure DEST_FILE is left exactly as it was.
cert_publish() {
    if [ $# -ne 3 ]; then
        log_error "cert_publish: expected 3 arguments (cert key dest), got $#"
        return 1
    fi

    local cert_file="$1" key_file="$2" dest_file="$3"
    local staging_dir backup_dir tmp base

    # (a) sources must exist and be non-empty before we touch anything.
    if [ ! -s "$cert_file" ]; then
        log_error "cert_publish: certificate $cert_file is missing or empty"
        return 1
    fi
    if [ ! -s "$key_file" ]; then
        log_error "cert_publish: private key $key_file is missing or empty"
        return 1
    fi

    # (b) assemble in the staging dir - NOT in the certs dir, which HAProxy
    #     scans wholesale.
    staging_dir="$(cert_staging_dir)"
    if ! mkdir -p "$staging_dir"; then
        log_error "cert_publish: cannot create staging directory $staging_dir"
        return 1
    fi
    # Sweep temps orphaned by a kill -9 / OOM in an earlier run. Restricted to
    # the mktemp suffix shape inside our own staging dir.
    find "$staging_dir" -maxdepth 1 -type f -name '*.??????' -mmin +1440 -delete 2>/dev/null

    base="$(basename "$dest_file")"
    tmp="$(mktemp "${staging_dir}/${base}.XXXXXX" 2>/dev/null)"
    if [ -z "$tmp" ] || [ ! -f "$tmp" ]; then
        log_error "cert_publish: cannot create a staging file in $staging_dir"
        return 1
    fi
    # 0600 while the temp file holds a private key; the final mode is matched
    # to the file being replaced just before the swap (see below).
    chmod 600 "$tmp" 2>/dev/null

    if ! cat "$cert_file" "$key_file" > "$tmp"; then
        log_error "cert_publish: failed to assemble $cert_file + $key_file (live $dest_file left untouched)"
        rm -f "$tmp"
        return 1
    fi
    if [ ! -s "$tmp" ]; then
        log_error "cert_publish: assembled bundle for $dest_file is empty (live file left untouched)"
        rm -f "$tmp"
        return 1
    fi

    # (c) never promote something HAProxy would choke on.
    if ! cert_bundle_valid "$tmp"; then
        log_error "cert_publish: assembled bundle for $dest_file failed validation (live file left untouched)"
        rm -f "$tmp"
        return 1
    fi

    # (d) back up the bundle we are about to replace - but only if it is itself
    #     valid. Overwriting a good backup with garbage would turn "restore the
    #     backup" into "restore a different broken file". Same semantics as
    #     create_backup(require_valid=True) in haproxy_manager.py.
    if [ -e "$dest_file" ]; then
        backup_dir="$(cert_backup_dir)"
        if cert_bundle_valid "$dest_file"; then
            if mkdir -p "$backup_dir"; then
                if ! cp -p "$dest_file" "${backup_dir}/${base}"; then
                    log_warn "could not back up $dest_file to ${backup_dir}/${base}; publishing anyway"
                fi
            else
                log_warn "could not create backup directory $backup_dir; publishing without a backup"
            fi
        else
            log_warn "existing $dest_file is not a valid bundle - KEEPING the previous backup" \
                     "in $backup_dir rather than overwriting it with an unusable one"
        fi
    fi

    # Preserve the mode of the bundle being replaced (0644 by default, which is
    # what `cat > file` produced under the standard umask). mktemp gives 0600,
    # and mv carries the temp file's mode onto the destination, so without this
    # every publish would silently tighten the live pem's permissions. Changing
    # who can read these files is not something a write-safety fix should do as
    # a side effect - and it must match write_config_atomically() on the Python
    # side, which preserves the mode the same way.
    local mode
    mode="$(stat -c '%a' "$dest_file" 2>/dev/null)"
    [ -n "$mode" ] || mode=644
    chmod "$mode" "$tmp" 2>/dev/null

    # (e) atomic swap. Same filesystem by construction; if it still fails,
    #     stop - do not fall back to writing into the certs dir.
    if ! mv -f "$tmp" "$dest_file"; then
        log_error "cert_publish: failed to move $tmp into place as $dest_file" \
                  "(live file left untouched; NOT falling back to a direct write)"
        rm -f "$tmp"
        return 1
    fi

    return 0
}

# haproxy_config_ok
#
# Gate a reload on `haproxy -c`. Returns 0 if the config validates, or if we
# cannot check (no haproxy binary) - a missing checker must not block a reload
# that is otherwise needed, but a checker that says "no" always wins.
haproxy_config_ok() {
    local cfg="${HAPROXY_CONFIG:-/etc/haproxy/haproxy.cfg}"
    local out rc

    if ! command -v haproxy >/dev/null 2>&1; then
        log_warn "haproxy binary not found - skipping 'haproxy -c' validation before reload"
        return 0
    fi

    out="$(haproxy -c -f "$cfg" 2>&1 </dev/null)"
    rc=$?
    if [ $rc -eq 0 ]; then
        return 0
    fi

    log_error "haproxy -c -f $cfg failed (exit $rc): $out"
    return 1
}
