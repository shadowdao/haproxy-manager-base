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
# final mv is a rename(2) - atomic. There is deliberately no "just write it
# directly into the certs dir" fallback path.
#
# The same-filesystem property is CHECKED, not assumed (see cert_publish step
# (c)). An earlier revision of this comment claimed a cross-device mv would
# "fail loudly and leave the live pem alone". It does not: GNU mv falls back to
# copy-then-unlink across filesystems, so it OPENS THE DESTINATION FOR WRITING
# and only then discovers it cannot finish - e.g. with a full destination
# filesystem the live pem is already overwritten when mv reports failure. That
# is precisely the truncation this library exists to prevent, so the device
# numbers of the staging dir and the certs dir are compared with stat(1) before
# anything is written, and a mismatch aborts the publish. Both directories are
# env-overridable ($CERT_STAGING_DIR / $SSL_CERTS_DIR), so "they are siblings"
# is not something the code can take on faith. This mirrors the explicit
# st_dev check in publish_pem_bundle() on the Python side.

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
# Layer 1 (structure, pure shell/grep): covers the truncation / partial-write /
#         key-less failure modes this library exists to prevent.
# Layer 2 (cryptographic pairing via the openssl CLI): covers what layer 1
#         cannot see. Structural checks are weak on their own - a bundle of
#         EMPTY pem blocks ("-----BEGIN CERTIFICATE-----" immediately followed
#         by "-----END CERTIFICATE-----") satisfies every grep below and is
#         caught only by openssl.
#
# BOTH LAYERS ARE MANDATORY. An absent openssl binary is a hard failure, not a
# skip.
#
# The previous revision made layer 2 best-effort and justified it with "the
# container image installs haproxy, certbot and socat, but not necessarily the
# openssl CLI". That premise is false. openssl 3.x is present in the image: it
# is a dependency of ca-certificates, which certbot needs, and
# generate_self_signed_cert() in haproxy_manager.py shells out to `openssl req`
# with check=True during first-run setup, so a container that reached the point
# of publishing a bundle has always had it. The "unavailable" branch therefore
# never fired in production, which means the fail-open was safe only by
# accident - and a comment that justifies a decision on a false premise is
# worse than no comment, because the next person extends the reasoning.
#
# Making it mandatory does mean a hypothetical image without openssl stops
# publishing renewals. That is the right trade: it fails immediately and
# loudly, into the monitored error log, on the first renewal run, whereas
# publishing an unpaired or empty-block bundle takes the whole :443 bind (i.e.
# every site on the host) down at the next reload. There is deliberately no
# python `cryptography` fallback: the app runs on /usr/local/bin/python3 (the
# base image's 3.12), where cryptography is NOT importable - it is installed
# for Debian's /usr/bin/python3 as a certbot dependency. Coding to a hardcoded
# /usr/bin/python3 would just be a second unverified premise.
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

    # openssl is checked BEFORE any content check so a broken image is reported
    # as a broken image rather than as a bad certificate.
    if ! command -v openssl >/dev/null 2>&1; then
        log_error "openssl binary not found - REFUSING to publish $file." \
                  "The cert/key pairing check (openssl x509 -pubkey vs openssl pkey -pubout)" \
                  "is mandatory; structural checks alone cannot tell a real bundle from" \
                  "empty pem blocks. Install openssl in this image."
        return 1
    fi

    # Read the file ONCE and run every check against that snapshot.
    #
    # This used to open $file six times (two [ ] tests, three greps, two
    # openssl invocations). cert_bundle_valid() is called on the LIVE pem in
    # cert_publish() step (d), where a concurrent publisher can replace it
    # between two of those opens - each open then sees a different file. The
    # observable symptom was a spurious "private key does not match the
    # certificate" ERROR in the monitored error log for a pair that was fine:
    # openssl x509 read the old bundle and openssl pkey the new one.
    local content
    if ! content="$(cat -- "$file" 2>/dev/null)"; then
        log_error "Certificate bundle $file could not be read"
        return 1
    fi
    if [ -z "$content" ]; then
        log_error "Certificate bundle $file is empty"
        return 1
    fi

    # --- layer 1: structure -------------------------------------------------
    if ! grep -qF -- '-----BEGIN CERTIFICATE-----' <<< "$content"; then
        log_error "Certificate bundle $file contains no certificate block"
        return 1
    fi
    if ! grep -qF -- '-----END CERTIFICATE-----' <<< "$content"; then
        log_error "Certificate bundle $file has an unterminated certificate block (truncated?)"
        return 1
    fi

    local key_begin key_end
    key_begin="$(grep -m1 -oE -- '-----BEGIN (RSA |EC )?PRIVATE KEY-----' <<< "$content")"
    if [ -z "$key_begin" ]; then
        log_error "Certificate bundle $file contains no private key block"
        return 1
    fi
    key_end="${key_begin/BEGIN/END}"
    if ! grep -qF -- "$key_end" <<< "$content"; then
        log_error "Certificate bundle $file has an unterminated private key block (truncated?)"
        return 1
    fi

    # --- layer 2: cert/key pairing ------------------------------------------
    # Fed from the same snapshot on stdin (openssl reads stdin when -in is
    # omitted) rather than re-opening $file, so layer 2 judges exactly the
    # bytes layer 1 judged. -passin pass: means an encrypted key fails fast
    # instead of prompting - a passphrase prompt in a cron job is a hang, not
    # an error.
    local cert_pub key_pub
    if ! cert_pub="$(openssl x509 -noout -pubkey 2>/dev/null <<< "$content")" \
       || [ -z "$cert_pub" ]; then
        log_error "Certificate bundle $file: openssl could not read the certificate"
        return 1
    fi
    if ! key_pub="$(openssl pkey -pubout -passin pass: 2>/dev/null <<< "$content")" \
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
    local staging_dir backup_dir dest_dir tmp base

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
    dest_dir="$(dirname "$dest_file")"
    if ! mkdir -p "$staging_dir" || ! mkdir -p "$dest_dir"; then
        log_error "cert_publish: cannot create staging directory $staging_dir or destination directory $dest_dir"
        return 1
    fi

    # (c) the final swap is `mv`, which is only a rename(2) - and therefore only
    #     atomic - within one filesystem. Across filesystems GNU mv copies:
    #     it truncates and writes the DESTINATION, then unlinks the source, so a
    #     failure part-way through (ENOSPC is the realistic one) leaves exactly
    #     the half-written live pem this library exists to prevent. Both paths
    #     are env-overridable, so check instead of assuming. Same check as the
    #     st_dev comparison in publish_pem_bundle() on the Python side.
    local staging_dev dest_dev
    staging_dev="$(stat -Lc '%d' "$staging_dir" 2>/dev/null)"
    dest_dev="$(stat -Lc '%d' "$dest_dir" 2>/dev/null)"
    if [ -z "$staging_dev" ] || [ -z "$dest_dev" ]; then
        log_error "cert_publish: cannot stat $staging_dir and/or $dest_dir - refusing to publish $dest_file"
        return 1
    fi
    if [ "$staging_dev" != "$dest_dev" ]; then
        log_error "cert_publish: staging dir $staging_dir and destination dir $dest_dir" \
                  "are on different filesystems, so the bundle cannot be swapped in atomically." \
                  "Refusing to publish $dest_file (live file left untouched);" \
                  "point CERT_STAGING_DIR at a directory on the same filesystem as $dest_dir"
        return 1
    fi

    # Sweep temps orphaned by a kill -9 / OOM in an earlier run. Two shapes,
    # because two publishers share this directory: mktemp's six-X suffix from
    # this library, and `<name>.<random>.tmp` from write_config_atomically() on
    # the Python side (tempfile.mkstemp(prefix=name + '.', suffix='.tmp')).
    # Matching only the mktemp shape - as this did - left every Python-side
    # temp behind forever.
    find "$staging_dir" -maxdepth 1 -type f \
        \( -name '*.??????' -o -name '*.tmp' \) -mmin +1440 -delete 2>/dev/null

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

    # (d) never promote something HAProxy would choke on.
    if ! cert_bundle_valid "$tmp"; then
        log_error "cert_publish: assembled bundle for $dest_file failed validation (live file left untouched)"
        rm -f "$tmp"
        return 1
    fi

    # (e) back up the bundle we are about to replace - but only if it is itself
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
    #
    # -L (follow symlinks) matters: stat without it reports the mode of the
    # SYMLINK, which is 0777 on Linux and is not a permission at all. A live
    # pem that is a symlink therefore produced a world-WRITABLE 0777 private
    # key sitting in the crt directory. With -L we copy the mode of the file
    # the link points at, which is the mode an operator actually chose.
    local mode
    mode="$(stat -Lc '%a' "$dest_file" 2>/dev/null)"
    [ -n "$mode" ] || mode=644
    chmod "$mode" "$tmp" 2>/dev/null

    # (f) atomic swap. Same filesystem, verified in (c); if it still fails,
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
