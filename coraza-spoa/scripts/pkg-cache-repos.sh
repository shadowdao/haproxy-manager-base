#!/bin/bash
## pkg-cache-repos.sh — BUILD-TIME ONLY, OPT-IN. Points dnf/apt at the internal
## package cache (nginx proxy_cache, CT130 "pkg-cache" on the Proxmox cluster)
## when PKG_CACHE is set; without it the repo files are left alone and builds
## use the upstream repositories as before.
##
##   PKG_CACHE=https://192.168.1.40 pkg-cache-repos.sh rpm      # AlmaLinux/EPEL/Remi/NodeSource
##   PKG_CACHE=https://192.168.1.40 pkg-cache-repos.sh apt      # Ubuntu, Debian, LiteSpeed
##   pkg-cache-repos.sh release-install epel [remi]             # GPG-verified release RPMs (EL9/EL10)
##   pkg-cache-repos.sh nodesource MAJOR                        # NodeSource repo file + pinned key
##   eval "$(pkg-cache-repos.sh go-env)"                        # GOPROXY via the cache (go.sum/sumdb verified)
##   pkg-cache-repos.sh restore                                 # undo everything above
##
## CANONICAL copy: cloud-apache-container/scripts/pkg-cache-repos.sh (docs/pkg-cache.md
## there). Other repos carry byte-identical copies - change it there first.
##
## Every RUN that rewrites must `restore` before it ends: it puts rewritten files
## back, deletes files this script created, deletes any NEW repo/apt file that
## still references the cache, then FAILS if any reference is left — so no shipped
## layer carries the cache's LAN address (images run on hosts that can't reach it).
##
## Why: on 2026-10-21 (PHP security release) builds failed on Remi mirrors lagging
## hours behind origin, Remi's origin timing out over HTTPS, and an EPEL mirror
## with a broken certificate. The cache fetches from the ORIGINS over HTTPS (with
## origin/mirror fallbacks and stale-on-error), keeps metadata ~3 minutes and
## immutable .rpm/.deb files long-term.
##
## Integrity (security review 2026-10-21):
##  * PKG_CACHE must be https://. The cache's certificate is issued by the
##    name-constrained "pkg-cache internal CA" (keys/pkg-cache/ca.crt, valid only
##    for 192.168.1.40 / pkg-cache.*). That CA is trusted ONLY by the rewritten
##    repos (dnf sslcacert= bundle, apt per-host CaInfo) and only during the RUN —
##    never added to the system trust store.
##  * gpgcheck=1 is forced on every rewritten repo; repo_gpgcheck=1 on Remi and
##    AlmaLinux, which sign repomd.xml (measured: repomd.xml.asc 200). EPEL
##    publishes no repomd signature (404), so its metadata relies on HTTPS end
##    to end (client->cache->dl.fedoraproject.org/mirrors, all verified).
##  * release-install downloads epel-release / remi-release (from the cache, or
##    from the HTTPS origin without PKG_CACHE), checks the package name, imports
##    the signing keys committed in keys/pkg-cache/ and requires
##    `rpm -K` "signatures OK" before installing with localpkg_gpgcheck=1.
##  * The php.net version gates (EXPECT_PHP_MIN / EXPECT_PHP_VERSION) still fail
##    a build that gets old PHP (replay of old-but-signed metadata).
##
## rpm: each rewritten baseurl keeps the upstream origin as a SECOND url, so if
##      the cache dies mid-build dnf fails over to the origin by itself.
## apt: apt has no per-source failover; CI only sets PKG_CACHE after probing the
##      cache (with the CA), and a build without PKG_CACHE uses upstream sources.
set -euo pipefail

MODE="${1:?usage: pkg-cache-repos.sh rpm|apt|release-install NAME...|nodesource MAJOR|go-env|restore}"
shift || true
STATE=/var/lib/pkg-cache-repos          # saved originals + manifest + created files
SHARE="${PKG_CACHE_SHARE:-/usr/local/share/pkg-cache}"   # ca.crt + RPM-GPG-KEY-*
C="${PKG_CACHE:-}"
C="${C%/}"

die() { echo "FATAL(pkg-cache-repos): $*" >&2; exit 1; }

if [ -n "$C" ]; then
    case "$C" in
        https://*) ;;
        *) die "PKG_CACHE must be an https:// URL (plain http is refused), got '$C'" ;;
    esac
    [[ "$C" =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._/-]*)?$ ]] || die "PKG_CACHE has unexpected characters: '$C'"
    HOSTPORT="${C#https://}"; HOSTPORT="${HOSTPORT%%/*}"
    [ -s "$SHARE/ca.crt" ] || die "PKG_CACHE set but $SHARE/ca.crt (pkg-cache CA) is missing"
fi

# System CA bundle (EL vs Debian/Ubuntu path); the pkg-cache CA is appended to a
# copy in the state dir, never to the system store.
sys_bundle() {
    local b
    for b in /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
        [ -s "$b" ] && { echo "$b"; return 0; }
    done
    die "no system CA bundle found"
}
make_bundle() { cat "$(sys_bundle)" "$SHARE/ca.crt" > "$STATE/ca-bundle.pem"; }

# Files that may hold repo configuration; restore re-checks all of them.
repo_files() {
    find /etc/yum.repos.d /etc/dnf /etc/apt -type f 2>/dev/null | sort || true
}

start_session() {
    [ -d "$STATE" ] && return 0
    mkdir -p "$STATE/orig"
    repo_files > "$STATE/manifest"     # what existed before this RUN touched anything
    : > "$STATE/created"
    printf '%s\n' "$HOSTPORT" > "$STATE/host"
}
save() {                                # keep the first-seen (pre-rewrite) copy
    [ -e "$STATE/orig$1" ] && return 0
    mkdir -p "$STATE/orig$(dirname "$1")"
    cp -p "$1" "$STATE/orig$1"
}
created() { printf '%s\n' "$1" >> "$STATE/created"; }

if [ "$MODE" = restore ]; then
    [ -d "$STATE" ] || exit 0
    host=$(cat "$STATE/host")
    # mapfile from a process substitution, not `cmd | while read`: no pipeline,
    # so nothing for pipefail to misreport (scripts/tests/lsphp-info-probe.test.sh).
    mapfile -t saved < <(cd "$STATE/orig" && find . -type f)
    for rel in "${saved[@]}"; do
        cat "$STATE/orig/$rel" > "/${rel#./}"
    done
    while read -r f; do [ -n "$f" ] && rm -f -- "$f"; done < "$STATE/created"
    # A repo/apt file that appeared during this RUN and still names the cache
    # (e.g. written by a package from the rewritten repos) is removed too.
    mapfile -t current < <(repo_files)
    for f in "${current[@]}"; do
        if ! grep -qxF -- "$f" "$STATE/manifest" && grep -qF -- "$host" "$f"; then
            echo "pkg-cache-repos: removing new file that references the cache: $f"
            rm -f -- "$f"
        fi
    done
    left=$(repo_files | xargs -r grep -lF -- "$host" 2>/dev/null || true)
    rm -rf "$STATE"
    [ -z "$left" ] || die "cache address $host still present after restore in: $left"
    echo "pkg-cache-repos: original repository files restored (no reference to $host left)"
    exit 0
fi

if [ "$MODE" = release-install ]; then
    [ $# -gt 0 ] || die "release-install needs: epel and/or remi"
    tmp=$(mktemp -d)
    curl_opts=(-fsS --proto '=https' --retry 5 --retry-all-errors --max-time 120)
    if [ -n "$C" ]; then
        start_session
        make_bundle
        curl_opts+=(--cacert "$STATE/ca-bundle.pem")
    fi
    files=()
    el=$(rpm -E '%{?rhel}' 2>/dev/null || true)
    case "$el" in 9|10) ;; *) die "release-install supports EL9/EL10 only (rpm -E %rhel = '$el')" ;; esac
    for name in "$@"; do
        case "$name" in
            epel) pkg=epel-release key=RPM-GPG-KEY-EPEL-$el
                  path=/epel/epel-release-latest-$el.noarch.rpm
                  origin=https://dl.fedoraproject.org/pub/epel/epel-release-latest-$el.noarch.rpm ;;
            remi) pkg=remi-release key=RPM-GPG-KEY-remi2024
                  path=/remi/enterprise/remi-release-$el.rpm
                  origin=https://rpms.remirepo.net/enterprise/remi-release-$el.rpm ;;
            *) die "unknown release package '$name'" ;;
        esac
        url="$origin"; [ -n "$C" ] && url="$C$path"
        f="$tmp/$pkg.rpm"
        curl "${curl_opts[@]}" -o "$f" "$url" || die "download failed: $url"
        rpm --import "$SHARE/$key" || die "cannot import $SHARE/$key"
        got=$(rpm -qp --nosignature --qf '%{NAME}' "$f" 2>/dev/null || true)
        [ "$got" = "$pkg" ] || die "$url is '$got', expected $pkg"
        chk=$(rpm -K "$f" 2>&1 || true)
        [[ "$chk" == *": digests signatures OK" ]] || die "signature check failed for $url: $chk"
        echo "pkg-cache-repos: $pkg verified ($chk) from $url"
        files+=("$f")
    done
    dnf install -y --setopt=localpkg_gpgcheck=1 "${files[@]}"
    rm -rf "$tmp"
    exit 0
fi

if [ -z "$C" ] && [ "$MODE" != nodesource ] && [ "$MODE" != go-env ]; then
    echo "pkg-cache-repos($MODE): PKG_CACHE not set - using upstream repositories"
    exit 0
fi

rewrite_rpm() {
    local f="$1"
    grep -q -E '^#? ?baseurl=https?://(repo\.almalinux\.org|download\.example|rpms\.remirepo\.net|rpm\.nodesource\.com)/' "$f" || return 0
    save "$f"
    # Per [section]: a (commented or live) baseurl on a known origin becomes
    # "baseurl=<cache>/<prefix>/<path> <origin>/<path>"; that section's
    # mirrorlist/metalink is commented out (dnf prefers them over baseurl) and it
    # gets sslcacert=<system bundle + pkg-cache CA>, gpgcheck=1 and, for repos
    # that sign repomd.xml, repo_gpgcheck=1. Other sections are untouched.
    awk -v C="$C" -v BUNDLE="$STATE/ca-bundle.pem" '
        function flush(   i) {
            for (i = 1; i <= n; i++) {
                if (hit && buf[i] ~ /^(mirrorlist|metalink)=/) buf[i] = "#" buf[i]
                if (hit && buf[i] ~ /^(sslcacert|gpgcheck|repo_gpgcheck)[ \t]*=/) continue
                print buf[i]
            }
            if (hit) {
                print "sslcacert=" BUNDLE
                print "gpgcheck=1"
                if (signed) print "repo_gpgcheck=1"
            }
            n = 0; hit = 0; signed = 0
        }
        function rw(line, re, prefix, origin, sig,   p) {
            if (match(line, re)) {
                p = substr(line, RSTART + RLENGTH); sub(/[ \t].*$/, "", p)
                hit = 1; if (sig) signed = 1
                return "baseurl=" C "/" prefix "/" p " " origin "/" p
            }
            return line
        }
        /^\[/ { flush() }
        {
            l = $0
            if (l ~ /^#? ?baseurl=/) {
                l = rw(l, "^#? ?baseurl=https?://repo\\.almalinux\\.org/almalinux/", "almalinux", "https://repo.almalinux.org/almalinux", 1)
                l = rw(l, "^#? ?baseurl=https?://download\\.example/pub/epel/", "epel", "https://dl.fedoraproject.org/pub/epel", 0)
                l = rw(l, "^#? ?baseurl=https?://rpms\\.remirepo\\.net/", "remi", "https://rpms.remirepo.net", 1)
                # NodeSource signs its RPMs but not repomd.xml (404): gpgcheck only.
                l = rw(l, "^#? ?baseurl=https?://rpm\\.nodesource\\.com/", "nodesource", "https://rpm.nodesource.com", 0)
            }
            buf[++n] = l
        }
        END { flush() }
    ' "$f" > "$f.pkgcache" && cat "$f.pkgcache" > "$f" && rm -f "$f.pkgcache"
}

rewrite_apt() {
    local f="$1"
    grep -q -E 'https?://([a-z]{2}\.)?(archive|security)\.ubuntu\.com/|https?://rpms\.litespeedtech\.com/|https?://(deb|security)\.debian\.org/' "$f" || return 0
    save "$f"
    # Debian: debian-security first, and "debian" only as a whole path segment,
    # so .../debian-security is never rewritten as /debian/.
    sed -i -E \
        -e "s%https?://(archive|[a-z]{2}\.archive)\.ubuntu\.com/ubuntu/?%$C/ubuntu/%g" \
        -e "s%https?://security\.ubuntu\.com/ubuntu/?%$C/ubuntu-security/%g" \
        -e "s%https?://rpms\.litespeedtech\.com/%$C/litespeed/%g" \
        -e "s%https?://(deb|security)\.debian\.org/debian-security/?([[:space:]]|\$)%$C/debian-security/\\2%g" \
        -e "s%https?://security\.debian\.org/?([[:space:]]|\$)%$C/debian-security/\\1%g" \
        -e "s%https?://deb\.debian\.org/debian/?([[:space:]]|\$)%$C/debian/\\1%g" \
        "$f"
}

if [ "$MODE" = go-env ]; then
    # Prints shell exports for `eval`. Without PKG_CACHE: nothing (Go defaults).
    # GOPROXY "a|b" falls through on ANY error, so a dead cache costs one
    # failed request, not the build. GOSUMDB stays the default sum.golang.org,
    # reached directly: modules are still verified against go.sum + the sumdb.
    [ -n "$C" ] || { echo "pkg-cache-repos(go-env): PKG_CACHE not set - default GOPROXY" >&2; exit 0; }
    start_session
    make_bundle
    printf "export GOPROXY='%s/goproxy|https://proxy.golang.org|direct' SSL_CERT_FILE='%s'\n" "$C" "$STATE/ca-bundle.pem"
    echo "pkg-cache-repos(go-env): GOPROXY via $C/goproxy (fallback proxy.golang.org)" >&2
    exit 0
fi

if [ "$MODE" = nodesource ]; then
    # Replaces `curl https://rpm.nodesource.com/setup_N.x | bash` (unverified
    # remote script): writes the same nodesource-nodejs repo (origin URL, so the
    # shipped image keeps a normal repo file) with gpgcheck=1 and the signing key
    # committed in keys/pkg-cache/; with PKG_CACHE it is then rewritten like any
    # other repo and `restore` puts the origin version back.
    major="${1:?usage: pkg-cache-repos.sh nodesource MAJOR}"
    [[ "$major" =~ ^[0-9]{1,3}$ ]] || die "bad Node major '$major'"
    key="$SHARE/RPM-GPG-KEY-nodesource"
    [ -s "$key" ] || die "missing $key"
    rpm --import "$key" || die "cannot import $key"
    rm -f /etc/yum.repos.d/nodesource*.repo
    f=/etc/yum.repos.d/nodesource-nodejs.repo
    printf '%s\n' "[nodesource-nodejs]" \
        "name=Node.js Packages for Linux RPM based distros - \$basearch" \
        "baseurl=https://rpm.nodesource.com/pub_${major}.x/nodistro/nodejs/\$basearch" \
        "priority=9" "enabled=1" "gpgcheck=1" \
        "gpgkey=file://$key" "module_hotfixes=1" > "$f"
    echo "pkg-cache-repos: wrote $f (Node ${major}.x, key $(basename "$key"))"
    if [ -n "$C" ]; then
        start_session
        make_bundle
        rewrite_rpm "$f"
        grep -h '^baseurl=' "$f" | sed 's/^/  /'
    fi
    exit 0
fi

case "$MODE" in
    rpm)
        start_session
        make_bundle
        for f in /etc/yum.repos.d/*.repo; do [ -f "$f" ] && rewrite_rpm "$f"; done
        echo "pkg-cache-repos(rpm): repos now via $C:"
        grep -h '^baseurl=' /etc/yum.repos.d/*.repo | grep -F "$C/" | sort -u | sed 's/^/  /'
        ;;
    apt)
        start_session
        conf=/etc/apt/apt.conf.d/99pkg-cache
        # Trust the pkg-cache CA for the cache host ONLY (apt per-host option).
        printf 'Acquire::https::%s::CaInfo "%s";\n' "${HOSTPORT%%:*}" "$SHARE/ca.crt" > "$conf"
        created "$conf"
        for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
            [ -f "$f" ] && rewrite_apt "$f"
        done
        echo "pkg-cache-repos(apt): sources now via $C:"
        # (|| true: Debian 13 images have no /etc/apt/sources.list; grep's exit 2
        # for the missing file must not fail the build under pipefail)
        { grep -h -E '^(deb|URIs:)' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true; } | grep -F "$C/" | sort -u | sed 's/^/  /' || true
        ;;
    *) die "unknown mode '$MODE'" ;;
esac
