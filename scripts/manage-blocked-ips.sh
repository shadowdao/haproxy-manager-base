#!/bin/bash

# HAProxy IP blocking management script
# Usage: ./manage-blocked-ips.sh [block|unblock|list|clear] [IP_ADDRESS]

SOCKET="/tmp/haproxy-cli"
MAP_FILE="/etc/haproxy/blocked_ips.map"

# HAProxy runs in master-worker mode here, and /tmp/haproxy-cli is the MASTER
# socket. Data-plane commands (map/table manipulation) are NOT accepted on the
# master socket — they must be routed to a worker with the "@<n>" prefix. "@1"
# targets the current active worker. (A bare "add map ..." on the master socket
# fails with "Unknown command: 'add'".)
cli() { printf '@1 %s\n' "$*" | socat stdio "$SOCKET"; }

# Map lookup in haproxy.cfg is `map_ip(...,0) -m int gt 0`, so each entry MUST be
# "<ip_or_cidr> 1" — a bare IP yields an empty value (0) and is NOT blocked once
# the map file is re-read on reload. The runtime map and the file must agree.
MAP_VALUE=1

# Ensure map file exists
if [ ! -f "$MAP_FILE" ]; then
    echo "# Blocked IPs - Format: <ip_or_cidr> 1 (one per line)" > "$MAP_FILE"
fi

# Escape regex metacharacters (notably dots) in an IP/CIDR for anchored matching.
esc_re() { printf '%s' "$1" | sed 's/[.[\*^$/]/\\&/g'; }

case "$1" in
    block)
        if [ -z "$2" ]; then
            echo "Usage: $0 block IP_ADDRESS"
            exit 1
        fi
        re="$(esc_re "$2")"
        # Persist (idempotent, anchored so 1.2.3.4 doesn't match 1.2.3.45),
        # always with the trailing value so the block survives a reload.
        if ! grep -qE "^${re}([[:space:]]|$)" "$MAP_FILE"; then
            echo "$2 $MAP_VALUE" >> "$MAP_FILE"
        fi
        # Apply at runtime immediately (no reload).
        cli "add map $MAP_FILE $2 $MAP_VALUE"
        echo "Blocked IP: $2"
        ;;

    unblock)
        if [ -z "$2" ]; then
            echo "Usage: $0 unblock IP_ADDRESS"
            exit 1
        fi
        re="$(esc_re "$2")"
        # Remove from map file (match "<ip>" optionally followed by a value).
        sed -i -E "/^${re}([[:space:]]|$)/d" "$MAP_FILE"
        # Remove from runtime map.
        cli "del map $MAP_FILE $2"
        echo "Unblocked IP: $2"
        ;;

    list)
        echo "Currently blocked IPs:"
        # `show map` output is "<ptr> <key> <value>" — the IP is field 2.
        cli "show map $MAP_FILE" | awk 'NF>=2 {print $2}'
        ;;

    clear)
        echo "Clearing all blocked IPs..."
        cli "clear map $MAP_FILE"
        echo "# Blocked IPs - Format: <ip_or_cidr> 1 (one per line)" > "$MAP_FILE"
        echo "All IPs unblocked"
        ;;

    stats)
        echo "=== HAProxy 3.0.11 Threat Intelligence Dashboard ==="
        cli "show table web" | awk 'NR<=21'
        echo ""
        echo "=== Top Threat Scores ==="
        cli "show table web" | awk '
        NR>1 {
            ip = $1
            auth_fail = 0
            authz_fail = 0
            scanner = 0
            repeat_off = 0
            manual_bl = 0

            if ($0 ~ /gpc\(0\)=([0-9]+)/) { match($0, /gpc\(0\)=([0-9]+)/, arr); auth_fail = arr[1] }
            if ($0 ~ /gpc\(1\)=([0-9]+)/) { match($0, /gpc\(1\)=([0-9]+)/, arr); authz_fail = arr[1] }
            if ($0 ~ /gpc\(3\)=([0-9]+)/) { match($0, /gpc\(3\)=([0-9]+)/, arr); scanner = arr[1] }
            if ($0 ~ /gpc\(12\)=([0-9]+)/) { match($0, /gpc\(12\)=([0-9]+)/, arr); repeat_off = arr[1] }
            if ($0 ~ /gpc\(13\)=([0-9]+)/) { match($0, /gpc\(13\)=([0-9]+)/, arr); manual_bl = arr[1] }

            threat_score = auth_fail*10 + authz_fail*8 + scanner*12 + repeat_off*25 + manual_bl*100

            if (threat_score > 0) {
                printf "%-15s Score:%-3d (Auth:%d Authz:%d Scanner:%d Repeat:%d Manual:%d)\n",
                       ip, threat_score, auth_fail, authz_fail, scanner, repeat_off, manual_bl
            }
        }' | sort -k2 -nr | head -10
        ;;

    blacklist)
        if [ -z "$2" ]; then
            echo "Usage: $0 blacklist IP_ADDRESS"
            exit 1
        fi
        # Add to manual blacklist using GPC(13)
        cli "set table web key $2 data.gpc(13) 1"
        echo "Manually blacklisted IP: $2 (GPC(13) = 1)"
        ;;

    unblacklist)
        if [ -z "$2" ]; then
            echo "Usage: $0 unblacklist IP_ADDRESS"
            exit 1
        fi
        # Clear manual blacklist flag
        cli "set table web key $2 data.gpc(13) 0"
        echo "Removed manual blacklist for IP: $2"
        ;;

    auto-blacklist)
        if [ -z "$2" ]; then
            echo "Usage: $0 auto-blacklist IP_ADDRESS"
            exit 1
        fi
        # Add to auto-blacklist using GPC(14)
        cli "set table web key $2 data.gpc(14) 1"
        echo "Auto-blacklisted IP: $2 (GPC(14) = 1)"
        ;;

    threat-score)
        if [ -z "$2" ]; then
            echo "Usage: $0 threat-score IP_ADDRESS"
            exit 1
        fi
        # Show detailed threat breakdown for specific IP
        echo "Threat analysis for $2:"
        cli "show table web key $2"
        ;;

    *)
        echo "Usage: $0 {block|unblock|list|clear|blacklist|unblacklist|auto-blacklist|threat-score|stats} [IP_ADDRESS]"
        echo ""
        echo "HAProxy 3.0.11 Enhanced Security Commands:"
        echo "  block IP         - Block IP via map file (immediate + persisted)"
        echo "  unblock IP       - Unblock IP from map file"
        echo "  blacklist IP     - Manual blacklist via GPC(13) array"
        echo "  unblacklist IP   - Remove manual blacklist flag"
        echo "  auto-blacklist IP - Auto-blacklist via GPC(14) array"
        echo "  threat-score IP  - Show detailed threat analysis for IP"
        echo "  list             - List all blocked IPs (map file)"
        echo "  clear            - Clear all blocked IPs (map file)"
        echo "  stats            - Show threat intelligence dashboard"
        echo ""
        echo "Array-Based GPC Threat Matrix:"
        echo "  gpc(0):  Authentication failures (401s)     × 10"
        echo "  gpc(1):  Authorization failures (403s)      × 8"
        echo "  gpc(3):  Scanner/Bot detection              × 12"
        echo "  gpc(12): Repeat offender flag               × 25"
        echo "  gpc(13): Manual blacklist flag              × 100"
        echo "  gpc(14): Auto-blacklist candidate           × 50"
        exit 1
        ;;
esac
