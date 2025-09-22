#!/bin/bash

# HAProxy IP blocking management script
# Usage: ./manage-blocked-ips.sh [block|unblock|list|clear] [IP_ADDRESS]

SOCKET="/tmp/haproxy-cli"
MAP_FILE="/etc/haproxy/blocked_ips.map"

# Ensure map file exists
if [ ! -f "$MAP_FILE" ]; then
    touch "$MAP_FILE"
    echo "# Blocked IPs - Format: IP_ADDRESS" > "$MAP_FILE"
fi

case "$1" in
    block)
        if [ -z "$2" ]; then
            echo "Usage: $0 block IP_ADDRESS"
            exit 1
        fi
        # Add IP to map file
        grep -q "^$2" "$MAP_FILE" || echo "$2" >> "$MAP_FILE"
        # Add to runtime map
        echo "add map /etc/haproxy/blocked_ips.map $2 1" | socat stdio "$SOCKET"
        echo "Blocked IP: $2"
        ;;

    unblock)
        if [ -z "$2" ]; then
            echo "Usage: $0 unblock IP_ADDRESS"
            exit 1
        fi
        # Remove from map file
        sed -i "/^$2$/d" "$MAP_FILE"
        # Remove from runtime map
        echo "del map /etc/haproxy/blocked_ips.map $2" | socat stdio "$SOCKET"
        echo "Unblocked IP: $2"
        ;;

    list)
        echo "Currently blocked IPs:"
        echo "show map /etc/haproxy/blocked_ips.map" | socat stdio "$SOCKET" | awk '{print $1}'
        ;;

    clear)
        echo "Clearing all blocked IPs..."
        echo "clear map /etc/haproxy/blocked_ips.map" | socat stdio "$SOCKET"
        echo "# Blocked IPs - Format: IP_ADDRESS" > "$MAP_FILE"
        echo "All IPs unblocked"
        ;;

    stats)
        echo "Stick table statistics (showing potential bad actors):"
        echo "show table web" | socat stdio "$SOCKET" | head -50
        ;;

    *)
        echo "Usage: $0 {block|unblock|list|clear|stats} [IP_ADDRESS]"
        echo ""
        echo "Commands:"
        echo "  block IP     - Block an IP address"
        echo "  unblock IP   - Unblock an IP address"
        echo "  list         - List all blocked IPs"
        echo "  clear        - Clear all blocked IPs"
        echo "  stats        - Show current stick table stats"
        exit 1
        ;;
esac