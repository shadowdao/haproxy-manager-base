#!/bin/bash

# Real-time attack monitoring for HAProxy
# Shows blocked requests and suspicious activity

LOG_FILE="/var/log/haproxy.log"
SOCKET="/tmp/haproxy-cli"

echo "==================================================="
echo "HAProxy Security Monitor - Real-time Attack Detection"
echo "==================================================="
echo ""

# Function to show current threats
show_threats() {
    echo "Current Threat IPs (Rate Limiting Table):"
    echo "show table web" | socat stdio "$SOCKET" 2>/dev/null | \
        awk '$4 > 0 || $5 > 20 || $6 > 5 || $7 > 10 {
            printf "%-15s req_rate:%-3s err_rate:%-3s conn_rate:%-3s marked:%s\n",
                   $1, $5, $6, $7, $4
        }' | head -10

    echo ""
    echo "Blacklisted IPs (24h tracking):"
    echo "show table security_blacklist" | socat stdio "$SOCKET" 2>/dev/null | \
        awk '$4 > 0 || $5 > 0 {
            printf "%-15s blacklisted:%s violations:%s\n",
                   $1, $4, $5
        }' | head -10

    echo ""
    echo "WordPress 403 Failures:"
    echo "show table wp_403_track" | socat stdio "$SOCKET" 2>/dev/null | \
        awk '$4 > 2 {
            printf "%-15s 403_rate:%-3s\n",
                   $1, $4
        }' | head -10
    echo "---------------------------------------------------"
}

# Function to show recent blocks
show_recent_blocks() {
    echo "Recent Blocked Requests:"
    tail -100 "$LOG_FILE" 2>/dev/null | \
        grep -E "(bot_scanner|scan_admin|scan_shells|sql_injection|directory_traversal|rate_abuse|tarpit|denied|403)" | \
        tail -10 | \
        awk '{
            if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/)) {
                ip = substr($0, RSTART, RLENGTH)
                gsub(/:.*/, "", ip)
                reason = ""
                if ($0 ~ /bot_scanner/) reason = "BOT_SCANNER"
                else if ($0 ~ /scan_admin/) reason = "ADMIN_SCAN"
                else if ($0 ~ /scan_shells/) reason = "SHELL_SCAN"
                else if ($0 ~ /sql_injection/) reason = "SQL_INJECTION"
                else if ($0 ~ /directory_traversal/) reason = "DIR_TRAVERSAL"
                else if ($0 ~ /rate_abuse/) reason = "RATE_ABUSE"
                else if ($0 ~ /tarpit/) reason = "TARPIT"
                else if ($0 ~ /denied/) reason = "DENIED"
                else if ($0 ~ /403/) reason = "BLOCKED"
                printf "[%s] %-15s %s\n", strftime("%H:%M:%S"), ip, reason
            }
        }'
    echo ""
}

# Monitor mode selection
if [ "$1" == "live" ]; then
    echo "Live monitoring mode - Press Ctrl+C to exit"
    echo ""

    while true; do
        clear
        echo "==================================================="
        echo "HAProxy Security Monitor - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "==================================================="
        echo ""
        show_threats
        echo ""
        show_recent_blocks
        sleep 5
    done
else
    # Single run mode
    show_threats
    echo ""
    show_recent_blocks
    echo ""
    echo "Tip: Run with 'live' parameter for continuous monitoring"
    echo "Usage: $0 [live]"
fi