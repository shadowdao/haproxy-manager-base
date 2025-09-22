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
    echo "Current Threat IPs (from stick table):"
    echo "show table web" | socat stdio "$SOCKET" 2>/dev/null | \
        awk '$4 > 0 || $5 > 0 || $6 > 30 || $7 > 5 || $8 > 10 {
            printf "%-15s req_rate:%-3s err_rate:%-3s conn_rate:%-3s blocked:%s repeat:%s\n",
                   $1, $6, $7, $8, $4, $5
        }' | head -20
    echo "---------------------------------------------------"
}

# Function to show recent blocks
show_recent_blocks() {
    echo "Recent Blocked Requests:"
    tail -100 "$LOG_FILE" 2>/dev/null | \
        grep -E "(scanner|exploit|ratelimit|repeat|tarpit|denied|dropped)" | \
        tail -10 | \
        awk '{
            if (match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/)) {
                ip = substr($0, RSTART, RLENGTH)
                gsub(/:.*/, "", ip)
                reason = ""
                if ($0 ~ /scanner/) reason = "SCANNER"
                else if ($0 ~ /exploit/) reason = "EXPLOIT"
                else if ($0 ~ /ratelimit/) reason = "RATE_LIMIT"
                else if ($0 ~ /repeat/) reason = "REPEAT_OFFENDER"
                else if ($0 ~ /tarpit/) reason = "TARPIT"
                else if ($0 ~ /denied/) reason = "DENIED"
                else if ($0 ~ /dropped/) reason = "DROPPED"
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