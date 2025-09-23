#!/bin/bash

# Real-time attack monitoring for HAProxy
# Shows blocked requests and suspicious activity

LOG_FILE="/var/log/haproxy.log"
SOCKET="/tmp/haproxy-cli"

echo "==================================================="
echo "HAProxy Security Monitor - Real-time Attack Detection"
echo "==================================================="
echo ""

# Function to show current threats with HAProxy 3.0.11 metrics
show_threats() {
    echo "HAProxy 3.0.11 Threat Intelligence Dashboard:"
    echo "show table web" | socat stdio "$SOCKET" 2>/dev/null | \
        awk 'NR>1 {
            # Parse the stick table output for array-based GPC values
            ip = $1
            # Look for GPC array values in the data
            auth_fail = 0; authz_fail = 0; rate_viol = 0; scanner = 0
            sql_inj = 0; traversal = 0; wp_brute = 0; admin_scan = 0
            shell_att = 0; repeat_off = 0; manual_bl = 0; auto_bl = 0
            glitch_rate = 0; threat_score = 0

            # Extract relevant metrics (simplified parsing)
            if ($0 ~ /gpc\(0\)=([0-9]+)/) {
                match($0, /gpc\(0\)=([0-9]+)/, arr); auth_fail = arr[1]
            }
            if ($0 ~ /gpc\(1\)=([0-9]+)/) {
                match($0, /gpc\(1\)=([0-9]+)/, arr); authz_fail = arr[1]
            }
            if ($0 ~ /gpc\(3\)=([0-9]+)/) {
                match($0, /gpc\(3\)=([0-9]+)/, arr); scanner = arr[1]
            }
            if ($0 ~ /gpc\(12\)=([0-9]+)/) {
                match($0, /gpc\(12\)=([0-9]+)/, arr); repeat_off = arr[1]
            }
            if ($0 ~ /gpc\(13\)=([0-9]+)/) {
                match($0, /gpc\(13\)=([0-9]+)/, arr); manual_bl = arr[1]
            }
            if ($0 ~ /glitch_rate\(300s\)=([0-9]+)/) {
                match($0, /glitch_rate\(300s\)=([0-9]+)/, arr); glitch_rate = arr[1]
            }

            # Calculate composite threat score (simplified)
            threat_score = auth_fail*10 + authz_fail*8 + scanner*12 + repeat_off*25 + manual_bl*100

            # Only show IPs with significant threat indicators
            if (auth_fail > 0 || authz_fail > 0 || scanner > 0 || repeat_off > 0 || manual_bl > 0 || glitch_rate > 0) {
                threat_level = "LOW"
                if (threat_score >= 100) threat_level = "CRITICAL"
                else if (threat_score >= 50) threat_level = "HIGH"
                else if (threat_score >= 20) threat_level = "MEDIUM"

                printf "%-15s [%8s] Score:%-3d Auth:%-2d Authz:%-2d Scanner:%-1d Repeat:%-1d Glitch:%-2d\n",
                       ip, threat_level, threat_score, auth_fail, authz_fail, scanner, repeat_off, glitch_rate
            }
        }' | head -15

    echo ""
    echo "Top HTTP/2 Protocol Violators:"
    echo "show table web" | socat stdio "$SOCKET" 2>/dev/null | \
        awk 'NR>1 && $0 ~ /glitch/ {
            if ($0 ~ /glitch_rate\(300s\)=([0-9]+)/) {
                match($0, /glitch_rate\(300s\)=([0-9]+)/, arr)
                if (arr[1] > 2) {
                    printf "%-15s glitch_rate:%-3s\n", $1, arr[1]
                }
            }
        }' | head -5
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