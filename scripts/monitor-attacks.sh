#!/usr/bin/env bash
#
# monitor-attacks.sh — HAProxy edge activity monitor.
#
# Two sections, both fed from real data:
#   1. Current per-IP rates, from the `web` stick table (delegated to
#      show-edge-ip-rates.sh — there is exactly one stick-table parser).
#   2. Recent enforcement events, from the HAProxy access log.
#
# HISTORY / WHY THIS IS SHORTER THAN IT USED TO BE
#   The previous version printed a "Threat Intelligence Dashboard" with
#   fourteen categories (auth_fail, authz_fail, scanner, sql_inj, traversal,
#   wp_brute, admin_scan, shell_att, repeat_off, manual_bl, auto_bl,
#   glitch_rate, ...) and a composite "threat score", all parsed out of
#   gpc(0), gpc(1), gpc(3), gpc(12), gpc(13) and glitch_rate(300s). NONE of
#   those fields exist: the `web` table stores only conn_cur, conn_rate,
#   http_req_rate and http_err_rate. Every category was permanently 0 and the
#   whole dashboard printed nothing while implying it was watching. All of it
#   has been deleted rather than "fixed" — there was no data source to fix it
#   against.
#
# Usage: monitor-attacks.sh [live]
# Env:   LOG_FILE=<path>  access log to read (default /var/log/haproxy.log)
#        LOG_LINES=<n>    how many trailing log lines to scan (default 500)

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${LOG_FILE:-/var/log/haproxy.log}"
LOG_LINES="${LOG_LINES:-500}"

# --- Section 1: current rates (real stick-table data) -----------------------
show_rates() {
    "$SCRIPT_DIR/show-edge-ip-rates.sh" "$@"
}

# --- Section 2: recent enforcement events (real access-log data) ------------
show_recent_blocks() {
    echo "Recent enforcement events (last $LOG_LINES log lines):"
    echo

    if [ ! -f "$LOG_FILE" ] || [ ! -r "$LOG_FILE" ]; then
        cat <<MSG
  Access log not readable at: $LOG_FILE

  This is expected INSIDE the haproxy-manager container: HAProxy logs to
  syslog on the DOCKER HOST, and the file lives on the host, not in here.
  Read it from the host instead:

    grep -aE ' (PT|PR)--' /var/log/haproxy.log | tail -20   # tarpit / deny
    grep -aE ' (429|403) ' /var/log/haproxy.log | tail -20  # rate-limited / blocked
    grep -a 'cip=<IP>'  /var/log/haproxy.log | tail -50     # one client IP
    grep -a 'id=<uuid>' /var/log/haproxy.log                # one request reference
                                                            # (the UUID on the block page)
    tail -f /var/log/haproxy.log | grep -aE ' (PT|PR)--'    # live

  Or point this script at a copy:  LOG_FILE=/path/to/haproxy.log $0
MSG
        echo
        return 0
    fi

    printf "%-15s %-16s %-4s %-5s %-28s %s\n" "TIME" "CLIENT IP" "CODE" "TERM" "HOST" "REQUEST / REQUEST-ID"
    printf "%s\n" "-----------------------------------------------------------------------------------------------------"

    local found
    found=$(tail -n "$LOG_LINES" "$LOG_FILE" 2>/dev/null | awk '
    {
        status = ""; term = ""; cip = ""; host = ""; id = ""; ts = ""; req = ""

        # %tr is bracketed: [22/Aug/2026:10:11:12.345] -> keep HH:MM:SS
        # No {n} interval expressions here: not every awk in a slim Debian
        # image supports them. Spelled out instead.
        if (match($0, /\[[0-9][0-9]\/[A-Za-z][A-Za-z][A-Za-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
            ts = substr($0, RSTART + 13, 8)
        }

        # Anchor on the %TR/%Tw/%Tc/%Tr/%Ta timers block: %ST follows it, and
        # the termination state (%tsc) is 4 fields further on (%B %CC %CS %tsc).
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^[+-]?[0-9]+\/[+-]?[0-9]+\/[+-]?[0-9]+\/[+-]?[0-9]+\/[+-]?[0-9]+$/) {
                status = $(i + 1)
                term = $(i + 5)
                break
            }
        }

        # Only enforcement outcomes: tarpit (PT--), deny (PR--), 403, 429.
        if (!(term ~ /^PT/ || term ~ /^PR/ || status == "403" || status == "429")) next

        for (i = 1; i <= NF; i++) {
            if (substr($i, 1, 4) == "cip=")  cip  = substr($i, 5)
            if (substr($i, 1, 5) == "host=") host = substr($i, 6)
            if (substr($i, 1, 3) == "id=")   id   = substr($i, 4)
        }

        if (match($0, /"[A-Z]+ [^"]*"/)) {
            req = substr($0, RSTART + 1, RLENGTH - 2)
            if (length(req) > 42) req = substr(req, 1, 41) "..."
        }

        if (cip == "") cip = "-"
        if (host == "") host = "-"
        if (term == "") term = "-"
        if (status == "") status = "-"
        printf "%-15s %-16s %-4s %-5s %-28s %s\n", ts, cip, status, term, host, req
        if (id != "" && id != "-") printf "%-15s %s\n", "", "  id=" id
        n++
    }
    END { if (n == 0) print "(no tarpit/deny/403/429 events in the scanned window)" }
    ')
    printf '%s\n' "$found"
    echo
    echo "TERM = HAProxy termination state: PT-- tarpit, PR-- deny (incl. WAF/rate limit)."
    echo "id=  = request reference; it is printed on the block page and is how a"
    echo "       customer support ticket correlates to an exact request here."
}

banner() {
    echo "==================================================="
    echo "HAProxy Edge Monitor - $(date '+%Y-%m-%d %H:%M:%S')"
    echo "==================================================="
    echo
}

if [ "${1:-}" = "live" ]; then
    echo "Live monitoring mode - Press Ctrl+C to exit"
    while true; do
        clear
        banner
        show_rates || true
        echo
        show_recent_blocks
        sleep 5
    done
else
    banner
    rc=0
    show_rates || rc=$?
    echo
    show_recent_blocks
    echo
    echo "Tip: run with 'live' for a refreshing view."
    echo "Usage: $0 [live]"
    # Propagate a stick-table read failure: if the rates section could not be
    # produced, this run did NOT report what it claims to report.
    exit "$rc"
fi
