#!/bin/bash

# Script to display IPs that have been tarpitted by HAProxy 3.0
# Uses HAProxy stats socket to query stick-table data
#
# Usage in Docker container:
#   docker exec -it haproxy-manager /haproxy/scripts/show-tarpit-ips.sh

SOCKET="/tmp/haproxy-cli"

# Check if socket exists
if [ ! -S "$SOCKET" ]; then
    echo "Error: HAProxy socket not found at $SOCKET"
    echo "Make sure HAProxy is running with stats socket enabled"
    exit 1
fi

echo "==================================================================="
echo "                    HAProxy Tarpitted IPs Report                   "
echo "==================================================================="
echo
echo "Showing IPs tracked in the stick-table with scan detection counters:"
echo "(gpc0 = total scan attempts, gpc1 = escalation level)"
echo

# In HAProxy 3.0, we need to use the proper process prefix
# The web frontend table is in the worker process, not master
# First check which process has the table
# Note: grep for actual worker line, not the header
PROCESS_ID=$(echo "show proc" | socat stdio "$SOCKET" 2>/dev/null | grep -E '^[0-9]+.*worker' | awk '{print $1}' | head -1)

if [ -z "$PROCESS_ID" ]; then
    echo "Error: Could not find HAProxy worker process"
    echo "Try: echo 'show proc' | socat stdio $SOCKET"
    exit 1
fi

# Show stick-table entries from the web frontend using the worker process
# Use printf to avoid bash history expansion issues with !
printf "@!%s show table web\n" "${PROCESS_ID}" | socat stdio "$SOCKET" 2>/dev/null | {
    # Skip the header line
    read header
    
    # Check if we got an error or empty response
    if echo "$header" | grep -q "No such table"; then
        echo "Error: Table 'web' not found. HAProxy may need to be reloaded."
        exit 1
    fi
    
    has_data=false
    echo "IP Address           | Scan Count | Level | HTTP Err Rate | Status"
    echo "---------------------|------------|-------|---------------|------------------"
    
    # Process each line
    while IFS= read -r line; do
        # Skip empty lines and comments
        if [ -z "$line" ] || echo "$line" | grep -q "^#"; then
            continue
        fi
        
        # HAProxy 3.0 format: 0x... key=<ip> use=... exp=... gpc0=... gpc1=... http_err_rate(10s)=...
        if echo "$line" | grep -q "key="; then
            has_data=true
            
            # Extract IP and counters
            ip=$(echo "$line" | grep -o 'key=[^ ]*' | cut -d'=' -f2)
            gpc0=$(echo "$line" | grep -o 'gpc0=[0-9]*' | cut -d'=' -f2)
            gpc1=$(echo "$line" | grep -o 'gpc1=[0-9]*' | cut -d'=' -f2)
            err_rate=$(echo "$line" | grep -o 'http_err_rate([^)]*=[0-9]*' | grep -o '[0-9]*$')
            
            # Set defaults if values are empty
            gpc0=${gpc0:-0}
            gpc1=${gpc1:-0}
            err_rate=${err_rate:-0}
            
            # Determine status based on scan count and escalation
            status=""
            if [ "$gpc0" -ge 50 ]; then
                status="BLOCKED (429)"
            elif [ "$gpc0" -ge 35 ]; then
                status="SILENT-DROP"
            elif [ "$gpc0" -ge 20 ]; then
                if [ "$gpc1" -ge 2 ]; then
                    status="SILENT-DROP (repeat)"
                else
                    status="TARPIT 10s"
                fi
            elif [ "$gpc0" -ge 10 ]; then
                status="TARPIT 10s"
            else
                status="Normal"
            fi
            
            # Format output
            printf "%-20s | %10s | %5s | %13s | %s\n" "$ip" "$gpc0" "$gpc1" "$err_rate/10s" "$status"
        fi
    done
    
    if [ "$has_data" = false ]; then
        echo "(No IPs currently tracked - table is empty)"
    fi
}

echo
echo "==================================================================="
echo "Legend:"
echo "  - Scan Count 10-19: Low scanner → TARPIT 10s delay"
echo "  - Scan Count 20-34: Medium scanner → TARPIT 10s (1st), SILENT-DROP (repeat)"
echo "  - Scan Count 35-49: High scanner → SILENT-DROP (immediate disconnect)"
echo "  - Scan Count 50+:   Critical scanner → BLOCKED (429 response)"
echo "  - Burst (5+ in 10s): → TARPIT 10s (1st), SILENT-DROP (repeat)"
echo "==================================================================="
echo "Note: IPs are tracked for 1 hour since last activity"
echo
echo "To clear a specific IP from the table:"
echo "  printf '@!${PROCESS_ID} del table web key <IP>\\n' | socat stdio $SOCKET"
echo
echo "To clear all entries:"
echo "  printf '@!${PROCESS_ID} clear table web\\n' | socat stdio $SOCKET"
echo
echo "Debug: Worker PID is ${PROCESS_ID}"
echo