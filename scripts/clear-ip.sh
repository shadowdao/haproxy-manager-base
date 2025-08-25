#!/bin/bash

# Script to clear a specific IP from HAProxy stick-table
# Usage: ./clear-ip.sh <IP_ADDRESS>

if [ $# -ne 1 ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    echo "Example: $0 192.168.1.100"
    exit 1
fi

IP="$1"
SOCKET="/tmp/haproxy-cli"

# Check if socket exists
if [ ! -S "$SOCKET" ]; then
    echo "Error: HAProxy socket not found at $SOCKET"
    exit 1
fi

# Get worker process ID
PROCESS_ID=$(echo "show proc" | socat stdio "$SOCKET" 2>/dev/null | grep -E '^[0-9]+.*worker' | awk '{print $1}' | head -1)

if [ -z "$PROCESS_ID" ]; then
    echo "Error: Could not find HAProxy worker process"
    exit 1
fi

echo "Clearing IP $IP from stick-table..."

# Clear the IP from the table
printf "@!%s del table web key %s\n" "${PROCESS_ID}" "${IP}" | socat stdio "$SOCKET" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "Successfully cleared $IP from the stick-table"
else
    echo "Failed to clear $IP (may not exist in table)"
fi

# Verify it's gone
echo
echo "Checking if IP is still in table..."
printf "@!%s show table web\n" "${PROCESS_ID}" | socat stdio "$SOCKET" 2>/dev/null | grep "key=$IP" > /dev/null

if [ $? -eq 0 ]; then
    echo "Warning: IP $IP is still in the table"
else
    echo "Confirmed: IP $IP has been removed"
fi