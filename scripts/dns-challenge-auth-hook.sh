#!/usr/bin/env bash
set -euo pipefail

# Certbot DNS-01 auth hook
# Called by certbot with CERTBOT_DOMAIN and CERTBOT_VALIDATION env vars
# Writes the validation token for the API to read, then waits for proceed signal

TOKEN_FILE="/tmp/dns-challenge-${CERTBOT_DOMAIN}.token"
PROCEED_FILE="/tmp/dns-challenge-${CERTBOT_DOMAIN}.proceed"

# Write the challenge token so the API can return it to the caller
echo "${CERTBOT_VALIDATION}" > "${TOKEN_FILE}"

# Wait for the proceed signal (PHP side sets DNS record, then calls verify endpoint)
MAX_WAIT=300
ELAPSED=0

while [ ${ELAPSED} -lt ${MAX_WAIT} ]; do
    if [ -f "${PROCEED_FILE}" ]; then
        # Give DNS a moment to propagate after the signal
        sleep 5
        exit 0
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

echo "Timed out waiting for proceed signal for ${CERTBOT_DOMAIN}" >&2
exit 1
