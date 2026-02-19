#!/usr/bin/env bash
set -euo pipefail

# Certbot DNS-01 cleanup hook
# Removes temporary challenge files after certbot finishes

TOKEN_FILE="/tmp/dns-challenge-${CERTBOT_DOMAIN}.token"
PROCEED_FILE="/tmp/dns-challenge-${CERTBOT_DOMAIN}.proceed"

rm -f "${TOKEN_FILE}" "${PROCEED_FILE}"
