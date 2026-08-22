#!/usr/bin/env bash
#
# DEPRECATED SHIM — kept so existing docs/runbooks/muscle memory keep working.
#
# This script used to print a "Tarpitted IPs Report" with a "Scan Count" and a
# BLOCKED / SILENT-DROP / TARPIT status per IP, all derived from gpc0 and gpc1
# stick-table columns. Those columns DO NOT EXIST: the `web` table
# (templates/hap_listener.tpl) stores only conn_cur, conn_rate, http_req_rate
# and http_err_rate. The old parser defaulted every missing field to 0, so the
# whole report was fabricated — every IP showed "Scan Count 0 / Normal"
# regardless of what it was actually doing.
#
# The stick table also keeps NO history, so nothing in it can identify who was
# tarpitted. Real enforcement events live in the access log ON THE DOCKER HOST
# at /var/log/haproxy.log (it does not exist inside this container):
#   grep -aE ' (PT|PR)--' /var/log/haproxy.log | tail -20   # tarpit / deny
#   grep -aE ' (429|403) ' /var/log/haproxy.log | tail -20  # rate-limit / block
#
# What IS knowable from the stick table — the current per-IP rates — is printed
# by show-edge-ip-rates.sh, which this shim now runs.

set -euo pipefail

cat >&2 <<'NOTE'
NOTE: show-tarpit-ips.sh is deprecated and cannot report tarpits.
      The HAProxy stick table stores no history and no gpc0/gpc1 counters, so
      the old "Scan Count"/"BLOCKED" columns were fabricated numbers.
      Actual tarpit/deny events are in /var/log/haproxy.log ON THE HOST:
        grep -aE ' (PT|PR)--' /var/log/haproxy.log | tail -20
      Running show-edge-ip-rates.sh instead (current rates, real values):

NOTE

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$SCRIPT_DIR/show-edge-ip-rates.sh" "$@"
