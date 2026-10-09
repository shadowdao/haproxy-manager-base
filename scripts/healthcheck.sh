#!/usr/bin/env bash
# Container liveness probe: BOTH planes must answer quickly.
#
#   1. Management API (:8000) -- GET /health with a short --max-time. On
#      2026-10-09 (sdbees) the API workers' thread pools were wedged for long
#      enough that /health hung 40s+, while the container reported "healthy"
#      because the deployed --health-cmd only probed :80. A hung API is a dead
#      control plane (every WHP site update times out), so it must turn the
#      container unhealthy.
#   2. HAProxy data plane (:80) -- any HTTP answer at all (the default page,
#      a redirect, a 4xx/5xx) proves HAProxy accepted and answered. Only a
#      connect/timeout failure fails it, which is why there is no -f here.
#
# 127.0.0.1, not localhost: the API binds IPv4 only, and resolving localhost
# to ::1 first costs a failed connect on every probe.
#
# WHP's lib-edge-container.sh overrides the image HEALTHCHECK with its own
# --health-cmd; point that at this script so the fleet gets the same probe.
set -u
API_TIMEOUT="${HAPROXY_MGR_HEALTH_API_TIMEOUT:-4}"
EDGE_TIMEOUT="${HAPROXY_MGR_HEALTH_EDGE_TIMEOUT:-5}"

if ! curl -sf -o /dev/null --max-time "$API_TIMEOUT" http://127.0.0.1:8000/health; then
    echo "management API :8000 /health failed or took longer than ${API_TIMEOUT}s"
    exit 1
fi
if ! curl -s -o /dev/null --max-time "$EDGE_TIMEOUT" http://127.0.0.1/; then
    echo "HAProxy :80 did not answer within ${EDGE_TIMEOUT}s"
    exit 1
fi
exit 0
