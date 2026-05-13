# Coraza-SPOA backend.
# Only rendered into haproxy.cfg when HAPROXY_CORAZA_SPOE_BACKEND env var is
# set on the haproxy-manager container. SPOE traffic to this backend is TCP,
# not HTTP. The agent target comes from the env var so a single image can be
# deployed against different sidecar host:port pairs (typically the sidecar
# container's name + 9000 inside the shared docker network).
backend coraza-spoa-backend
    mode tcp
    # spop-check actually speaks the SPOE protocol against the agent —
    # confirms the agent can negotiate a session, not just that the TCP
    # port is open. Required to detect a half-broken SPOA that's listening
    # but not actually processing.
    option spop-check
    timeout connect 5s
    timeout server  30s
    server coraza-spoa {{ agent_target }} check
