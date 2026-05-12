# Coraza-SPOA backend.
# Only rendered into haproxy.cfg when HAPROXY_CORAZA_SPOE_BACKEND env var is
# set on the haproxy-manager container. SPOE traffic to this backend is TCP,
# not HTTP. The agent target comes from the env var so a single image can be
# deployed against different sidecar host:port pairs (typically the sidecar
# container's name + 9000 inside the shared docker network).
backend coraza-spoa-backend
    mode tcp
    timeout connect 5s
    timeout server  30s
    # Keep-alive connection to the SPOA — saves a TCP handshake on every
    # request. SPOE protocol multiplexes multiple requests over one
    # connection so this is normal.
    server coraza-spoa {{ agent_target }} check inter 30s rise 2 fall 3
