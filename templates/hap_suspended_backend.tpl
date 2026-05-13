# Suspended-site backend. Used when external tooling adds a host to
# /etc/haproxy/suspended_domains.list (read by an ACL in the frontend).
# The backend points at a single upstream that serves a static 503
# "site temporarily unavailable" page. Only rendered when the
# HAPROXY_SUSPENSION_BACKEND env var is set on the haproxy-manager
# container; non-WHP deployments (home networks, standalone use) see
# no change to haproxy.cfg.
backend bk_suspended
    mode http
    option http-server-close
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-For %[src]
    server suspended {{ target }} check inter 30s
