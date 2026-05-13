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
    # init-addr last,none: tolerate startup-time DNS resolution failure
    # (the upstream container may not be up yet when haproxy-manager starts).
    # resolvers docker_dns: re-resolve via Docker's embedded DNS at 127.0.0.11
    # so the server picks up the real IP once the upstream becomes available
    # (the docker_dns block is defined in hap_header.tpl).
    server suspended {{ target }} check inter 30s init-addr last,none resolvers docker_dns
