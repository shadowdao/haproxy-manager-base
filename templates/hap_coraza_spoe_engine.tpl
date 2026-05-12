# Coraza SPOE engine configuration.
#
# Written to /etc/haproxy/coraza-spoe.cfg by haproxy_manager.generate_config()
# when HAPROXY_CORAZA_SPOE_BACKEND env var is set. Referenced from haproxy.cfg
# via `filter spoe engine coraza config /etc/haproxy/coraza-spoe.cfg`.
#
# Engine name "coraza" must match the engine name in the filter line in the
# main config and the application name "haproxy" must match the application
# block name in coraza-spoa's config.yaml.

[coraza]

spoe-agent coraza
    # The single message we send (defined below) — per-request inspection.
    messages    coraza-check

    # Prefix for any variables the agent sets back on the request.
    option      var-prefix coraza

    # FAIL-OPEN. If the SPOA is unreachable or times out, requests flow
    # through uninspected rather than failing. For a hosting platform,
    # availability beats unconditional inspection coverage.
    option      set-on-error continue

    # Aggressive timeouts: we don't want the WAF to materially slow page
    # loads. processing 100ms is the per-request inspection budget.
    timeout     hello       2s
    timeout     idle        2m
    timeout     processing  100ms

    use-backend coraza-spoa-backend
    log         global

spoe-message coraza-check
    # Send the request shape to Coraza for inspection.
    # `app=str(haproxy)` matches the application named "haproxy" in
    # coraza-spoa's config.yaml — that's how Coraza picks which ruleset
    # to apply.
    args        app=str(haproxy) \
                src-ip=src \
                src-port=src_port \
                dest-ip=dst \
                dest-port=dst_port \
                method=method \
                path=path \
                query=query \
                version=req.ver \
                headers=req.hdrs \
                body=req.body
    event       on-frontend-http-request
