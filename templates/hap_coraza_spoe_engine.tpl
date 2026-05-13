# Coraza SPOE engine configuration.
#
# Written to /etc/haproxy/coraza-spoe.cfg by haproxy_manager.generate_config()
# when HAPROXY_CORAZA_SPOE_BACKEND env var is set. Referenced from haproxy.cfg
# via `filter spoe engine coraza config /etc/haproxy/coraza-spoe.cfg`.
#
# Engine name "coraza" must match the engine name in the filter line in the
# main config; group name "coraza-req" must match the send-spoe-group action.
# Application name "haproxy" must match the application block in coraza-spoa's
# config.yaml.
#
# Reference: this config follows the shape from coraza-spoa's upstream
# example/haproxy/coraza.cfg (v0.7.1). Arg names + ordering are required by
# Coraza-SPOA exactly as specified — DO NOT reorder or rename without
# coordinating with the agent.

[coraza]

spoe-agent coraza
    # `groups` (not `messages`) lists the spoe-group names this engine offers
    # via `send-spoe-group` actions. The same group name appears below in a
    # spoe-group block, which in turn references the actual message.
    groups      coraza-req

    # Prefix for variables the agent sets back on the request transaction —
    # e.g. var(txn.coraza.error) when set-on-error triggers.
    option      var-prefix coraza

    # On agent error/timeout, set var(txn.coraza.error). We DON'T add a
    # corresponding `http-request deny if { var(txn.coraza.error) -m bool }`
    # in the frontend, so the request continues uninspected. This is the
    # fail-open posture: WAF outage shouldn't 503 customer traffic.
    option      set-on-error error

    timeout     hello       2s
    timeout     idle        2m
    timeout     processing  100ms

    use-backend coraza-spoa-backend
    log         global

# Per-request inspection message. No `event` directive — fires only when
# explicitly invoked from haproxy.cfg via `http-request send-spoe-group`.
# Arg order/names are mandatory: Coraza-SPOA parses positionally and renames
# break the agent. `app=str(haproxy)` is the literal application name from
# coraza-spoa's config.yaml `applications:` block.
spoe-message coraza-req
    args app=str(haproxy) src-ip=src src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body

# Group binding for send-spoe-group invocation in the frontend. One group,
# one message; could add more in the future (e.g. coraza-res for response
# inspection — currently disabled in coraza-spoa's config.yaml).
spoe-group coraza-req
    messages coraza-req
