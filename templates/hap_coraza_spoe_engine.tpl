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
# example/haproxy/coraza.cfg (v0.7.1). Arg NAMES are a contract with
# coraza-spoa — DO NOT rename without coordinating with the agent. Ordering:
# only `app` is positional (it must be FIRST); the rest are matched by name.

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

    # NO `log global` here, deliberately.
    #
    # `log global` in a spoe-agent emits one line PER INSPECTED REQUEST, e.g.
    #   SPOE: [coraza] <GROUP:coraza-req> sid=537 st=0 0/0/0/0/0 32/32 0/0 0/467
    # Measured on whp01 immediately after access logging started working:
    # 618 SPOE lines vs 669 real access lines -- it was ~48% of the log volume,
    # i.e. it would roughly DOUBLE the edge's log footprint (~400 MB/day extra)
    # to record `st=0` over and over.
    #
    # It carries nothing incident response needs: the WAF's verdict is already
    # visible in the access log line (status 403 + the `id=` UUID, which joins
    # to /var/log/coraza/audit.log for the rule_id), and per-transaction WAF
    # detail is written by the SPOA itself to /var/log/coraza/spoa.log.
    # Agent-level failures still surface via `option set-on-error error` ->
    # var(txn.coraza.error) and the fail-open path in hap_listener.tpl.

# Per-request inspection message. No `event` directive — fires only when
# explicitly invoked from haproxy.cfg via `http-request send-spoe-group`.
#
# How coraza-spoa v0.7.1 reads these args (measured from source, not inferred):
#   * `app` MUST be the first arg. internal/agent.go HandleSPOE reads exactly
#     one KV entry and Panics if its name is not "app".
#   * Every other arg is matched BY NAME in a switch (internal/application.go
#     HandleRequest); order is irrelevant and unknown names are ignored with a
#     debug log. So a typo'd name silently drops that input — renames still
#     break inspection, they just don't error.
# `app=str(haproxy)` is the literal application name from coraza-spoa's
# config.yaml `applications:` block.
#
# id=unique-id makes Coraza's transaction ID the SAME UUID HAProxy generates
# via `unique-id-format %[uuid()]` (hap_header.tpl) — the value shown on the
# 403-waf.html page, sent as X-Request-Reference, and logged as `id=` in
# /var/log/haproxy.log. coraza-spoa passes it to waf.NewTransactionWithID(),
# so it becomes `transaction.id` in /var/log/coraza/audit.log and
# `match.unique_id` in /var/log/coraza/spoa.log: a customer-quoted reference
# greps straight to the rule that fired. Without it coraza-spoa invents a
# random 16-letter A-Z ID that appears nowhere on the HAProxy side. If the
# fetch ever came back empty the agent falls back to that random ID, so this
# cannot break inspection.
#
# Response inspection (a `coraza-res` message) is NOT configured:
# config.yaml has response_check: false. If it is ever enabled, coraza-res
# MUST also send `id=unique-id` -- HandleResponse
# looks the request transaction up by that ID and errors without it.
#
# src-ip uses var(txn.real_ip) — HAProxy resolves the real client IP at the
# top of the frontend (CF-Connecting-IP > X-Real-IP > X-Forwarded-For > src,
# only honoring those headers from trusted proxies). Falls back to `src`
# when no proxy headers are present. This is what shows up as `client_ip`
# in /var/log/coraza/audit.log and the rule manager's view-matches panel.
spoe-message coraza-req
    args app=str(haproxy) id=unique-id src-ip=var(txn.real_ip) src-port=src_port dst-ip=dst dst-port=dst_port method=method path=path query=query version=req.ver headers=req.hdrs body=req.body

# Group binding for send-spoe-group invocation in the frontend. One group,
# one message; could add more in the future (e.g. coraza-res for response
# inspection — currently disabled in coraza-spoa's config.yaml).
spoe-group coraza-req
    messages coraza-req
