# Long-lived backend for {{ name }} (template_override='hap_backend_longlived').
# Use for apps whose PRIMARY traffic holds connections open: media streaming,
# large up/downloads, or persistent viewer/streaming sessions. Both the primary
# and the SSE backend are tuned long-lived here (no http-server-close,
# http-no-delay, 6h server/tunnel/keep-alive timeouts).
#
# Compare hap_backend_websocket.tpl, which keeps the PRIMARY backend standard
# and only makes the -sse-backend long-lived. Pick this one when the main path
# itself needs long-lived connections, not just an SSE side-channel.
backend {{ name }}-backend
    no option http-server-close
    option http-no-delay
    timeout server 6h
    timeout tunnel 6h
    timeout http-keep-alive 6h
    option forwardfor
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    http-request set-header X-Forwarded-For %[var(txn.real_ip)]
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }} resolvers docker_dns init-addr last,libc,none
    {% endfor %}

# SSE variant (Accept: text/event-stream / ?action=stream auto-routes here)
backend {{ name }}-sse-backend
    no option http-server-close
    option http-no-delay
    timeout server 6h
    timeout tunnel 6h
    timeout http-keep-alive 6h
    option forwardfor
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    http-request set-header X-Forwarded-For %[var(txn.real_ip)]
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }
    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }} resolvers docker_dns init-addr last,libc,none
    {% endfor %}
