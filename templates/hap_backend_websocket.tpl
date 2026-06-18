# Long-lived / websocket-safe backend for {{ name }} (template_override)
# For apps with persistent WebSocket/streaming connections (e.g. Jitsi /xmpp-websocket, /colibri-ws).
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
