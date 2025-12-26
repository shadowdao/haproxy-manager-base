
backend {{ name }}-backend
    # Detect Server-Sent Events (SSE) connections
    # SSE uses Accept: text/event-stream or ?action=stream query parameter
    acl is_sse hdr(accept) -i -m sub text/event-stream
    acl is_sse_url urlp(action) -i -m str stream

    # Disable http-server-close from defaults to allow SSE long-lived connections
    # Normal HTTP requests still work fine without this option
    no option http-server-close

    # Enable http-no-delay for immediate data transmission (good for SSE and general performance)
    option http-no-delay

    # Extended timeouts to support SSE long-lived connections (up to 6 hours)
    # These values also work fine for normal HTTP requests
    # Note: SSE sends keepalives every 1 second, so timeout only triggers if backend hangs
    timeout server 6h
    timeout http-keep-alive 6h

    # Ensure keep-alive connection for SSE requests
    http-response set-header Connection keep-alive if is_sse or is_sse_url

    option forwardfor
    # Pass the real client IP to backend (from proxy headers or direct connection)
    # This is crucial for container-level logging and security tools
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    http-request set-header X-Forwarded-For %[var(txn.real_ip)]
    {% if ssl_enabled %}http-request set-header X-Forwarded-Proto https if { ssl_fc }{% endif %}


    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}
    {% endfor %}
