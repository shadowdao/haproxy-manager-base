
# Regular HTTP backend - uses http-server-close for better security and connection management
backend {{ name }}-backend
    option forwardfor
    # Pass the real client IP to backend (from proxy headers or direct connection)
    # This is crucial for container-level logging and security tools
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    http-request set-header X-Forwarded-For %[var(txn.real_ip)]
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }

    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}
    {% endfor %}

# SSE-specific backend - optimized for Server-Sent Events long-lived connections
backend {{ name }}-sse-backend
    # Disable http-server-close to allow SSE long-lived connections
    no option http-server-close

    # Enable http-no-delay for immediate data transmission
    option http-no-delay

    # Extended timeouts to support SSE long-lived connections (up to 6 hours)
    # Note: SSE sends keepalives every 1 second, so timeout only triggers if backend hangs
    timeout server 6h
    timeout http-keep-alive 6h

    option forwardfor
    # Pass the real client IP to backend (from proxy headers or direct connection)
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    http-request set-header X-Forwarded-For %[var(txn.real_ip)]
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Proto http if !{ ssl_fc }

    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}
    {% endfor %}
