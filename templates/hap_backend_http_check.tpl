
backend {{ name }}-backend
    option forwardfor
    option httpchk
    # Pass the real client IP to backend (from proxy headers or direct connection)
    # This is crucial for container-level logging and security tools
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    http-request set-header X-Forwarded-For %[var(txn.real_ip)]
    {% if ssl_enabled %}http-request set-header X-Forwarded-Proto https if { ssl_fc }{% endif %}
    
    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}
    {% endfor %}
    