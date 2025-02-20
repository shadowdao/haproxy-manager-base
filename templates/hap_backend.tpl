
backend {{ name }}-backend
    option forwardfor
    http-request add-header X-CLIENT-IP %[src]
    {% if ssl_enabled %}http-request set-header X-Forwarded-Proto https if { ssl_fc }{% endif %}
    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}
    {% endfor %}