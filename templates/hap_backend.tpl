
backend {{ name }}-backend

    option forwardfor
    http-request add-header X-CLIENT-IP %[src]
    {% if ssl_enabled %} ttp-request set-header X-Forwarded-Proto https if \{ ssl_fc \} {% endif %}
    {% for server in servers %}
    server {{ server.name }} {{ server.address }}:{{ server.port }} {{ server.options }}
    {% endfor %}
