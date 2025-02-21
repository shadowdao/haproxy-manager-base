
backend {{ name }}-backend
    {% for server in servers %}server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}{% endfor %}
    