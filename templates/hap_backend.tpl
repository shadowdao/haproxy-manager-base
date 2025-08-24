
backend {{ name }}-backend
    option forwardfor
    # Pass the real client IP to backend (from proxy headers or direct connection)
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    {% if ssl_enabled %}http-request set-header X-Forwarded-Proto https if { ssl_fc }{% endif %}
    
    # Define scanning attempt patterns
    acl is_404_error status 404
    acl is_403_error status 403  
    acl is_401_error status 401
    acl is_400_error status 400
    acl is_scan_attempt status 400 401 403 404
    
    # Additional suspicious patterns
    acl suspicious_path path_reg -i \.(php|asp|aspx|jsp|cgi)$
    acl suspicious_path path_reg -i /(wp-admin|phpmyadmin|admin|login|xmlrpc)
    acl suspicious_path path_reg -i \.(env|git|svn|backup|bak|old)
    
    # Track scan attempts in the frontend stick table
    # This increments the counter AFTER the backend responds with an error
    # The frontend will check this counter on SUBSEQUENT requests
    http-response sc-inc-gpc0(0) if is_scan_attempt
    
    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}
    {% endfor %}
    