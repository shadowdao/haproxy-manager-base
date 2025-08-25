
backend {{ name }}-backend
    option forwardfor
    # Pass the real client IP to backend (from proxy headers or direct connection)
    http-request add-header X-CLIENT-IP %[var(txn.real_ip)]
    http-request set-header X-Real-IP %[var(txn.real_ip)]
    
    # Define error status codes
    acl is_404_error status 404
    acl is_403_error status 403  
    acl is_401_error status 401
    acl is_400_error status 400
    
    # Define suspicious scan patterns - only these count as scan attempts
    acl scan_scripts path_reg -i \.(php|asp|aspx|jsp|cgi|pl|py|rb|sh|bash)$
    acl scan_admin path_reg -i /(wp-admin|wp-login|phpmyadmin|adminer|manager|admin-console)
    acl scan_configs path_reg -i \.(env|git|svn|htaccess|htpasswd|ini|conf|config|yml|yaml|toml)
    acl scan_backups path_reg -i \.(backup|bak|old|orig|save|swp|sql|db|dump|tar|zip|rar|7z)
    acl scan_vulns path_reg -i /(cgi-bin|fckeditor|tiny_mce|ckfinder|userfiles|filemanager)
    
    # Combine all scan patterns
    acl is_suspicious_request scan_scripts or scan_admin or scan_configs or scan_backups or scan_vulns
    
    # Define legitimate static assets that should NOT count
    acl legitimate_assets path_reg -i \.(css|js|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot|otf|map|webp|mp4|webm|pdf)$
    acl legitimate_paths path_beg /static/ /assets/ /media/ /images/ /fonts/ /css/ /js/
    
    # Only count suspicious 404s and auth failures
    acl is_scan_attempt is_suspicious_request is_404_error !legitimate_assets !legitimate_paths
    acl is_scan_attempt is_403_error !legitimate_assets !legitimate_paths
    acl is_scan_attempt is_401_error
    
    # Track scan attempts in the frontend stick table
    http-response sc-inc-gpc0(0) if is_scan_attempt
    
    {% for server in servers %}
    server {{ server.server_name }} {{ server.server_address }}:{{ server.server_port }} {{ server.server_options }}
    {% endfor %}
    