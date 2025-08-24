#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    # Stick table for tracking attacks with escalating timeouts
    # gpc0 = total scan attempts
    # gpc1 = escalation level (0=none, 1=level1, 2=level2, 3=level3)  
    stick-table type ip size 200k expire 2h store gpc0,gpc1,http_err_rate(10s)
    
    # Whitelist trusted networks and monitoring systems
    acl trusted_networks src 127.0.0.1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
    acl health_check path_beg /health /ping /status /.well-known/
    
    # Allow trusted traffic to bypass all protection
    http-request allow if trusted_networks or health_check
    
    # Detect real client IP from proxy headers if they exist
    # Priority: CF-Connecting-IP (Cloudflare) > X-Real-IP > X-Forwarded-For > src
    acl has_cf_connecting_ip req.hdr(CF-Connecting-IP) -m found
    acl has_x_real_ip req.hdr(X-Real-IP) -m found
    acl has_x_forwarded_for req.hdr(X-Forwarded-For) -m found
    
    # Set the real IP based on available headers
    http-request set-var(txn.real_ip) req.hdr(CF-Connecting-IP) if has_cf_connecting_ip
    http-request set-var(txn.real_ip) req.hdr(X-Real-IP) if !has_cf_connecting_ip has_x_real_ip
    http-request set-var(txn.real_ip) req.hdr(X-Forwarded-For) if !has_cf_connecting_ip !has_x_real_ip has_x_forwarded_for
    http-request set-var(txn.real_ip) src if !has_cf_connecting_ip !has_x_real_ip !has_x_forwarded_for
    
    # Track the real client IP in stick table (not the proxy IP)
    http-request track-sc0 var(txn.real_ip)
    
    # IP blocking using map file (no word limit, runtime updates supported)
    # Map file: /etc/haproxy/blocked_ips.map
    # Runtime updates: echo "add map #0 IP_ADDRESS" | socat stdio /var/run/haproxy.sock
    # Now checks the real client IP (from headers if present, otherwise src)
    http-request set-path /blocked-ip if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
    use_backend default-backend if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
    
    # Define threat levels based on accumulated error responses from backends
    # These will be checked on subsequent requests after errors are tracked
    acl scanner_low sc0_get_gpc0 ge 5          # 5+ errors = potential scanner
    acl scanner_medium sc0_get_gpc0 ge 15      # 15+ errors = likely scanner
    acl scanner_high sc0_get_gpc0 ge 30        # 30+ errors = confirmed scanner
    acl scanner_critical sc0_get_gpc0 ge 50    # 50+ errors = aggressive scanner
    
    # Rate-based detection (burst of errors)
    acl burst_scanner sc0_http_err_rate gt 5   # >5 errors in 10 seconds
    
    # BLOCKING RULES - Block aggressive scanners completely
    # Only block after significant error accumulation
    http-request deny deny_status 429 if scanner_critical
    
    # TARPIT RULES - Slow down detected scanners
    # Apply progressive delays based on error count
    http-request tarpit if scanner_high
    http-request tarpit if scanner_medium burst_scanner
    
    # Note: The backend will increment sc0_get_gpc0 when it sees 400/401/403/404 responses
