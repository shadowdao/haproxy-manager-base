#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    # Stick table for tracking attacks with escalating timeouts
    # gpc0 = total scan attempts
    # gpc1 = escalation level (0=none, 1=level1, 2=level2, 3=level3)  
    stick-table type ip size 200k expire 1h store gpc0,gpc1,http_err_rate(10s)
    
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
    acl scanner_low sc0_get_gpc0 ge 10         # 10+ errors = potential scanner
    acl scanner_medium sc0_get_gpc0 ge 20      # 20+ errors = likely scanner
    acl scanner_high sc0_get_gpc0 ge 35        # 35+ errors = confirmed scanner
    acl scanner_critical sc0_get_gpc0 ge 50    # 50+ errors = aggressive scanner
    
    # Rate-based detection (burst of errors)
    acl burst_scanner sc0_http_err_rate gt 5   # >5 errors in 10 seconds
    
    # Escalation levels (tracks how many times we've escalated this IP)
    acl escalation_level_0 sc0_get_gpc1 eq 0   # First offense
    acl escalation_level_1 sc0_get_gpc1 eq 1   # Second offense
    acl escalation_level_2 sc0_get_gpc1 eq 2   # Third offense
    acl escalation_level_3 sc0_get_gpc1 ge 3   # Repeat offender
    
    # BLOCKING RULES - Progressive response based on threat level
    
    # Level 4: Complete block for critical threats (50+ errors)
    http-request deny deny_status 429 if scanner_critical
    
    # Level 3: Silent drop for obvious scanners and burst attacks
    # This immediately closes the connection without any response
    http-request silent-drop if scanner_high              # 35+ errors
    http-request silent-drop if scanner_medium burst_scanner  # 20+ errors with burst
    http-request silent-drop if scanner_medium escalation_level_2  # Repeat medium scanner
    http-request silent-drop if burst_scanner escalation_level_1   # Repeat burst scanner
    
    # Level 2: Tarpit for medium scanners (first offense)
    # 10 second delay before closing connection
    http-request tarpit deny_status 429 if scanner_medium escalation_level_0
    http-request tarpit deny_status 429 if scanner_medium escalation_level_1
    
    # Level 1: Tarpit for low-level scanners
    # 10 second delay to slow them down
    http-request tarpit deny_status 429 if scanner_low
    http-request tarpit deny_status 429 if burst_scanner escalation_level_0
    
    # Increment escalation level when we apply any protection
    # This tracks how many times this IP has been actioned
    http-request sc-inc-gpc1(0) if scanner_low or scanner_medium or scanner_high or burst_scanner
    
    # Note: The backend will increment sc0_get_gpc0 when it sees 400/401/403/404 responses
