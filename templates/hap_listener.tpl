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
    
    # BLOCKING RULES - Block aggressive scanners completely
    # Only block after significant error accumulation
    http-request deny deny_status 429 if scanner_critical
    
    # ESCALATING TARPIT RULES - Progressive delays based on offense level
    # Level 0 (first offense): Short delays
    http-request tarpit deny_status 429 timeout 2s if scanner_low escalation_level_0
    http-request tarpit deny_status 429 timeout 3s if scanner_medium escalation_level_0
    http-request tarpit deny_status 429 timeout 5s if scanner_high escalation_level_0
    http-request tarpit deny_status 429 timeout 5s if burst_scanner escalation_level_0
    
    # Level 1 (second offense): Medium delays
    http-request tarpit deny_status 429 timeout 8s if scanner_low escalation_level_1
    http-request tarpit deny_status 429 timeout 12s if scanner_medium escalation_level_1
    http-request tarpit deny_status 429 timeout 15s if scanner_high escalation_level_1
    http-request tarpit deny_status 429 timeout 10s if burst_scanner escalation_level_1
    
    # Level 2 (third offense): Long delays
    http-request tarpit deny_status 429 timeout 20s if scanner_low escalation_level_2
    http-request tarpit deny_status 429 timeout 30s if scanner_medium escalation_level_2
    http-request tarpit deny_status 429 timeout 45s if scanner_high escalation_level_2
    http-request tarpit deny_status 429 timeout 25s if burst_scanner escalation_level_2
    
    # Level 3+ (repeat offender): Maximum delays
    http-request tarpit deny_status 429 timeout 60s if scanner_low escalation_level_3
    http-request tarpit deny_status 429 timeout 60s if scanner_medium escalation_level_3
    http-request tarpit deny_status 429 timeout 60s if scanner_high escalation_level_3
    http-request tarpit deny_status 429 timeout 60s if burst_scanner escalation_level_3
    
    # Increment escalation level when we apply tarpit
    # This tracks how many times this IP has been tarpitted
    http-request sc-inc-gpc1(0) if scanner_low or scanner_medium or scanner_high or burst_scanner
    
    # Note: The backend will increment sc0_get_gpc0 when it sees 400/401/403/404 responses
