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
    
    # Track client in stick table
    http-request track-sc0 src
    
    # IP blocking using map file (no word limit, runtime updates supported)
    # Map file: /etc/haproxy/blocked_ips.map
    # Runtime updates: echo "add map #0 IP_ADDRESS" | socat stdio /var/run/haproxy.sock
    http-request set-path /blocked-ip if { src -f /etc/haproxy/blocked_ips.map }
    use_backend default-backend if { src -f /etc/haproxy/blocked_ips.map }
    
    # Define threat levels based on scan attempts and rates
    acl has_scan_attempts sc0_get_gpc0 gt 0
    acl low_threat sc0_get_gpc0 ge 3 sc0_get_gpc0 lt 10
    acl medium_threat sc0_get_gpc0 ge 10 sc0_get_gpc0 lt 25  
    acl high_threat sc0_get_gpc0 ge 25 sc0_get_gpc0 lt 50
    acl critical_threat sc0_get_gpc0 ge 50
    
    # Rate-based detection (burst attacks)
    acl burst_attack sc0_http_err_rate gt 5     # >5 errors in 10 seconds
    
    # Combined threat detection
    acl is_threat has_scan_attempts
    acl needs_tarpit low_threat or medium_threat or high_threat or burst_attack
    
    # TARPIT RULES - Only apply to actual threats
    # Apply tarpit only if there are scan attempts
    http-request tarpit if needs_tarpit
    
    # Complete block for critical threats
    http-request deny deny_status 429 if critical_threat
    
    # Increment scan counter when tarpit is applied (this happens after response in backend)
