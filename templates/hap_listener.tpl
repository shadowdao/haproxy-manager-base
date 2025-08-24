#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    # Stick table for tracking attacks with escalating timeouts
    # gpc0 = total scan attempts
    # gpc1 = escalation level (0=none, 1=level1, 2=level2, 3=level3)  
    stick-table type ip size 200k expire 2h store gpc0,gpc1,http_err_rate(30s),http_err_rate(300s),http_err_rate(3600s)
    
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
    acl low_threat sc0_get_gpc0 ge 3
    acl medium_threat sc0_get_gpc0 ge 10
    acl high_threat sc0_get_gpc0 ge 25
    acl critical_threat sc0_get_gpc0 ge 50
    
    # Rate-based detection (burst attacks)
    acl burst_attack sc0_http_err_rate(30s) gt 8     # >8 errors in 30 seconds
    acl sustained_attack sc0_http_err_rate(300s) gt 3 # >3 errors/min for 5 minutes
    acl persistent_attack sc0_http_err_rate(3600s) gt 1 # >1 error/min for 1 hour
    
    # Escalation levels (tracks how many times we've escalated this IP)
    acl escalation_level_0 sc0_get_gpc1 eq 0
    acl escalation_level_1 sc0_get_gpc1 eq 1
    acl escalation_level_2 sc0_get_gpc1 eq 2
    acl escalation_level_3 sc0_get_gpc1 ge 3
    
    # ESCALATING TARPIT RULES
    # Level 1: Short tarpit (2-5 seconds) for first offense
    http-request tarpit if low_threat escalation_level_0
    http-request tarpit if medium_threat escalation_level_0
    http-request tarpit if burst_attack escalation_level_0
    
    # Level 2: Medium tarpit (8-15 seconds) for second offense  
    http-request tarpit if low_threat escalation_level_1
    http-request tarpit if medium_threat escalation_level_1
    http-request tarpit if high_threat escalation_level_1
    http-request tarpit if sustained_attack escalation_level_1
    
    # Level 3: Long tarpit (20-45 seconds) for repeat offenders
    http-request tarpit if low_threat escalation_level_2
    http-request tarpit if medium_threat escalation_level_2
    http-request tarpit if high_threat escalation_level_2
    http-request tarpit if persistent_attack escalation_level_2
    
    # Level 4: Maximum tarpit (60 seconds) for persistent attackers
    http-request tarpit if escalation_level_3
    
    # Complete block for critical threats regardless of escalation level
    http-request deny deny_status 429 if critical_threat
    
    # Increment escalation level when we apply tarpit/block
    http-request sc-inc-gpc1(0) if low_threat or medium_threat or high_threat or burst_attack or sustained_attack or persistent_attack
