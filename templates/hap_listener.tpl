#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    # Stick table kept for potential future use or custom implementations
    # Can be used by containers to track IPs if needed
    stick-table type ip size 200k expire 1h store gpc0,gpc1,http_err_rate(10s)
    
    # Whitelist trusted networks and monitoring systems
    acl trusted_networks src 127.0.0.1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
    acl health_check path_beg /health /ping /status /.well-known/
    acl common_missing path /favicon.ico /robots.txt /sitemap.xml /apple-touch-icon.png
    
    # Allow trusted traffic to bypass all protection
    http-request allow if trusted_networks or health_check
    
    # Don't count common missing files against the error count
    http-request return status 404 if common_missing
    
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
    # Kept for potential container-level tracking integrations
    http-request track-sc0 var(txn.real_ip)
    
    # IP blocking using map file (no word limit, runtime updates supported)
    # Map file: /etc/haproxy/blocked_ips.map
    # Runtime updates: echo "add map #0 IP_ADDRESS" | socat stdio /var/run/haproxy.sock
    # Checks the real client IP (from headers if present, otherwise src)
    http-request set-path /blocked-ip if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
    use_backend default-backend if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
