#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1

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

    # IP blocking using map file (manual blocks only)
    # Map file format: /etc/haproxy/blocked_ips.map contains "<ip_or_cidr> 1" per line
    # Runtime updates: echo "add map #0 IP_ADDRESS 1" | socat stdio /var/run/haproxy.sock
    # Checks the real client IP (from headers if present, otherwise src)
    # map_ip() converter supports both single IPs and CIDR ranges (e.g., 192.168.1.0/24)
    acl is_blocked_ip var(txn.real_ip),map_ip(/etc/haproxy/blocked_ips.map,0) -m int gt 0
    http-request set-path /blocked-ip if is_blocked_ip
    use_backend default-backend if is_blocked_ip
