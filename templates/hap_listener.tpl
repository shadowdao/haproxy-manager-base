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
    # Map file: /etc/haproxy/blocked_ips.map
    # Runtime updates: echo "add map #0 IP_ADDRESS" | socat stdio /var/run/haproxy.sock
    # Checks the real client IP (from headers if present, otherwise src)
    http-request set-path /blocked-ip if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
    use_backend default-backend if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
