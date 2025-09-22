#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    # Stick tables for tracking and rate limiting
    # Main tracking table: stores request rates, error rates, and abuse counters
    stick-table type ip size 200k expire 30m store gpc0,gpc1,http_req_rate(10s),http_err_rate(10s),conn_rate(10s)
    
    # Whitelist trusted networks and monitoring systems
    acl trusted_networks src 127.0.0.1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
    acl health_check path_beg /health /ping /status /.well-known/

    # Allow trusted traffic to bypass all protection
    http-request allow if trusted_networks or health_check

    # ============================================
    # SECURITY: Anti-Scan and Brute Force Protection
    # ============================================

    # 1. Detect common exploit scan patterns
    acl scan_wordpress path_beg /wp-admin /wp-login /xmlrpc.php /wp-content/uploads/ /wp-includes/
    acl scan_admin path_beg /admin /administrator /phpmyadmin /pma /mysql /cpanel /panel
    acl scan_exploits path_end .sql .bak .backup .zip .tar.gz .rar .old .orig .save .swp .env .git .svn .DS_Store
    acl scan_shells path_beg /shell.php /c99.php /r57.php /wso.php /alfa.php /eval.php /cmd.php
    acl scan_dotfiles path_beg /. /.env /.git /.svn /.htaccess /.htpasswd /.ssh /.aws
    acl scan_paths path_beg /cgi-bin /scripts /fckeditor /ckfinder /userfiles /console /api/v1/auth/login

    # 2. Detect malicious user agents
    acl bot_scanner hdr_sub(user-agent) -i sqlmap nikto nmap masscan zmap dirbuster gobuster wpscan joomscan acunetix nessus openvas metasploit burp zgrab
    acl bot_generic hdr_sub(user-agent) -i bot crawler spider scraper scan probe
    acl bot_empty hdr_len(user-agent) eq 0

    # 3. Detect suspicious request patterns
    acl suspicious_method method TRACE TRACK OPTIONS CONNECT
    acl has_sql_chars url_sub -i select union insert update delete drop create alter exec script
    acl has_traversal url_sub ../ ..\\ %2e%2e %252e
    acl excessive_params url_len gt 2000

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
    
    # Track the real client IP in stick table for rate limiting
    http-request track-sc0 var(txn.real_ip)

    # ============================================
    # APPLY SECURITY RULES
    # ============================================

    # 4. Rate limiting - Check if IP is exceeding limits
    acl rate_abuse sc0_http_req_rate gt 50
    acl conn_abuse sc0_conn_rate gt 20
    acl error_abuse sc0_http_err_rate gt 10
    acl marked_bad sc0_get_gpc0 gt 0
    acl repeat_offender sc0_get_gpc1 gt 2

    # 5. Mark bad actors in stick table
    # gpc0: Current bad actor flag (0=good, 1=bad)
    # gpc1: Offense counter (increments each time marked bad)
    http-request sc-set-gpc0(0) 1 if scan_wordpress or scan_admin or scan_exploits or scan_shells or scan_dotfiles
    http-request sc-set-gpc0(0) 1 if bot_scanner or suspicious_method or has_sql_chars or has_traversal
    http-request sc-set-gpc0(0) 1 if rate_abuse or conn_abuse or error_abuse
    http-request sc-inc-gpc1(0) 1 if marked_bad !repeat_offender

    # 6. Progressive response based on threat level
    # Level 1: Deny with tarpit for suspicious scanners (uses tarpit timeout from defaults)
    http-request tarpit if scan_wordpress or scan_admin or scan_shells or bot_scanner
    http-request tarpit if suspicious_method or has_sql_chars or has_traversal

    # Level 2: Deny for rate abusers and marked bad actors
    http-request deny if marked_bad
    http-request deny if rate_abuse or conn_abuse or error_abuse

    # Level 3: Reject repeat offenders completely
    http-request deny if repeat_offender

    # 7. Additional protections for login/auth endpoints
    acl is_login path_end /login /signin /auth /authenticate
    acl is_api_auth path_beg /api/login /api/auth /api/v1/auth /api/v2/auth

    # Strict rate limit for authentication endpoints (max 5 requests per 10s)
    acl auth_abuse sc0_http_req_rate gt 5
    http-request deny if is_login auth_abuse
    http-request deny if is_api_auth auth_abuse

    # 8. Log security events for monitoring
    http-request capture var(txn.real_ip) len 40
    http-request capture req.hdr(user-agent) len 150
    http-request set-var(txn.blocked) str(scanner) if bot_scanner
    http-request set-var(txn.blocked) str(exploit) if scan_exploits or scan_shells
    http-request set-var(txn.blocked) str(ratelimit) if rate_abuse
    http-request set-var(txn.blocked) str(repeat) if repeat_offender
    
    # IP blocking using map file (no word limit, runtime updates supported)
    # Map file: /etc/haproxy/blocked_ips.map
    # Runtime updates: echo "add map #0 IP_ADDRESS" | socat stdio /var/run/haproxy.sock
    # Checks the real client IP (from headers if present, otherwise src)
    http-request set-path /blocked-ip if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
    use_backend default-backend if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
