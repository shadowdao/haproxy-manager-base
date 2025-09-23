#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    # Main rate limiting table (short-term, high-frequency tracking)
    stick-table type ip size 100k expire 10m store http_req_rate(10s),conn_rate(10s),http_err_rate(10s),gpc0
    
    # Whitelist trusted networks and monitoring systems
    acl trusted_networks src 127.0.0.1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12
    acl health_check path_beg /health /ping /status /.well-known/

    # Allow trusted traffic to bypass all protection
    http-request allow if trusted_networks or health_check

    # ============================================
    # SECURITY: Anti-Scan and Brute Force Protection
    # ============================================

    # 1. Enhanced exploit scan detection patterns (based on HAProxy 2.6.12 best practices)
    acl is_wordpress_path path_beg /wp-admin /wp-login /xmlrpc.php /wp-content/ /wp-includes/
    acl scan_admin path_beg /administrator /phpmyadmin /pma /mysql /cpanel /panel /admin
    acl scan_exploits path_end .sql .bak .backup .zip .tar.gz .rar .old .orig .save .swp .env .git .svn .DS_Store
    acl scan_shells path_beg /shell.php /c99.php /r57.php /wso.php /alfa.php /eval.php /cmd.php
    acl scan_dotfiles path_beg /. /.env /.git /.svn /.htaccess /.htpasswd /.ssh /.aws
    acl scan_paths path_beg /cgi-bin /scripts /fckeditor /ckfinder /userfiles /console

    # Advanced injection detection patterns
    acl sql_injection path_reg -i "(union.*select|insert.*into|delete.*from|drop.*table|<script|javascript:)"
    acl directory_traversal path_reg -i "(\.\.\/|%2e%2e|\.\.%2f)"
    acl header_injection hdr_reg(x-forwarded-for) -i "<script"

    # 2. Detect malicious user agents
    acl bot_scanner hdr_sub(user-agent) -i sqlmap nikto nmap masscan zmap dirbuster gobuster wpscan joomscan acunetix nessus openvas metasploit burp zgrab
    acl bot_empty hdr_len(user-agent) eq 0

    # Whitelist legitimate bots and services
    acl legitimate_bot hdr_sub(user-agent) -i googlebot bingbot yandexbot facebookexternalhit twitterbot linkedinbot whatsapp slack
    acl wordpress_app hdr_sub(user-agent) -i "WordPress/" "Jetpack" "wp-android" "wp-iphone"
    acl browser_ua hdr_sub(user-agent) -i mozilla chrome safari firefox edge opera

    # 3. Enhanced suspicious request pattern detection
    acl suspicious_method method TRACE TRACK OPTIONS CONNECT PROPFIND
    acl dangerous_methods method PUT DELETE PATCH
    acl old_protocol req.proto_http -m str "HTTP/1.0"
    acl missing_accept_header hdr_cnt(accept) eq 0
    acl missing_lang_header hdr_cnt(accept-language) eq 0
    acl excessive_params url_len gt 2000
    acl suspicious_referrer hdr_reg(referer) -i "(poker|casino|pharmacy|xxx)"

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
    
    # Multi-table tracking for comprehensive security monitoring
    http-request track-sc0 var(txn.real_ip)
    http-request track-sc1 var(txn.real_ip) table security_blacklist

    # ============================================
    # APPLY SECURITY RULES
    # ============================================

    # 4. Enhanced rate limiting and blacklist checking
    acl rate_abuse sc0_http_req_rate gt 30
    acl rate_severe sc0_http_req_rate gt 100
    acl conn_abuse sc0_conn_rate gt 20
    acl error_abuse sc0_http_err_rate gt 10
    acl wp_403_abuse sc1_http_err_rate(wp_403_track) gt 5
    acl blacklisted sc1_get_gpc0(security_blacklist) gt 0
    acl auto_blacklist_candidate sc0_http_req_rate(0) gt 100
    acl marked_bad sc0_get_gpc0 gt 0
    acl repeat_offender sc1_get_gpc1(security_blacklist) gt 2

    # WordPress-specific detection logic
    # We focus on clear scanner indicators rather than all errors for WordPress paths
    # since 404s on wp-admin are normal (CSS, JS files, etc.)

    # Combine conditions to identify actual attacks vs legitimate use
    # WordPress-specific attack detection (combining path + threat indicators)
    acl wp_scanner_detected is_wordpress_path bot_scanner
    acl wp_brute_force_detected wp_403_abuse
    acl wp_suspicious_detected is_wordpress_path bot_empty

    # WordPress brute force detection now based on actual 403 failures (5+ in 10s)
    # This catches real authentication failures, not just POST requests

    # Simplified threat detection for HAProxy 3.0 compatibility
    # Direct threat level classification based on individual indicators
    acl high_threat_detected bot_scanner
    acl high_threat_scan scan_admin
    acl high_threat_shells scan_shells
    acl medium_threat_injection sql_injection
    acl medium_threat_traversal directory_traversal
    acl medium_threat_wp_attack wp_brute_force_detected
    acl low_threat_rate rate_abuse
    acl low_threat_method suspicious_method
    acl low_threat_headers missing_accept_header
    acl critical_threat_blacklist blacklisted
    acl critical_threat_autoban auto_blacklist_candidate

    # 5. Dynamic blacklisting based on threat level
    http-request sc-inc-gpc0(1) if auto_blacklist_candidate
    http-request sc-inc-gpc1(1) if high_threat_detected or high_threat_scan or high_threat_shells
    http-request sc-inc-gpc1(1) if critical_threat_blacklist or critical_threat_autoban

    # Mark current session as bad based on threat level
    http-request sc-set-gpc0(0) 1 if medium_threat_injection or medium_threat_traversal or medium_threat_wp_attack
    http-request sc-set-gpc0(0) 1 if high_threat_detected or high_threat_scan or high_threat_shells
    http-request sc-set-gpc0(0) 1 if critical_threat_blacklist or critical_threat_autoban

    # 6. Graduated response system based on threat level
    # Low threat: Warning header only
    http-request set-header X-Security-Warning "rate-limit-approaching" if low_threat_rate !legitimate_bot !wordpress_app !browser_ua
    http-request set-header X-Security-Warning "suspicious-method" if low_threat_method !legitimate_bot !wordpress_app !browser_ua
    http-request set-header X-Security-Warning "missing-headers" if low_threat_headers !legitimate_bot !wordpress_app !browser_ua

    # Medium threat: Tarpit delay
    http-request tarpit if medium_threat_injection !legitimate_bot !wordpress_app !browser_ua
    http-request tarpit if medium_threat_traversal !legitimate_bot !wordpress_app !browser_ua
    http-request tarpit if medium_threat_wp_attack !legitimate_bot !wordpress_app !browser_ua

    # High threat: Immediate deny
    http-request deny deny_status 403 if high_threat_detected !legitimate_bot !wordpress_app !browser_ua
    http-request deny deny_status 403 if high_threat_scan !legitimate_bot !wordpress_app !browser_ua
    http-request deny deny_status 403 if high_threat_shells !legitimate_bot !wordpress_app !browser_ua
    http-request deny deny_status 403 if wp_scanner_detected !legitimate_bot !wordpress_app !browser_ua

    # Critical threat: Blacklist and deny
    http-request deny deny_status 403 if critical_threat_blacklist
    http-request deny deny_status 403 if critical_threat_autoban

    # Additional immediate threat rules
    http-request deny if repeat_offender
    http-request deny if dangerous_methods !trusted_networks

    # 7. Additional protections for login/auth endpoints
    acl is_login path_end /login /signin /auth /authenticate
    acl is_api_auth path_beg /api/login /api/auth /api/v1/auth /api/v2/auth
    acl is_wp_login path_beg /wp-login.php /wp-admin/admin-ajax.php
    acl is_xmlrpc path /xmlrpc.php

    # Rate limits for different types of authentication
    # WordPress brute force is now handled by 403 tracking above
    # Other auth: 5 requests per 10s (stricter for non-WordPress)
    # XMLRPC: 20 requests per 10s (can be legitimately high for some plugins)
    acl auth_abuse sc0_http_req_rate gt 5
    acl xmlrpc_abuse is_xmlrpc sc0_http_req_rate gt 20

    # Rate limiting for non-WordPress authentication endpoints
    http-request deny if is_login auth_abuse
    http-request deny if is_api_auth auth_abuse
    http-request deny if xmlrpc_abuse !legitimate_bot !wordpress_app

    # 8. Enhanced logging with threat level tracking
    http-request capture var(txn.real_ip) len 40
    http-request capture req.hdr(user-agent) len 150

    # Set log level based on threat level
    http-request set-log-level info if low_threat_rate or low_threat_method or low_threat_headers
    http-request set-log-level warning if medium_threat_injection or medium_threat_traversal or medium_threat_wp_attack
    http-request set-log-level alert if high_threat_detected or high_threat_scan or high_threat_shells
    http-request set-log-level alert if critical_threat_blacklist or critical_threat_autoban

    # Track WordPress paths for 403 response monitoring
    http-request set-var(txn.is_wp_path) int(1) if is_wordpress_path

    # 9. Response-phase tracking for WordPress 403 failures
    http-response track-sc1 var(txn.real_ip) table wp_403_track if { var(txn.is_wp_path) -m int 1 } { status 403 }
    
    # IP blocking using map file (no word limit, runtime updates supported)
    # Map file: /etc/haproxy/blocked_ips.map
    # Runtime updates: echo "add map #0 IP_ADDRESS" | socat stdio /var/run/haproxy.sock
    # Checks the real client IP (from headers if present, otherwise src)
    http-request set-path /blocked-ip if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
    use_backend default-backend if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
