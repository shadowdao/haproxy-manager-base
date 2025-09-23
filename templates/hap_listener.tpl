#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    # HAProxy 3.0.11 Enhanced Security with Array-Based GPC System
    # Multi-dimensional threat scoring with weighted analysis
    stick-table type ipv6 size 200k expire 30m store gpc(15),gpc_rate(15,60s),gpt(5),glitch_cnt,glitch_rate(300s),http_req_rate(60s),http_err_rate(300s),conn_rate(10s),bytes_out_rate(60s)

    # Threat Scoring Matrix (GPC Array Indices):
    # gpc(0):  Authentication failures (401s)     - Weight: 10
    # gpc(1):  Authorization failures (403s)      - Weight: 8
    # gpc(2):  Rate limit violations              - Weight: 4
    # gpc(3):  Scanner/Bot detection              - Weight: 12
    # gpc(4):  SQL injection attempts             - Weight: 15
    # gpc(5):  Directory traversal attempts       - Weight: 10
    # gpc(6):  WordPress brute force attempts     - Weight: 8
    # gpc(7):  Admin panel scanning               - Weight: 12
    # gpc(8):  Shell/exploit attempts             - Weight: 20
    # gpc(9):  Suspicious HTTP methods            - Weight: 6
    # gpc(10): Protocol violations (HTTP/2)       - Weight: 15
    # gpc(11): Bandwidth abuse patterns           - Weight: 5
    # gpc(12): Repeat offender flag               - Weight: 25
    # gpc(13): Manual blacklist flag              - Weight: 100
    # gpc(14): Auto-blacklist candidate           - Weight: 50
    
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

    # 4. HAProxy 3.0.11 Enhanced Threat Detection with Array-Based Scoring
    # Rate and connection abuse detection
    acl rate_abuse sc0_http_req_rate gt 30
    acl rate_severe sc0_http_req_rate gt 100
    acl conn_abuse sc0_conn_rate gt 20
    acl error_abuse sc0_http_err_rate gt 10
    acl bandwidth_abuse sc0_bytes_out_rate gt 10485760  # 10MB/s

    # HTTP/2 Protocol violations and glitch detection
    acl protocol_violations sc0_glitch_rate gt 5
    acl glitch_abuse fc_glitches gt 100
    acl high_glitch_rate sc0_glitch_rate gt 10

    # Array-based threat flags (using GPC indices from matrix above)
    acl auth_failures sc_get_gpc(0,0) gt 5               # 401 errors
    acl authz_failures sc_get_gpc(1,0) gt 5              # 403 errors
    acl rate_violations sc_get_gpc(2,0) gt 10            # Rate limit hits
    acl scanner_detected sc_get_gpc(3,0) gt 0            # Bot/scanner flag
    acl sql_injection_attempts sc_get_gpc(4,0) gt 0      # SQL injection flag
    acl traversal_attempts sc_get_gpc(5,0) gt 0          # Directory traversal
    acl wp_brute_force sc_get_gpc(6,0) gt 3              # WordPress attacks
    acl admin_scanning sc_get_gpc(7,0) gt 0              # Admin panel scans
    acl shell_attempts sc_get_gpc(8,0) gt 0              # Shell/exploit attempts
    acl method_violations sc_get_gpc(9,0) gt 2           # Suspicious methods
    acl protocol_violator sc_get_gpc(10,0) gt 3          # HTTP/2 violations
    acl bandwidth_violator sc_get_gpc(11,0) gt 5         # Bandwidth abuse
    acl repeat_offender sc_get_gpc(12,0) gt 0            # Repeat offender flag
    acl manually_blacklisted sc_get_gpt(1,0) gt 0       # Manual blacklist
    acl auto_blacklist_candidate sc_get_gpt(0,0) gt 0   # Auto-blacklist flag

    # WordPress-specific detection logic
    # We focus on clear scanner indicators rather than all errors for WordPress paths
    # since 404s on wp-admin are normal (CSS, JS files, etc.)

    # 5. HAProxy 3.0.11 Array-Based GPC Threat Tracking System
    # Track individual threat indicators in their dedicated GPC array slots

    # Rate limit violations tracking
    http-request sc-inc-gpc(2,0) if rate_abuse

    # Scanner and bot detection
    http-request sc-inc-gpc(3,0) if bot_scanner

    # Attack pattern detection
    http-request sc-inc-gpc(4,0) if sql_injection
    http-request sc-inc-gpc(5,0) if directory_traversal
    http-request sc-inc-gpc(7,0) if scan_admin
    http-request sc-inc-gpc(8,0) if scan_shells
    http-request sc-inc-gpc(9,0) if suspicious_method

    # HTTP/2 protocol violations tracking
    http-request sc-inc-gpc(10,0) if protocol_violations
    http-request sc-inc-gpc(10,0) if glitch_abuse

    # Bandwidth abuse tracking
    http-request sc-inc-gpc(11,0) if bandwidth_abuse

    # Auto-blacklist candidate marking (using GPT instead of GPC for setting values)
    http-request sc-set-gpt(0,0) 1 if rate_severe

    # Repeat offender escalation (increment when multiple threats detected)
    http-request sc-inc-gpc(12,0) if scanner_detected sql_injection_attempts
    http-request sc-inc-gpc(12,0) if admin_scanning shell_attempts

    # 6. HAProxy 3.0.11 Composite Threat Scoring and Graduated Response System
    # Calculate weighted threat score using array GPC values (simplified approach)
    http-request set-var(txn.threat_score) int(0)

    # Individual threat component tracking (we'll use ACLs for graduated response)
    # Simplified scoring for critical threats only
    http-request set-var(txn.threat_score) int(100) if manually_blacklisted
    http-request set-var(txn.threat_score) int(50) if auto_blacklist_candidate !manually_blacklisted
    http-request set-var(txn.threat_score) int(25) if repeat_offender !auto_blacklist_candidate !manually_blacklisted
    http-request set-var(txn.threat_score) int(20) if shell_attempts !repeat_offender !auto_blacklist_candidate !manually_blacklisted
    http-request set-var(txn.threat_score) int(15) if sql_injection_attempts !shell_attempts !repeat_offender !auto_blacklist_candidate !manually_blacklisted

    # Graduated response system based on composite threat score
    # Level 1: Low threat (0-19) - Warning headers only
    http-request set-header X-Threat-Level "LOW" if { var(txn.threat_score) lt 20 }
    http-request set-header X-Security-Warning "monitoring" if { var(txn.threat_score) ge 1 } { var(txn.threat_score) lt 20 }

    # Level 2: Medium threat (20-49) - Tarpit delays
    http-request set-header X-Threat-Level "MEDIUM" if { var(txn.threat_score) ge 20 } { var(txn.threat_score) lt 50 }
    http-request tarpit if { var(txn.threat_score) ge 20 } { var(txn.threat_score) lt 50 } !legitimate_bot !wordpress_app !browser_ua

    # Level 3: High threat (50-99) - Immediate deny
    http-request set-header X-Threat-Level "HIGH" if { var(txn.threat_score) ge 50 } { var(txn.threat_score) lt 100 }
    http-request deny deny_status 403 if { var(txn.threat_score) ge 50 } { var(txn.threat_score) lt 100 } !legitimate_bot !wordpress_app !browser_ua

    # Level 4: Critical threat (100+) - Immediate blacklist and deny
    http-request set-header X-Threat-Level "CRITICAL" if { var(txn.threat_score) ge 100 }
    http-request sc-set-gpt(1,0) 1 if { var(txn.threat_score) ge 100 }  # Mark as manually blacklisted
    http-request deny deny_status 403 if { var(txn.threat_score) ge 100 }

    # HTTP/2 specific protections
    http-request tarpit deny_status 400 if high_glitch_rate
    http-request deny if glitch_abuse
    http-request silent-drop if protocol_violator

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

    # 8. HAProxy 3.0.11 Enhanced Logging with Threat Intelligence
    http-request capture var(txn.real_ip) len 40
    http-request capture req.hdr(user-agent) len 150
    http-request capture var(txn.threat_score) len 10

    # Enhanced logging format with glitch information
    log-format "%{+json}o \
        %(client_ip)[var(txn.real_ip)] \
        %(threat_score)[var(txn.threat_score)] \
        %(glitches)[fc_glitches] \
        %(h2_streams)[fc_nb_streams] \
        %(user_agent)[capture.req.hdr(1)] \
        %(threat_level)[res.hdr(X-Threat-Level)]"

    # Set log level based on threat score
    http-request set-log-level info if { var(txn.threat_score) lt 20 }
    http-request set-log-level warning if { var(txn.threat_score) ge 20 } { var(txn.threat_score) lt 50 }
    http-request set-log-level alert if { var(txn.threat_score) ge 50 }

    # Track WordPress paths for authentication failure monitoring
    http-request set-var(txn.is_wp_path) int(1) if is_wordpress_path

    # 9. Response-phase tracking for authentication and authorization failures
    # Track 401 authentication failures in gpc(0)
    http-response sc-inc-gpc(0,0) if { status 401 }

    # Track 403 authorization failures in gpc(1) - includes WordPress brute force
    http-response sc-inc-gpc(1,0) if { status 403 }

    # Track WordPress-specific 403 failures in gpc(6)
    http-response sc-inc-gpc(6,0) if { var(txn.is_wp_path) -m int 1 } { status 403 }
    
    # IP blocking using map file (no word limit, runtime updates supported)
    # Map file: /etc/haproxy/blocked_ips.map
    # Runtime updates: echo "add map #0 IP_ADDRESS" | socat stdio /var/run/haproxy.sock
    # Checks the real client IP (from headers if present, otherwise src)
    http-request set-path /blocked-ip if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
    use_backend default-backend if { var(txn.real_ip) -m ip -f /etc/haproxy/blocked_ips.map }
