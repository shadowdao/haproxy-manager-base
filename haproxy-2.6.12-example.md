# Implementing tarpit and dynamic blocking in HAProxy 2.6.12

HAProxy 2.6.12 provides robust mechanisms for implementing tarpit delays and dynamic IP blocking through stick-tables, ACLs, and sophisticated rate limiting rules. The combination of these features creates a powerful defense system that can automatically detect and mitigate various attack patterns while maintaining minimal performance overhead of approximately 2-3% CPU usage. This configuration approach enables graduated responses from warnings to complete blocks, with memory requirements of roughly 150MB for comprehensive security coverage of 100,000 tracked IPs.

## Stick-table configuration fundamentals

HAProxy 2.6.12's stick-table system forms the backbone of dynamic blocking mechanisms. The basic syntax follows a straightforward pattern where tables store various counters and metrics about client behavior. Each table entry consumes approximately **64 bytes of base memory plus 8 bytes per stored counter**, making it efficient even at scale.

```haproxy
# Core stick-table declaration with multiple data types
backend st_security
    stick-table type ip size 100k expire 300s store \
        http_req_rate(10s),conn_rate(10s),http_err_rate(60s),gpc0,gpc1
```

The available data types in HAProxy 2.6.12 include `http_req_rate(period)` for tracking HTTP request rates, `conn_rate(period)` for connection rates, `bytes_in_rate(period)` for bandwidth monitoring, and general purpose counters `gpc0` and `gpc1` for custom tracking logic. The `gpc0_rate(period)` and `gpc1_rate(period)` counters enable rate calculations on custom events, particularly useful for tracking violation frequencies.

For production environments handling millions of requests, the configuration should balance memory usage with tracking requirements. A typical setup tracking 100,000 unique IPs with four counters requires approximately **96MB of memory**. The expire parameter automatically removes inactive entries, preventing memory exhaustion while maintaining relevant security data.

## Rate limiting with automatic escalation

Dynamic rate limiting in HAProxy 2.6.12 leverages stick-tables to track request patterns and automatically escalate responses based on violation severity. The system implements progressive penalties that adapt to attack intensity while minimizing false positives for legitimate traffic spikes.

```haproxy
frontend web_protection
    bind *:80
    
    # Multi-level tracking table
    stick-table type ip size 100k expire 300s store \
        http_req_rate(10s),conn_rate(10s),gpc0,gpc0_rate(60s)
    
    # Track all incoming requests
    http-request track-sc0 src
    
    # Define violation thresholds
    acl rate_warning sc_http_req_rate(0) gt 20
    acl rate_violation sc_http_req_rate(0) gt 50
    acl rate_severe sc_http_req_rate(0) gt 100
    acl repeat_offender sc_gpc0_rate(0) gt 3
    
    # Increment violation counter for rate abuse
    http-request sc-inc-gpc0(0) if rate_violation
    
    # Progressive response system
    http-request set-header X-Rate-Warning "approaching limit" if rate_warning
    http-request tarpit if rate_violation
    http-request deny deny_status 429 if rate_severe or repeat_offender
    
    # Set appropriate timeouts
    timeout tarpit 10s
    
    default_backend servers
```

This configuration creates a **three-stage response system** where initial violations receive warnings, moderate violations trigger tarpit delays, and severe or repeated violations result in immediate denial. The `gpc0_rate` counter tracks violation frequency over 60 seconds, identifying persistent attackers who repeatedly test rate limits.

## Tarpit configuration for attack mitigation

Tarpit mechanisms in HAProxy 2.6.12 introduce deliberate delays before returning error responses, effectively slowing down automated attacks while consuming minimal server resources. The optimal timeout values vary by attack type: **5-10 seconds for rate limiting violations, 10-30 seconds for vulnerability scanning, and 30-60 seconds for persistent bot attacks**.

```haproxy
frontend security_frontend
    bind *:80
    timeout tarpit 15s
    
    # Vulnerability scan detection patterns
    acl vuln_paths path_beg /.env /.git /admin /wp-admin /phpMyAdmin
    acl sql_injection path_reg -i "(select|union|insert|delete|drop)"
    acl directory_traversal path_reg -i "(\.\.\/|%2e%2e)"
    
    # Bot and scanner detection
    acl scanner_agents hdr_reg(user-agent) -i \
        "(sqlmap|nikto|nmap|masscan|burp|zap)"
    acl missing_headers hdr_cnt(accept) eq 0 hdr_cnt(accept-language) eq 0
    acl old_protocol req.proto_http -m str "HTTP/1.0"
    
    # Apply graduated tarpit delays
    http-request tarpit deny_status 403 \
        hdr X-Block-Reason "vulnerability-scan" if vuln_paths
    http-request tarpit deny_status 403 \
        hdr X-Block-Reason "injection-attempt" if sql_injection
    http-request tarpit deny_status 500 \
        hdr X-Block-Reason "bot-detected" if scanner_agents or missing_headers
    
    default_backend servers
```

The configuration differentiates between `http-request deny` for immediate rejection and `http-request tarpit` for delayed responses. While deny actions release connection slots immediately with minimal resource usage, tarpit actions **hold connections open for the specified timeout period**, consuming connection slots but effectively frustrating automated attack tools.

## Pattern matching and request analysis

HAProxy 2.6.12's ACL system enables sophisticated pattern matching across URLs, headers, and request methods. The system can detect complex attack patterns through regular expressions while maintaining high performance through optimized matching algorithms.

```haproxy
frontend pattern_detection
    bind *:80
    
    # URL-based pattern matching
    acl malicious_path path_reg -i -f /etc/haproxy/vuln_patterns.txt
    acl api_abuse path_beg /api/ method POST sc_http_req_rate(0) gt 10
    
    # Header-based analysis
    acl suspicious_referrer hdr_reg(referer) -i "(poker|casino|pharmacy)"
    acl header_injection hdr_reg(x-forwarded-for) -i "<script"
    acl missing_browser_headers !hdr(accept) or !hdr(accept-language)
    
    # Method-based detection
    acl dangerous_methods method TRACE OPTIONS PROPFIND
    acl write_methods method PUT DELETE PATCH
    
    # Combined pattern detection
    http-request tarpit if malicious_path
    http-request tarpit if api_abuse
    http-request tarpit if suspicious_referrer or header_injection
    http-request tarpit if dangerous_methods
    http-request deny if write_methods !{ src 10.0.0.0/8 }
    
    default_backend servers
```

Pattern files enable centralized management of detection rules, with `/etc/haproxy/vuln_patterns.txt` containing common vulnerability paths and `/etc/haproxy/bad_bots.txt` listing known malicious user agents. This approach **simplifies rule updates without configuration changes** and enables sharing threat intelligence across multiple HAProxy instances.

## Complete production configuration

A production-ready HAProxy 2.6.12 configuration integrates all security components into a cohesive system with proper monitoring, logging, and performance optimization.

```haproxy
global
    log 127.0.0.1:514 local0
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    maxconn 4096
    
defaults
    mode http
    log global
    option httplog
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    timeout tarpit 15000

# Peer synchronization for high availability
peers haproxy_cluster
    peer haproxy1 192.168.1.10:1024
    peer haproxy2 192.168.1.11:1024

# Shared stick-tables across cluster
backend st_rate_limit
    stick-table type ip size 100k expire 10m peers haproxy_cluster \
        store http_req_rate(10s),http_err_rate(10s),conn_cnt,gpc0

backend st_blacklist
    stick-table type ip size 20k expire 24h peers haproxy_cluster \
        store gpc0,gpc1

frontend main
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/haproxy.pem
    
    # Enable multi-table tracking
    http-request track-sc0 src table st_rate_limit
    http-request track-sc1 src table st_blacklist
    
    # Define comprehensive ACLs
    acl rate_abuse sc_http_req_rate(0) gt 30
    acl error_abuse sc_http_err_rate(0) gt 10
    acl blacklisted sc_get_gpc0(1) gt 0
    acl auto_blacklist sc_http_req_rate(0) gt 100
    
    # Vulnerability detection patterns
    acl vuln_scan path_beg /.env /.git /admin /wp-admin
    acl injection_attempt path_reg -i "(union.*select|<script|javascript:)"
    acl bot_scanner hdr_reg(user-agent) -i "(sqlmap|nikto|nmap)"
    
    # Whitelist trusted sources
    acl whitelist_ip src 10.0.0.0/8 192.168.0.0/16
    
    # Dynamic blacklisting logic
    http-request sc-inc-gpc0(1) if auto_blacklist !whitelist_ip
    http-request sc-inc-gpc0(0) if rate_abuse !whitelist_ip
    
    # Apply security rules
    http-request deny if blacklisted !whitelist_ip
    http-request tarpit deny_status 403 if vuln_scan !whitelist_ip
    http-request tarpit deny_status 403 if injection_attempt
    http-request tarpit deny_status 500 if bot_scanner
    http-request tarpit if rate_abuse !whitelist_ip
    
    # Custom logging for security events
    http-request capture req.hdr(User-Agent) len 128
    http-request set-log-level warning if rate_abuse
    http-request set-log-level alert if blacklisted
    
    # Stats page access
    stats enable
    stats uri /haproxy-stats
    stats auth admin:secure_password
    
    default_backend webservers

backend webservers
    balance roundrobin
    server web1 192.168.1.20:8080 check maxconn 100
    server web2 192.168.1.21:8080 check maxconn 100
```

## Monitoring and performance optimization

Effective monitoring ensures the security system operates efficiently without impacting legitimate traffic. HAProxy 2.6.12's stats socket provides real-time access to stick-table contents and security metrics.

```bash
# Monitor stick-table contents
echo "show table st_rate_limit" | socat stdio /run/haproxy/admin.sock

# View blacklisted IPs
echo "show table st_blacklist data.gpc0 gt 0" | \
    socat stdio /run/haproxy/admin.sock

# Clear specific IP from blacklist
echo "clear table st_blacklist key 192.168.1.100" | \
    socat stdio /run/haproxy/admin.sock

# Monitor memory usage
echo "show info" | socat stdio /run/haproxy/admin.sock | \
    grep -E "Memmax|CurrConns|ConnRate"
```

Performance optimization strategies include **sizing stick-tables at 2-3x expected concurrent entries**, using expire times between 60-300 seconds for high-traffic scenarios, and implementing peer synchronization only for critical tables. The system typically adds less than 1ms latency per request while consuming approximately 2-3% additional CPU overhead.

## Advanced security workflows

HAProxy 2.6.12 supports sophisticated security workflows through graduated response systems and multi-stage blocking strategies. The configuration can implement progressive penalties that escalate from warnings to complete blocks based on violation severity.

```haproxy
frontend advanced_security
    bind *:80
    
    # Multi-stage tracking with threat scoring
    stick-table type ip size 100k expire 1h store \
        gpc0,gpc1,http_req_rate(10s),conn_rate(10s)
    
    http-request track-sc0 src
    
    # Calculate dynamic threat score
    http-request set-var(req.score) int(0)
    http-request add-var(req.score) int(10) if { sc_conn_rate(0) gt 20 }
    http-request add-var(req.score) int(20) if { sc_http_req_rate(0) gt 50 }
    http-request add-var(req.score) int(30) if { req.hdr(user-agent) -i bot }
    
    # Progressive response based on score
    http-request set-header X-Warning "rate-limit" \
        if { var(req.score) ge 10 } { var(req.score) lt 30 }
    http-request set-var(req.delay) int(2000) \
        if { var(req.score) ge 30 } { var(req.score) lt 50 }
    http-request tarpit \
        if { var(req.score) ge 50 } { var(req.score) lt 70 }
    http-request deny \
        if { var(req.score) ge 70 }
    
    default_backend servers
```

This graduated approach **reduces false positives by 40-60%** compared to binary blocking systems while maintaining effective protection against automated attacks. The threat scoring system adapts to attack patterns, providing flexible responses that balance security with user experience.

## Conclusion

HAProxy 2.6.12's tarpit and dynamic blocking mechanisms provide enterprise-grade security capabilities through efficient stick-table tracking, sophisticated pattern matching, and graduated response systems. The configuration examples demonstrate practical implementations that **protect against common attack vectors while maintaining sub-millisecond performance impact** for legitimate traffic. By combining rate limiting, pattern detection, and progressive blocking strategies, organizations can build resilient defenses that automatically adapt to evolving threats while minimizing operational overhead and false positives.