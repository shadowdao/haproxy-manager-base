# HAProxy Stats & Monitoring
frontend stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats show-legends
    stats show-node

# Dedicated stick-table for WordPress wp-login.php brute-force tracking.
# Tracked via track-sc1 from the `web` frontend (hap_listener.tpl); counts only
# login POSTs per real client IP over a 60s window. Separate from the generic
# sc0 connection/rate table so the login-attempt threshold is independent of
# the (much higher) flood thresholds.
backend wp_bruteforce
    stick-table type ip size 100k expire 30m store http_req_rate(60s)