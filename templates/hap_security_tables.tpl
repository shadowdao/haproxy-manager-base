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

# Dedicated stick-table for POST /xmlrpc.php flood tracking.
# Tracked via track-sc2 from the `web` frontend (hap_listener.tpl); counts
# only xmlrpc POSTs per real client IP over a 60s window. This is a SEPARATE
# table/counter from wp_bruteforce (sc1) rather than a shared one: both are
# machine-to-machine WordPress endpoints an attacker could hit from the same
# IP, and sharing a counter would let one endpoint's traffic inflate the
# other's rate -- an IP credential-stuffing wp-login while also flooding
# xmlrpc would trip the wp-login threshold early on xmlrpc volume alone (or
# vice versa). track-sc1 (wp-login) and track-sc2 (xmlrpc) are each gated on
# mutually exclusive path ACLs, so at most one of them ever fires per
# request -- HAProxy's "one track-sc<N> per counter per request" limit is
# never in play here since they're different counters anyway.
backend xmlrpc_bruteforce
    stick-table type ip size 100k expire 30m store http_req_rate(60s)