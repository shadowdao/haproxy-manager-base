# HAProxy Stats & Monitoring
frontend stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
    stats refresh 30s
    stats show-legends
    stats show-node