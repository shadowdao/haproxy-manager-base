# Security stick tables for multi-table tracking
backend security_blacklist
    stick-table type ip size 20k expire 24h store gpc0,gpc1

backend wp_403_track
    stick-table type ip size 50k expire 15m store http_err_rate(10s)