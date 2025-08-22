#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1
    
    {% if blocked_ips %}
    # IP blocking - single ACL with all blocked IPs
    acl is_blocked src{% for blocked_ip in blocked_ips %} {{ blocked_ip }}{% endfor %}
    
    # If IP is blocked, set path to blocked page and use default backend
    http-request set-path /blocked-ip if is_blocked
    use_backend default-backend if is_blocked
    {% endif %}
