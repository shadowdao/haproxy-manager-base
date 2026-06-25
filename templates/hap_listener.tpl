#web
frontend web
    bind 0.0.0.0:80
    # crt can now be a path, so it will load all .pem files in the path
    bind 0.0.0.0:443 ssl crt {{ crt_path }} alpn h2,http/1.1

    # HTTP/3 over QUIC (UDP/443). Same cert path as the TCP listener above.
    # The Debian haproxy package is built +QUIC (QUIC_OPENSSL_COMPAT), so this
    # is config-only — no source build. Requires UDP/443 published on the
    # container (`-p 443:443/udp`) and open at the host firewall. `h3` is the
    # only ALPN QUIC negotiates; h2/http1 stay on the TCP bind above. Sharing
    # the frontend means all the real-IP, rate-limit, IP-block and Coraza
    # rules below apply identically to H3 traffic.
    bind quic4@0.0.0.0:443 ssl crt {{ crt_path }} alpn h3

    # Advertise H3 so browsers upgrade their existing TCP (h2) connection to
    # QUIC on the next request. `ma` is how long (seconds) the client may
    # cache the advertisement. http-after-response applies it to every
    # response, including haproxy-generated ones (blocks, default page).
    http-after-response set-header alt-svc "h3=\":443\"; ma=86400"

    # Capture Host header so it appears in httplog output (in %hr field)
    http-request capture req.hdr(Host) len 64

    # Detect real client IP from proxy headers if they exist
    # Priority: CF-Connecting-IP (Cloudflare) > X-Real-IP > X-Forwarded-For > src
    acl has_cf_connecting_ip req.hdr(CF-Connecting-IP) -m found
    acl has_x_real_ip req.hdr(X-Real-IP) -m found
    acl has_x_forwarded_for req.hdr(X-Forwarded-For) -m found

    # Set the real IP based on available headers. Use hdr_ip (not hdr) so the
    # variable is typed as IP — required by the Coraza SPOE arg `src-ip` which
    # decodes binary IP bytes (passing a string IP panics the SPOA goroutine).
    # `hdr_ip(X-Forwarded-For,1)` extracts the FIRST address from a possibly
    # comma-separated chain (original client, not intermediate proxies).
    http-request set-var(txn.real_ip) req.hdr_ip(CF-Connecting-IP) if has_cf_connecting_ip
    http-request set-var(txn.real_ip) req.hdr_ip(X-Real-IP) if !has_cf_connecting_ip has_x_real_ip
    http-request set-var(txn.real_ip) req.hdr_ip(X-Forwarded-For,1) if !has_cf_connecting_ip !has_x_real_ip has_x_forwarded_for
    http-request set-var(txn.real_ip) src if !has_cf_connecting_ip !has_x_real_ip !has_x_forwarded_for

    # --- Connection & rate tracking ---
    stick-table type ip size 200k expire 10m store conn_cur,conn_rate(10s),http_req_rate(10s),http_err_rate(30s)
    http-request track-sc0 var(txn.real_ip)

    # Whitelist: let health checks, local, and trusted traffic bypass rate limits
    acl is_local src 127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
    acl is_trusted_ip src -f /etc/haproxy/trusted_ips.list
    acl is_health_check path_beg /.well-known/acme-challenge
    acl is_whitelisted var(txn.real_ip),map_ip(/etc/haproxy/trusted_ips.map,0) -m int gt 0

    # --- Rate limit rules (applied in order, first match wins) ---
    # Thresholds are generous to accommodate media-heavy sites where a
    # single page can load 100+ images/assets. These only trigger on
    # obvious automated abuse, not real users.
    #
    # Hard block: >5000 req/10s per IP (500 req/s — sustained flood)
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 5000 } !is_local !is_trusted_ip !is_whitelisted !is_health_check
    # Tarpit: >3000 req/10s per IP (300 req/s — aggressive bot/scraper)
    http-request tarpit deny_status 429 if { sc_http_req_rate(0) gt 3000 } !is_local !is_trusted_ip !is_whitelisted !is_health_check
    # Connection rate limit: >500 new connections per 10s per IP
    http-request deny deny_status 429 if { sc_conn_rate(0) gt 500 } !is_local !is_trusted_ip !is_whitelisted !is_health_check
    # Concurrent connection limit: >500 simultaneous connections per IP
    http-request deny deny_status 429 if { sc_conn_cur(0) gt 500 } !is_local !is_trusted_ip !is_whitelisted !is_health_check
    # High error rate: >100 errors in 30s (scanner/fuzzer behavior)
    http-request tarpit deny_status 403 if { sc_http_err_rate(0) gt 100 } !is_local !is_trusted_ip !is_whitelisted !is_health_check

    # --- WordPress wp-login.php brute-force protection ---
    # The generic limits above are deliberately high (media-heavy sites), so a
    # slow credential-stuffing run (dozens of login POSTs/min) slips under them.
    # Track POSTs to wp-login.php per real client IP in a DEDICATED 60s table
    # (sc1 / backend wp_bruteforce, defined in hap_security_tables.tpl) and
    # tarpit once an IP exceeds 30/min. Only login POSTs are counted — GETs of
    # the login form, normal browsing, and the handful of POSTs a legit user
    # makes are unaffected; an offending IP can still browse, just not keep
    # hammering login. path_end also covers subdirectory WP installs. Honors the
    # same whitelist (RFC1918 / trusted_ips.list / trusted_ips.map).
    acl wp_login_path path_end /wp-login.php
    http-request track-sc1 var(txn.real_ip) table wp_bruteforce if METH_POST wp_login_path
    http-request tarpit deny_status 429 if METH_POST wp_login_path { sc_http_req_rate(1) gt 30 } !is_local !is_trusted_ip !is_whitelisted

    # --- WordPress wp-login.php "must-load-the-form-first" cookie challenge ---
    # Defeats DISTRIBUTED credential-stuffing (hundreds of thousands of unique
    # IPs, each low-and-slow, so the per-IP rule above can't see them). Such
    # bots POST straight to /wp-login.php without ever GETting the form — on
    # these sites the login POST:GET ratio is ~15:1. We hand out a cookie when
    # the form is actually fetched (GET) and require it on POST; direct-POST
    # bots lack it and are denied AT THE EDGE before reaching PHP. Real logins
    # are unaffected — WordPress login already requires loading the page and
    # accepting cookies. Immediate deny (NOT tarpit) — under a 300k-POST flood,
    # holding tarpit connections would exhaust HAProxy. Honors the whitelist.
    # Mark login-form GETs at REQUEST time (method/path are reliably evaluable
    # here; in the response phase they are not) so the cookie is emitted on the
    # form's own response.
    http-request set-var(txn.wp_login_form) int(1) if METH_GET wp_login_path
    http-after-response add-header set-cookie "whplc=1; Path=/; Max-Age=1800; HttpOnly; Secure; SameSite=Lax" if { var(txn.wp_login_form) -m found }
    acl has_login_cookie req.cook(whplc) -m found
    http-request deny deny_status 403 if METH_POST wp_login_path !has_login_cookie !is_local !is_trusted_ip !is_whitelisted

    # IP blocking using map file (manual blocks only)
    # Map file format: /etc/haproxy/blocked_ips.map contains "<ip_or_cidr> 1" per line
    # Runtime updates: echo "add map #0 IP_ADDRESS 1" | socat stdio /var/run/haproxy.sock
    # Checks the real client IP (from headers if present, otherwise src)
    # map_ip() converter supports both single IPs and CIDR ranges (e.g., 192.168.1.0/24)
    acl is_blocked_ip var(txn.real_ip),map_ip(/etc/haproxy/blocked_ips.map,0) -m int gt 0
    http-request set-path /blocked-ip if is_blocked_ip
    use_backend default-backend if is_blocked_ip
{%- if suspension_enabled %}

    # Site suspension routing. Any Host header listed in
    # /etc/haproxy/suspended_domains.list is rewritten to /suspended and
    # routed through default-backend, which is the same Flask app that
    # serves the default page and blocked-ip page (port 8080 inside this
    # container). The `/suspended` route returns HTTP 503 with a static
    # suspension page. External tooling (e.g. WHP's site_disable.php)
    # maintains the list file via `docker cp`. An empty list is safe —
    # the ACL simply doesn't match. Sits after IP-blocking so 429/403
    # still trigger first.
    acl is_suspended_domain hdr(host),lower -f /etc/haproxy/suspended_domains.list
    http-request set-path /suspended if is_suspended_domain
    use_backend default-backend if is_suspended_domain
{%- endif %}
{%- if coraza_spoe_backend %}

    # Coraza WAF inspection via SPOE. Runs AFTER rate-limit and IP-block
    # guards (no point asking the WAF about requests we're already dropping)
    # and AFTER the real-client-IP resolution (so Coraza sees the right src).
    filter spoe engine coraza config /etc/haproxy/coraza-spoe.cfg
    http-request send-spoe-group coraza coraza-req

    # Enforce Coraza's verdict. The SPOA sets var(txn.coraza.action) to
    # "deny" / "drop" / "redirect" when a rule with the corresponding
    # disruptive action fires (depends on SecRuleEngine mode + per-rule
    # ctl:ruleEngine overrides). Without these rules, Coraza would inspect
    # but never block.
    #
    # On request-phase deny we return a rendered HTML page that surfaces the
    # request reference (the unique-id) so a customer who's been blocked
    # incorrectly can open a support ticket and quote it. lf-file expands
    # log-format expressions inside the file at response time, so
    # %[unique-id] / %[req.hdr(host)] / etc. get substituted live.
    # Response-phase deny stays as a bare 403 — outbound blocks are rare in
    # our config (Coraza response inspection is disabled by default) and
    # an HTML body on a 403 generated mid-response could land mid-stream.
    http-request return status 403 content-type "text/html; charset=utf-8" hdr waf-block "request" hdr x-request-reference "%[unique-id]" lf-file /haproxy/errors/403-waf.html if { var(txn.coraza.action) -m str deny }
    http-response deny deny_status 403 hdr waf-block "response" hdr x-request-reference "%[unique-id]" if { var(txn.coraza.action) -m str deny }
    http-request silent-drop if { var(txn.coraza.action) -m str drop }
    http-response silent-drop if { var(txn.coraza.action) -m str drop }
    http-request redirect code 302 location %[var(txn.coraza.data)] if { var(txn.coraza.action) -m str redirect }
    http-response redirect code 302 location %[var(txn.coraza.data)] if { var(txn.coraza.action) -m str redirect }

    # FAIL-OPEN on SPOA error. Upstream's example does the opposite — denies
    # 500 if var(txn.coraza.error) is set — but for a hosting platform we'd
    # rather lose WAF coverage briefly than 503 customer sites. The error
    # variable still gets set, so monitoring can observe it.
{%- endif %}
