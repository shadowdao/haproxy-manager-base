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

    # --- Trusted-proxy gate (MUST precede real-IP resolution below) ---
    # CF-Connecting-IP / X-Real-IP / X-Forwarded-For are client-supplied. Any
    # peer that is not a known reverse proxy gets them stripped, so the
    # set-var chain below falls through to `src` -- the real TCP peer.
    #
    # Without this, a direct client dictates txn.real_ip, and every control
    # keyed on that variable trusts the attacker's own claim: rate limiting
    # (track-sc0), the trusted-IP whitelist, the wp-login brute-force table and
    # cookie challenge, the wp-json/batch/v1 virtual patch, IP blocking, and
    # Coraza's src-ip. Spoofing a whitelisted IP bypassed all of them.
    #
    # ORDER MATTERS: these must come before the set-var lines. HAProxy applies
    # http-request rules in file order, so a strip placed afterwards would
    # validate cleanly and accomplish nothing.
    #
    # Cloudflare-fronted domains keep working: CF's edge matches
    # from_trusted_proxy, so its CF-Connecting-IP survives.
    acl from_trusted_proxy src -f /etc/haproxy/cloudflare_ips.list -f /etc/haproxy/trusted_proxies.list
    http-request del-header CF-Connecting-IP if !from_trusted_proxy
    http-request del-header X-Real-IP        if !from_trusted_proxy
    http-request del-header X-Forwarded-For  if !from_trusted_proxy

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

    # --- WordPress xmlrpc.php flood protection ---
    # xmlrpc.php floods are a common, sustained abuse pattern that the generic
    # limits above don't catch: those trigger at 3000/5000 req/10s (300-500
    # req/s, sized for media-heavy pageloads), while observed xmlrpc floods run
    # at just a few req/s for hours -- comfortably under that ceiling but still
    # enough to pin PHP-FPM workers and show up as 503s for the rest of the
    # site. Same shape of problem as wp-login credential stuffing, so it gets
    # the same fix: track POSTs to xmlrpc.php per real client IP in a DEDICATED
    # 60s table (sc2 / backend xmlrpc_bruteforce, defined in
    # hap_security_tables.tpl -- kept separate from wp_bruteforce so the two
    # endpoints' traffic can't inflate each other's counter, see that file for
    # the reasoning) and tarpit once an IP exceeds the threshold.
    #
    # Threshold is 60/min (double wp-login's 30/min), not because xmlrpc abuse
    # is less severe but because legitimate traffic here is machine-to-machine
    # rather than a human filling out a form: Jetpack sync, the WordPress
    # mobile app, and remote-publishing clients (e.g. an offline blog editor)
    # can legitimately burst several xmlrpc calls in quick succession. 60/min
    # (1 req/s average over the window) comfortably absorbs that burst while
    # still tripping well before an hours-long few-req/s flood does real
    # damage -- at 2 req/s sustained the 60s counter clears the threshold in
    # under a minute.
    #
    # Tarpit (not deny), matching the wp-login rule: this is per-IP tracking
    # of a bounded set of offenders, not the wp-login cookie challenge's
    # distributed hundreds-of-thousands-of-IPs scenario where holding
    # connections would exhaust HAProxy itself, so tying up the flooding IP's
    # connections is the cheaper and more effective response. path_end (not
    # path_beg) covers subdirectory WP installs, same reasoning as wp-login.
    # Honors the same whitelist (RFC1918 / trusted_ips.list / trusted_ips.map)
    # so health checks and trusted infrastructure are unaffected, and legit
    # clients under the threshold are never blocked outright.
    acl xmlrpc_path path_end /xmlrpc.php
    http-request track-sc2 var(txn.real_ip) table xmlrpc_bruteforce if METH_POST xmlrpc_path
    http-request tarpit deny_status 429 if METH_POST xmlrpc_path { sc_http_req_rate(2) gt 60 } !is_local !is_trusted_ip !is_whitelisted

    # WordPress REST batch endpoint lockdown ("wp2shell": CVE-2026-63030 +
    # CVE-2026-60137). Chaining a core SQL injection with REST batch-route
    # confusion gives unauthenticated RCE on WP 6.9.0-6.9.4 and 7.0.0-7.0.1
    # (fixed in 6.9.5 / 7.0.2). Exploits are public and were used against this
    # fleet on 2026-07-19/20; one site was compromised via this path before
    # patching. This is a virtual patch: it does not repair the vulnerable
    # application logic, it only removes reachability, so it stays until every
    # site is confirmed on a fixed release.
    #
    # Both routing forms must be covered -- a rule matching only the pretty
    # permalink path leaves the ?rest_route= fallback wide open, and urlp()
    # does not URL-decode, hence the third ACL for the %2F spelling.
    #
    # Anonymous-only. batch/v1 is used legitimately by the block editor for
    # multi-entity saves, so a blanket deny would break wp-admin for real
    # users; requiring a wordpress_logged_in_* cookie costs them nothing.
    # req.cook() needs an exact name and WordPress suffixes a per-site hash,
    # so this substring-matches the raw Cookie header instead.
    #
    # Immediate deny, not tarpit -- holding connections open helps an attacker
    # who is already scripting this. Honors the same whitelist as above.
    acl wp_batch_path path_beg /wp-json/batch/v1
    acl wp_batch_route urlp(rest_route) -i -m beg /batch/v1
    acl wp_batch_route_enc query -i -m sub rest_route=%2Fbatch%2Fv1
    acl has_wp_logged_in req.hdr(Cookie) -i -m sub wordpress_logged_in_
    http-request deny deny_status 403 if wp_batch_path !has_wp_logged_in !is_local !is_trusted_ip !is_whitelisted
    http-request deny deny_status 403 if wp_batch_route !has_wp_logged_in !is_local !is_trusted_ip !is_whitelisted
    http-request deny deny_status 403 if wp_batch_route_enc !has_wp_logged_in !is_local !is_trusted_ip !is_whitelisted

    # --- WordPress admin edge gate ---
    # Measured on whp02, 2026-08-14: distributed unauthenticated GETs booting
    # WordPress just to bounce back a login redirect --
    #   2801 GET /wp-admin/profile.php   2781 GET /wp-admin/edit.php   2761 GET /wp-admin/plugins.php
    # -- spread across many source IPs at roughly 4 req/min per IP, each hit
    # burning a PHP-FPM/lsphp worker. Two sites absorbed 1,243 resulting 503s
    # in nine hours as their pools saturated.
    #
    # IDENTITY, NOT RATE. This is the one rule in this file that tracks
    # nothing and has no stick-table counter or threshold. Every rate-based
    # control above (the generic limits, wp_bruteforce, xmlrpc_bruteforce) is
    # per-IP, and per-IP rate is exactly what this attack is engineered to
    # stay under: ~4 req/min from any single IP is indistinguishable from a
    # slow human, and the source set is large enough that no threshold can be
    # lowered to catch it without also catching real visitors. There is also
    # no free stick-table slot left to try anyway -- sc0/sc1/sc2 are already
    # used above and HAProxy's default tune.stick-counters is 3, so a fourth
    # tracked counter is not an option here. DO NOT "simplify" this into a
    # rate/threshold rule later: the whole point is that a threshold cannot
    # see this traffic. Instead we gate on identity -- a real logged-in
    # WordPress user always carries a wordpress_logged_in_* cookie (the same
    # ACL the wp2shell block above already declares), and an unauthenticated
    # request to a wp-admin page has no legitimate reason to boot PHP at all.
    #
    # 302, not 403. WordPress itself redirects an unauthenticated /wp-admin/
    # request to wp-login.php, so replicating that at the edge means an admin
    # whose session merely expired lands on the normal login screen instead
    # of an error page -- we are not trading a bot problem for a support
    # ticket. Bots get a cheap redirect they ignore.
    #
    # path_reg, not path_beg. A subdirectory install at /blog/wp-admin/ slips
    # past a prefix match; path_reg with an optional leading "/" catches both
    # root and subdirectory installs, same reasoning as the wp-login and
    # xmlrpc path_end rules above.
    #
    # regsub rewrites the redirect target itself, so /blog/wp-admin/x.php
    # redirects to /blog/wp-login.php rather than 404ing at the site root.
    #
    # DO NOT write regsub's regex argument with a capturing group / literal
    # parentheses, e.g. regsub((^|/)wp-admin/.*,\1wp-login.php) -- neither
    # inlined into the redirect's `location` nor in a standalone set-var.
    # HAProxy 3.0.11's converter-argument parser counts parens to find the
    # end of the regsub(...) call itself, so the *inner* "(^|/)" grouping
    # parens are misread as closing the outer call early -- it does not
    # matter whether the argument is quoted ("...": still fails) or the
    # parens are backslash-escaped (\(...\): still fails). Every such form
    # was verified against real HAProxy 3.0.11-1+deb13u3 and all produce the
    # same ALERT: "invalid arg 2 in converter 'regsub' : missing arguments
    # (got 1/2)". This is a converter-argument-parsing limitation, not a
    # log-format/`%[...]` issue -- the identical failure reproduces in a
    # plain set-var (outside any log-format string), which rules out the
    # `location` value's log-format context as the cause.
    #
    # The fix sidesteps groups/backreferences entirely: HTTP paths always
    # start with "/", so the leading "(^|/)" alternation is redundant --
    # matching the literal substring "/wp-admin/" (both slashes, no group)
    # is sufficient to anchor to a real path segment (a false match like
    # "/somewp-admin/" doesn't contain "/wp-admin/" as a substring, since
    # there's no "/" directly before "wp-admin"). No backreference is
    # needed either: regsub only replaces the matched substring, so
    # replacing "/wp-admin/.*" with a literal "/wp-login.php" leaves
    # whatever precedes it (the subdirectory-install prefix, if any)
    # untouched. Computed in its own set-var so it is a plain sample
    # expression, not something baked into the redirect's log-format
    # string. Behaviorally verified live against real HAProxy 3.0.11:
    # /wp-admin/edit.php -> /wp-login.php and
    # /blog/wp-admin/plugins.php -> /blog/wp-login.php, both with
    # redirect_to preserved. See
    # .superpowers/sdd/2026-08-14-wpadmin-edge-gate/task-3b-report.md.
    #
    # redirect_to carries the path only (%[path,url_enc]), not the query
    # string -- deliberate, see design spec. An admin bounced off
    # post.php?post=123&action=edit lands back on a blank post.php rather
    # than that exact post. Capturing the full URI needs capture.req.uri
    # (extra config, and the captured value is length-capped) for a benefit
    # that only matters on session expiry, so it was not worth it.
    #
    # THE ALLOWLIST IS MEASURED, NOT GUESSED -- taken from actual fleet
    # traffic returning 200 on /wp-admin/*. admin-ajax.php and admin-post.php
    # are the standard front-end AJAX/form-handler endpoints real themes and
    # plugins call while logged out. Critically, wp-login.php loads its OWN
    # css/js FROM /wp-admin/ (load-styles.php, load-scripts.php, and the
    # static wp_admin_asset dirs below) -- miss those and every login page on
    # the fleet renders unstyled with a broken password-strength meter, while
    # wp-login.php itself still returns 200, making it a silent regression
    # that "looks like" the gate is working.
    #
    # Each allowlist entry is anchored to /wp-admin/<file>, not a bare
    # filename suffix. A bare `path_end /admin-ajax.php` also matches
    # /wp-admin/evil/admin-ajax.php -- which ALSO matches wp_admin_path
    # (path_reg only requires /wp-admin/ to appear somewhere), so an
    # attacker-inserted path segment would sail through this allowlist
    # ungated and boot full WordPress, exactly the resource exhaustion this
    # gate exists to stop. Anchoring still covers subdirectory installs via
    # suffix matching (/blog/wp-admin/admin-ajax.php ends with
    # /wp-admin/admin-ajax.php) while rejecting an inserted directory.
    #
    # install.php is DELIBERATELY NOT allowlisted. It is legitimately
    # reachable without a cookie during a fresh install, but it is also a
    # standing scanner target and a real takeover vector on a site that was
    # half-installed and then abandoned. Anyone genuinely installing uses the
    # per-site exempt-list opt-out below instead.
    #
    # Honors the same whitelist as every other rule in this frontend
    # (RFC1918 / trusted_ips.list / trusted_ips.map), and a per-site opt-out
    # via /etc/haproxy/wpadmin_gate_exempt.list (operator-managed, seeded
    # empty by start-up.sh) for sites where a plugin legitimately serves
    # unauthenticated visitors from a /wp-admin/ URL outside this allowlist.
    acl wp_admin_path      path_reg (^|/)wp-admin/
    acl wp_admin_allowed   path_end /wp-admin/admin-ajax.php /wp-admin/admin-post.php /wp-admin/load-styles.php /wp-admin/load-scripts.php
    acl wp_admin_asset     path_reg (^|/)wp-admin/(css|js|images)/
    acl wp_gate_exempt     hdr(host),lower -f /etc/haproxy/wpadmin_gate_exempt.list
    http-request set-var(txn.wp_login_url) path,regsub(/wp-admin/.*,/wp-login.php) if wp_admin_path
    http-request redirect code 302 location %[var(txn.wp_login_url)]?redirect_to=%[path,url_enc] if wp_admin_path !wp_admin_allowed !wp_admin_asset !has_wp_logged_in !wp_gate_exempt !is_local !is_trusted_ip !is_whitelisted

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
