#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    # ACCESS LOG DESTINATION.
    #
    # This used to be `log 127.0.0.1 local2`, which was a silent black hole:
    # 127.0.0.1 is the CONTAINER's own loopback, nothing has ever listened on
    # udp/514 in the container netns, and there is no /dev/log in the image.
    # Every access log line -- ~1.5M/day across the whole edge -- was written
    # to a socket with no receiver and dropped. Nothing errored, nothing
    # warned, and `haproxy -c` was perfectly happy. The cost only shows up
    # during an incident: per-IP 429s, tarpits, wp-admin gate redirects,
    # WAF 403s and `silent-drop`s left no record anywhere, so the edge could
    # not be asked what it had rejected. Only aggregate stick-table counters
    # survived.
    #
    # Now points at the DOCKER BRIDGE GATEWAY, where the host's rsyslog has an
    # imudp listener bound (installed idempotently by WHP's
    # setup-haproxy-logrotate.sh, which also writes the logrotate stanza).
    # The host writes local2 to /var/log/haproxy.log and stops it there, so it
    # does not also flood /var/log/messages or the Graylog forwarder.
    #
    # WHY NOT `log stdout format raw local0`: it is INCOMPATIBLE with the
    # `daemon` keyword below, and incompatible SILENTLY. Verified on the
    # pinned 3.0.11 binary: with `daemon` set, a `log stdout` config serves
    # traffic normally and emits ZERO log lines, and `haproxy -c` returns 0
    # with no error and no warning -- so the CI config gate
    # (scripts/validate-rendered-config.py) cannot catch it either. Making it
    # work means dropping `daemon` / adding -db so haproxy stays in the
    # foreground, which in turn breaks the three synchronous
    # `subprocess.run(['haproxy', '-W', ...], check=True)` launch sites in
    # haproxy_manager.py (they would block until the 180s timeout and then be
    # killed). That is a change to the exact code path whose failure mode is
    # "container Up, ports 80/443 never bound, every site down, /health still
    # 200". Not worth it for a logging change.
    #
    # UDP means a dead listener degrades to dropped log lines, never to a
    # stalled or failing request path -- the correct failure direction for an
    # edge fronting ~60 customer sites.
    #
    # len 2048 accommodates the enriched log-format in hap_listener.tpl
    # (URL + User-Agent + UUID); the default 1024 would truncate long ones.
    log         {{ syslog_target }} len 2048 format rfc5424 local2 info

    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # SSL and Performance
    tune.ssl.default-dh-param 2048

    # Required by the `http-request normalize-uri` chain at the top of the
    # `web` frontend (hap_listener.tpl). normalize-uri is still flagged
    # EXPERIMENTAL in HAProxy 3.0, and HAProxy REFUSES TO START without this
    # opt-in -- not a warning, a fatal:
    #   [ALERT] config : parsing [...] : 'normalize-uri' action is
    #   experimental, must be allowed via a global
    #   'expose-experimental-directives'
    # (verified against real haproxy 3.0.11-9e587df: `haproxy -c` exits 1).
    # So this line and the normalize-uri rules must be added/removed together.
    #
    # Dropping this one alone does NOT crash-loop the container -- the truth
    # is worse: it is a SILENT TOTAL OUTAGE that nothing escalates. Container
    # init (scripts/init.py -> haproxy_manager.do_initial_setup()) calls
    # generate_config() (which still succeeds -- Jinja doesn't validate
    # HAProxy semantics) and then start_haproxy(), which runs `haproxy -c`,
    # sees it fail, logs an error, and RETURNS WITHOUT RAISING. init.py exits
    # 0. scripts/start-up.sh then execs gunicorn as PID 1 regardless. Result:
    # the container stays "Up", ports 80/443 are never bound, EVERY SITE ON
    # THE HOST IS DOWN, and the in-container supervisor loop
    # (ensure_haproxy.py, every HAPROXY_SUPERVISOR_INTERVAL seconds) retries
    # the identical failing render forever without ever escalating. Worse
    # still, GET /health keeps returning HTTP 200 -- health_check() only
    # answers 500 on a database error; a dead haproxy just flips the JSON
    # body's "haproxy_status" to "stopped" while the status code a naive
    # monitor checks never changes. Do not trust /health alone to catch this.
    #
    # This exposes ONLY the experimental directives that are actually used --
    # it does not change the behaviour of anything else in this file.
    expose-experimental-directives

    # HTTP/3 over QUIC. The Debian haproxy package is built against system
    # OpenSSL via the compatibility shim (USE_QUIC_OPENSSL_COMPAT), which is
    # not a native QUIC TLS stack. HAProxy therefore rejects `quic*@` binds
    # unless this opt-in is set. `limited-quic` enables QUIC through the compat
    # layer (no 0-RTT — that needs quictls/aws-lc or native OpenSSL 3.5 QUIC).
    # Without this, the quic bind in the frontend fails to start: "this SSL
    # library does not support the QUIC protocol".
    limited-quic
{%- if cluster_secret %}

    # Stable secret keying QUIC Retry/address-validation tokens. Self-healed
    # to /etc/haproxy/cluster-secret (named volume) by the manager so it
    # survives recreates; without it haproxy picks a random one per process
    # and tokens don't survive reloads (benign, just a startup notice).
    cluster-secret "{{ cluster_secret }}"
{%- endif %}

    # HTTP/2 protection against Rapid Reset (CVE-2023-44487) and stream abuse
    tune.h2.fe.max-total-streams 2000
    tune.h2.fe.glitches-threshold 50

    # Stats persistence for zero-downtime reloads
    stats-file /var/lib/haproxy/stats.dat

#---------------------------------------------------------------------
# DNS resolver for Docker container name resolution
# Re-resolves backend server addresses so container IP changes
# (from restarts, recreations, scaling) are picked up automatically
#---------------------------------------------------------------------
resolvers docker_dns
    nameserver dns1 127.0.0.11:53
    resolve_retries 3
    timeout resolve 1s
    timeout retry 1s
    hold valid 10s
    hold other 10s
    hold refused 10s
    hold nx 10s
    hold timeout 10s
    hold obsolete 10s

#---------------------------------------------------------------------
# common defaults that all the 'listen' and 'backend' sections will
# use if not designated in their block
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option http-server-close
    option forwardfor       #except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    30s
    timeout queue           2m
    timeout connect         10s
    timeout client          5m
    timeout server          10m
    timeout http-keep-alive 30s
    timeout check           10s
    timeout tarpit          10s  # Tarpit delay for low-level scanners (before silent-drop)
    maxconn                 3000

    # Per-request unique reference, used:
    #   - in the access log line, as the `id=` field of the custom log-format
    #     in hap_listener.tpl. NOTE: `option httplog` does NOT include %ID
    #     (verified against haproxy 3.0.11) -- this comment used to claim it
    #     did, which made the support workflow below look supported when it
    #     was not. The explicit log-format is what actually carries it.
    #   - echoed to clients in the X-Request-Reference response header on
    #     WAF blocks so a customer can quote it when opening a support ticket
    #   - embedded in /etc/haproxy/errors/403-waf.html so a blocked visitor
    #     sees it on the rendered 403 page
    # Support correlates ref → /var/log/haproxy.log line → timestamp+client+host
    # → /var/log/coraza/audit.log entry → rule_id.
    unique-id-format        %[uuid()]
    unique-id-header        X-Request-Reference
    