#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    # ACCESS LOG DESTINATION: a UNIX datagram socket INSIDE this container.
    #
    # scripts/haproxy-log-receiver.py (supervised by start-up.sh) reads it and
    # writes a size-capped, rotating /var/log/haproxy/access.log in the
    # haproxy-logs volume. No network listener anywhere.
    #
    # History: `log 127.0.0.1 local2` was a black hole (nothing listened in
    # the container netns); its successor, the docker bridge gateway
    # 172.18.0.1:514 with a host rsyslog imudp listener, had no listener on
    # the fleet either (probable cause, not measured: rsyslog binds that
    # address once at boot, before docker has created the bridge, and does
    # not retry). Either way per-IP
    # 429s, tarpits, gate redirects and WAF 403s left no record.
    #
    # WHY NOT `log stdout`: silently emits NOTHING with `daemon` (below) on
    # the pinned 3.0.11 (`haproxy -c` still passes), and dropping `daemon`
    # breaks the synchronous `haproxy -W` launch sites in haproxy_manager.py.
    # Also, `docker logs haproxy-manager` feeds WHP's AI log monitor, which
    # must not get a per-request firehose.
    #
    # The path is relative to the `chroot` below: HAProxy resolves it after
    # chrooting, so `/log.sock` here is /var/lib/haproxy/log.sock on disk,
    # which is where the receiver binds (HAPROXY_LOG_SOCKET).
    #
    # Sends are non-blocking: a dead receiver or a full socket buffer drops
    # log lines, never stalls a request. HAPROXY_SYSLOG_TARGET still
    # overrides the target (`<ip>:<port>` for a remote collector).
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
{%- if coraza_spoe_backend %}

    # WAF BODY INSPECTION LIMIT. Only emitted when Coraza is wired in, so a
    # WAF-off / standalone config is unchanged byte-for-byte. 16384 is also
    # HAProxy's default: this line changes no behaviour or memory, it pins
    # the value so nobody raises it without reading this.
    #
    # The request body Coraza sees is whatever `req.body` holds when
    # send-spoe-group fires, and with `option http-buffer-request`
    # (hap_listener.tpl) that is "the whole body, or as much as fits in ONE
    # buffer". So bufsize IS the inspection limit: a body up to roughly
    # bufsize - maxrewrite (1024) - the request headers (~15 KB) is inspected
    # whole and stamped `complete`; anything larger is forwarded intact, its
    # first ~15 KB inspected, and stamped `partial`. Large uploads are never
    # rejected or held for it.
    #
    # DO NOT RAISE THIS WITHOUT RE-MEASURING -- three ceilings, all measured:
    #   * TIME. Coraza+CRS 4.25 costs ~3.3 ms per KB of body (linear; 31 KB
    #     base64 = 104 ms, 15 KB = ~50 ms on a 32-core box). The SPOE
    #     `timeout processing` is 100 ms (hap_coraza_spoe_engine.tpl) and a
    #     timeout FAILS OPEN: with tune.bufsize 32768 a payload at byte 0 of a
    #     30 KB base64 multipart body passed 933180 uninspected. A larger
    #     buffer is a bypass, not more coverage, unless the timeout (and CPU
    #     budget) grows with it.
    #   * FRAME. coraza-spoa's SPOP library (dropmorepackets/haproxy-go
    #     v0.0.8) refuses a HELLO whose max-frame-size exceeds 65535; HAProxy
    #     derives its offer from bufsize. bufsize >= 64 KB = every SPOE
    #     handshake fails = WAF silently off for all traffic.
    #   * MEMORY. maxconn 4000 x 2 buffers x bufsize, inside the 1 GB edge
    #     container.
    # Coraza's SecRequestBodyLimit (coraza-spoa/config.yaml, 131072) must stay
    # above anything this can deliver. Pinned by
    # scripts/test-waf-body-inspection.py.
    tune.bufsize 16384
{%- endif %}

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
    