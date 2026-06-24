#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    # to have these messages end up in /var/log/haproxy.log you will
    # need to:
    #
    # 1) configure syslog to accept network log events.  This is done
    #    by adding the '-r' option to the SYSLOGD_OPTIONS in
    #    /etc/sysconfig/syslog
    #
    # 2) configure local2 events to go to the /var/log/haproxy.log
    #   file. A line like the following can be added to
    #   /etc/sysconfig/syslog
    #
    #    local2.*                       /var/log/haproxy.log
    #
    log         127.0.0.1 local2

    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # SSL and Performance
    tune.ssl.default-dh-param 2048

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
    #   - in the log line (httplog includes %ID)
    #   - echoed to clients in the X-Request-Reference response header on
    #     WAF blocks so a customer can quote it when opening a support ticket
    #   - embedded in /etc/haproxy/errors/403-waf.html so a blocked visitor
    #     sees it on the rendered 403 page
    # Support correlates ref → /var/log/haproxy.log line → timestamp+client+host
    # → /var/log/coraza/audit.log entry → rule_id.
    unique-id-format        %[uuid()]
    unique-id-header        X-Request-Reference
    