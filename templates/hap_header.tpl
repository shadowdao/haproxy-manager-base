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

    # HAProxy 3.0.11 Enhanced Security Configuration
    # Selective status code tracking for reduced false positives
    http-err-codes 401,403,429  # Only track security-relevant errors
    http-fail-codes 500-503     # Server errors for monitoring

    # HTTP/2 Security and Performance Tuning
    tune.h2.fe-max-total-streams 2000        # Connection cycling for security
    tune.h2.fe.glitches-threshold 50         # Protocol violation detection
    tune.h2.fe.max-concurrent-streams 100    # Balanced security/performance
    tune.bufsize 32768                       # Enhanced HTTP/2 protection
    tune.ring.queues 16                      # Performance optimization

    # SSL and General Performance
    tune.ssl.default-dh-param 2048

    # Stats persistence for zero-downtime reloads
    stats-file /var/lib/haproxy/stats.dat
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
    timeout http-request    300s
    timeout queue           2m
    timeout connect         120s
    timeout client          10m
    timeout server          10m
    timeout http-keep-alive 120s
    timeout check           10s
    timeout tarpit          10s  # Tarpit delay for low-level scanners (before silent-drop)
    maxconn                 3000
    