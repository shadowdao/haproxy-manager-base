# HAProxy 3.0.11 advanced security implementation guide

HAProxy 3.0.11 represents a significant leap in load balancer security capabilities, introducing enhanced tarpit mechanisms, array-based GPCs with up to 100 elements per array, and sophisticated HTTP/2 protection features. This Long Term Support version, maintained until 2029, delivers up to 6x performance improvements in stick-table operations while maintaining robust backward compatibility with version 2.x configurations.

## Tarpit mechanisms and dynamic blocking architecture

HAProxy 3.0.11's tarpit functionality operates as a sophisticated resource exhaustion defense, accepting connections but deliberately delaying responses to tie up attacker resources. The implementation leverages **sharded stick tables** with reduced lock contention, achieving near-lockless operations on high-volume systems through read-write locks instead of exclusive locking mechanisms.

The core tarpit configuration introduces progressive response strategies:

```haproxy
frontend advanced_security
    bind :80
    
    # High-performance stick table with optimized locking
    stick-table type ipv6 size 1000k expire 30s store gpc0,conn_rate(10s),http_req_rate(10s)
    http-request track-sc0 src
    
    # Progressive blocking thresholds
    acl moderate_abuse sc_http_req_rate(0) gt 50
    acl severe_abuse sc_http_req_rate(0) gt 100
    acl blocked_client src_get_gpc0 gt 0
    
    # Graduated response system
    timeout tarpit 5s
    http-request tarpit deny_status 429 if moderate_abuse !severe_abuse
    http-request tarpit deny_status 503 if severe_abuse
    http-request silent-drop if blocked_client
    
    # Persistent blocking for severe abusers
    acl mark_abuser sc_inc_gpc0 ge 0
    http-request capture req.hdr(User-Agent) len 128 if mark_abuser severe_abuse
```

Performance benchmarks demonstrate **minimal CPU overhead** (less than 1% additional processing) for tarpit operations, with hash-based IP lookups maintaining O(1) complexity even at millions of concurrent tracked IPs. The zero-copy forwarding introduced in 3.0 eliminates additional buffering, preserving data in CPU caches and reducing memory usage during request processing.

## Array-based GPC implementation for threat scoring

The revolutionary array-based General Purpose Counter system enables multi-dimensional threat analysis through indexed counter arrays. Unlike legacy GPCs limited to two counters (gpc0, gpc1), the new syntax supports comprehensive threat matrices:

```haproxy
backend threat_detection
    stick-table type ip size 1m expire 24h store \
        gpc(20),gpc_rate(20,60s),gpt(10),glitch_cnt,glitch_rate(60s)
    
    # Threat scoring matrix with weighted calculations
    # GPC Index Assignment:
    # 0: Authentication failures    Weight: 10
    # 1: Authorization failures     Weight: 8
    # 2: Input validation failures  Weight: 6
    # 3: Rate limit violations     Weight: 4
    # 4: Suspicious paths          Weight: 7
    # 5: Protocol violations       Weight: 12
    
    http-request track-sc0 src
    
    # Increment specific threat indicators
    http-response sc-inc-gpc(0,0) if { status 401 }
    http-response sc-inc-gpc(1,0) if { status 403 }
    http-request sc-inc-gpc(4,0) if { path_beg /admin /wp-admin }
    
    # Calculate composite threat score
    acl threat_score_critical expr \
        sc_gpc(0,0)*10 + sc_gpc(1,0)*8 + sc_gpc(2,0)*6 + \
        sc_gpc(3,0)*4 + sc_gpc(4,0)*7 + sc_gpc(5,0)*12 gt 200
    
    http-request deny deny_status 403 if threat_score_critical
```

Memory calculations for array-based GPCs follow a predictable pattern: each table entry requires approximately **50 bytes base overhead** plus 4 bytes per GPC counter and 20 bytes per rate counter. A configuration with 100,000 entries using 10 GPCs with rates consumes approximately 32.4 MB, representing efficient memory utilization for enterprise-scale deployments.

## HTTP/2 security and glitch detection

HAProxy 3.0.11's HTTP/2 implementation provides **inherent protection** against CONTINUATION flood attacks through buffer-based defenses. Each stream receives a dedicated 16KB buffer (configurable via `tune.bufsize`), with automatic stream termination when buffers fill without receiving END_HEADERS flags. The system processes up to 1,000,000 CONTINUATION frames per second per CPU core while maintaining protection.

The new glitch detection system tracks protocol anomalies through specialized counters:

```haproxy
frontend h2_security
    bind :443 ssl crt /path/to/cert.pem alpn h2,http/1.1
    
    # Configure stream limits and glitch thresholds
    stick-table type ip size 100k expire 1h store \
        glitch_cnt,glitch_rate(60s),gpc(10),gpc_rate(10,60s)
    
    http-request track-sc0 src
    
    # Enhanced logging with glitch information
    log-format "%{+json}o %(glitches)[fc_glitches] %(streams)[fc_nb_streams] \
                %(backend_glitches)[bc_glitches] %(threat_score)[sc_get_gpt(0,0)]"
    
    # Block based on glitch patterns
    acl high_glitch_rate sc_glitch_rate(0) gt 5
    acl glitch_abuse fc_glitches gt 100
    http-request tarpit deny_status 400 if high_glitch_rate
    http-request deny if glitch_abuse
```

The `tune.h2.fe-max-total-streams` parameter prevents resource monopolization by limiting total streams per connection, forcing periodic rebalancing through graceful GOAWAY frames. Combined with `tune.h2.fe.glitches-threshold`, this creates a comprehensive defense against HTTP/2-specific attack vectors including Rapid Reset (CVE-2023-44487) and protocol-level exploits.

## Enhanced rate limiting with selective status code tracking

The new `http-err-codes` and `http-fail-codes` directives enable precise tracking of specific HTTP status codes, moving beyond simplistic rate limiting to behavioral analysis:

```haproxy
global
    # Define custom error tracking
    http-err-codes 400-499 -404 +429  # Exclude 404s, explicitly include 429s
    http-fail-codes 500-503 +504      # Server errors plus gateway timeout
    
frontend api_gateway
    stick-table type ip size 10m expire 24h store \
        http_req_rate(60s),http_err_rate(60s),http_fail_rate(60s),gpc(5)
    
    http-request track-sc0 src
    
    # Progressive rate limiting based on error patterns
    acl error_spike sc_http_err_rate(0) gt 10
    acl failure_pattern sc_http_fail_rate(0) gt 5
    acl repeat_offender sc_get_gpc(0,0) gt 3
    
    # Escalation mechanism
    http-request sc-inc-gpc(0,0) if error_spike
    http-request set-status 429 if error_spike !repeat_offender
    http-request tarpit if repeat_offender
```

This granular approach enables **false positive reduction** by excluding legitimate error codes (like 404s for dynamic content) while focusing on actual abuse patterns. The integration with stick tables allows correlation between error rates, request patterns, and behavioral anomalies.

## Production-ready security workflows

A complete production deployment integrates multiple security layers with automated threat response:

```haproxy
global
    # Performance and security optimization
    tune.h2.fe-max-total-streams 2000
    tune.h2.fe.glitches-threshold 50
    tune.bufsize 32768
    tune.ring.queues 16
    
    # Stats persistence for zero-downtime reloads
    stats-file /var/lib/haproxy/stats.dat
    
    # Enhanced error tracking
    http-err-codes 400-404,429
    http-fail-codes 500-503
    
defaults
    timeout tarpit 10s
    timeout http-request 15s
    
# Centralized threat intelligence
backend threat_intel
    stick-table type ipv6 size 2m expire 24h store \
        gpc(15),gpc_rate(15,60s),gpt(5),glitch_cnt,glitch_rate(300s),\
        http_req_rate(60s),http_err_rate(300s),bytes_out_rate(60s)

frontend security_gateway
    bind :443 ssl crt-list /etc/ssl/certs.list alpn h2,http/1.1
    
    # Multi-dimensional tracking
    http-request track-sc0 src table threat_intel
    tcp-request connection track-sc1 src table threat_intel
    
    # Composite threat scoring
    acl auth_failures sc_gpc(0,0) gt 5
    acl rate_violations sc_gpc(3,0) gt 10
    acl protocol_violations sc_glitch_rate(0) gt 5
    acl bandwidth_abuse sc_bytes_out_rate(0) gt 10485760  # 10MB/s
    
    # Calculate threat level
    http-request set-var(txn.threat_score) int(0)
    http-request add-var(txn.threat_score) sc_gpc(0,0),mul(10)
    http-request add-var(txn.threat_score) sc_gpc(3,0),mul(4)
    http-request add-var(txn.threat_score) fc_glitches,mul(2)
    
    # Progressive response based on threat score
    http-request set-header X-Threat-Level "LOW" if { var(txn.threat_score) lt 20 }
    http-request set-header X-Threat-Level "MEDIUM" if { var(txn.threat_score) ge 20 }
    http-request set-header X-Threat-Level "HIGH" if { var(txn.threat_score) ge 50 }
    http-request tarpit if { var(txn.threat_score) ge 50 }
    http-request deny deny_status 403 if { var(txn.threat_score) ge 100 }
```

## Migration strategy from HAProxy 2.x

The transition to 3.0.11 requires minimal configuration changes while delivering substantial performance improvements. **Stick table operations** show up to 11x improvement on 24-core systems through enhanced locking mechanisms. The migration path preserves backward compatibility while introducing new capabilities:

```haproxy
# Phase 1: Parallel configuration during migration
stick-table type ip size 100k expire 1h store \
    gpc0,gpc1,gpc(10),gpc0_rate(60s),gpc1_rate(60s),gpc_rate(10,60s)

# Maintain dual logic
http-request sc-inc-gpc0(0) if auth_failure     # Legacy
http-request sc-inc-gpc(0,0) if auth_failure    # New array syntax

# Phase 2: Full migration after validation
stick-table type ip size 100k expire 1h store \
    gpc(10),gpc_rate(10,60s),glitch_cnt,glitch_rate(60s)
```

Breaking changes remain minimal: multiple Runtime API commands now require separation, dynamic servers reject the "enabled" keyword, and HTTP/1 request validation becomes stricter. The `expose-deprecated-directives` global option allows gradual migration of legacy features.

## Runtime API enhancements for operational excellence

The enhanced Runtime API enables sophisticated management of security features:

```bash
# Monitor array GPC values
echo "show table threat_intel" | socat stdio /var/run/haproxy.sock

# Set specific threat scores
echo "set table threat_intel key 192.168.1.100 data.gpc(5) 100" | \
    socat stdio /var/run/haproxy.sock

# Automated blacklisting based on threat scores
echo "show table threat_intel" | socat stdio /var/run/haproxy.sock | \
awk '/gpt\(0\)=[0-9]+/ { 
    if ($0 ~ /gpt\(0\)=([5-9][0-9]|[1-9][0-9]{2,})/) {
        match($0, /key=([0-9.]+)/, ip)
        print "add acl virt@blacklist.acl " ip[1]
    }
}' | socat stdio /var/run/haproxy.sock
```

The new pointer-based operations improve efficiency for bulk modifications, while the `wait` command enables complex orchestration of maintenance operations. Stats persistence through GUIDs ensures metrics continuity across reloads, critical for maintaining security baselines.

## Performance metrics and operational considerations

Real-world deployments demonstrate **87.6% cost reduction** and **75% latency improvement** when properly configured. Stick table operations achieve 1.2 million reads per second per core, with write operations sustaining 800,000 operations per second. The memory footprint remains efficient: a million-entry table with 15 GPCs consumes approximately 400MB.

Critical tuning parameters for optimal security-performance balance include setting `tune.h2.fe.max-concurrent-streams` to 100 for balanced security, `tune.h2.fe-max-total-streams` to 2000 for connection cycling, and `tune.bufsize` to 32KB for enhanced HTTP/2 protection. These settings provide robust defense against contemporary attack vectors while maintaining sub-millisecond processing latency.

The integration of virtual ACL files eliminates disk I/O for dynamic blacklisting, enabling real-time threat response without performance degradation. Combined with external threat intelligence feeds and automated scoring systems, HAProxy 3.0.11 provides enterprise-grade security capabilities previously requiring dedicated security appliances.