# Base image mirrored into the in-house registry to remove docker.io
# (Cloudflare R2) as a single point of failure for CI builds. The 2026-05-12
# Cloudflare incident took down docker.io blob pulls and broke this image's CI.
# Refresh procedure (run on a workstation that can reach docker.io, e.g.
# monthly or when Python patches drop):
#     docker pull docker.io/library/python:3.12-slim
#     docker tag  docker.io/library/python:3.12-slim \
#                 repo.anhonesthost.net/cloud-hosting-platform/python:3.12-slim
#     docker push repo.anhonesthost.net/cloud-hosting-platform/python:3.12-slim
# Future improvement: a scheduled Gitea Action that does the above automatically.
FROM repo.anhonesthost.net/cloud-hosting-platform/python:3.12-slim

# image.source is what ghcr.io uses to link the package to a GitHub repo
# sidebar; pointing at the public GitHub mirror enables that linking. The
# canonical source-of-truth git remote is still Gitea, but Gitea's registry
# doesn't consume this label, so there's no contention.
# Stamped from the VERSION file by CI (build-arg) so `docker inspect` reports
# what's running on any host. Defaults to "dev" for local/manual builds.
ARG VERSION=dev
LABEL org.opencontainers.image.title="haproxy-manager-base" \
      org.opencontainers.image.description="HAProxy management API with Let's Encrypt automation, Coraza WAF integration, and template-driven config" \
      org.opencontainers.image.source="https://github.com/shadowdao/haproxy-manager-base" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"

# haproxy is PINNED. It was previously unpinned, so the binary could move under
# us at Debian's timing — an upstream release that rejected our config would have
# broken an unrelated commit's build, or worse, shipped an edge that refuses to
# start (see the `haproxy -c` gate below for why that matters: a config HAProxy
# rejects leaves the container Up with 80/443 unbound and /health still 200).
#
# Pinning does NOT make the gate redundant, and the gate does NOT make pinning
# unnecessary — they compose. Pinned means the version moves deliberately; the
# gate then answers immediately whether the new binary still accepts fleet config.
# It also makes the image reproducible, which it previously was not.
#
# To move it: bump the version here, rebuild, and let the gate verify. If Debian
# security-updates the package (e.g. -1+deb13u4) the build FAILS until this pin is
# updated — that failure is the point, not a bug. Check availability with:
#   apt-cache policy haproxy
ARG HAPROXY_VERSION=3.0.11-1+deb13u3
RUN apt update -y && apt dist-upgrade -y && apt install socat "haproxy=${HAPROXY_VERSION}" cron certbot curl jq net-tools -y && apt-mark hold haproxy && apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /haproxy
COPY ./templates /haproxy/templates
COPY requirements.txt /haproxy/
COPY haproxy_manager.py /haproxy/
COPY scripts /haproxy/scripts
COPY trusted_ips.list /etc/haproxy/trusted_ips.list
COPY trusted_ips.map /etc/haproxy/trusted_ips.map
# /etc/haproxy is a named volume in deployed containers, so baked-in files
# under that path get shadowed by the volume on existing deployments. The
# trusted_ips.* pair above predates that discovery and is handled by the
# older start-up.sh guard (out of scope here). cloudflare_ips.list and
# trusted_proxies.list are staged under /haproxy/defaults instead, so
# start-up.sh can always read the image's baked copy regardless of what the
# volume shadows /etc/haproxy with.
COPY cloudflare_ips.list /haproxy/defaults/cloudflare_ips.list
COPY trusted_proxies.list /haproxy/defaults/trusted_proxies.list
COPY wpadmin_gate_exempt.list /haproxy/defaults/wpadmin_gate_exempt.list
# Place errorfiles outside the volumed path; the HAProxy config references
# them by absolute path.
COPY errors /haproxy/errors
RUN chmod +x /haproxy/scripts/*
RUN pip install -r requirements.txt
# ---------------------------------------------------------------------------
# Build gate: no image ships unless the real haproxy binary accepts the config
# this image's templates actually produce.
#
# On 2026-08-14 a template change rendered fine, passed all 13 unit tests, and
# was rejected by HAProxy ("invalid arg 2 in converter 'regsub'"). It was only
# caught because someone built an image by hand and ran `haproxy -c`. Nothing
# in the build or in CI would have stopped it: .gitea/workflows/build-push.yaml
# is checkout -> build -> push, and test-config-rollback.py's "haproxy" is a
# shell stub that only rejects a sentinel token. In production an invalid
# haproxy.cfg means init.py refuses to start HAProxy while the container stays
# Up - ports 80/443 unbound, every site on the host down, /health still 200.
#
# This lives in the Dockerfile rather than in the workflow deliberately:
#   * it cannot be skipped, and it protects local `docker build` too;
#   * no workflow restructuring (build-push-action builds and pushes in one
#     step, so gating in CI would mean splitting build from push);
#   * it validates against the EXACT haproxy binary in this image. Line 26
#     installs haproxy unpinned, so that binary moves between builds - this
#     turns "the new haproxy rejects our config" from a silent production
#     risk into a build failure.
#
# The unit suites run here too. They had never run anywhere automated either,
# and they cost a few seconds.
RUN python3 /haproxy/scripts/test-wpadmin-gate.py \
 && python3 /haproxy/scripts/test-trusted-proxy-gate.py \
 && python3 /haproxy/scripts/test-xmlrpc-rate-limit.py \
 && python3 /haproxy/scripts/test-config-rollback.py \
 && python3 /haproxy/scripts/test-cert-write-safety.py \
 && python3 /haproxy/scripts/test-cert-scripts.py \
 && python3 /haproxy/scripts/validate-rendered-config.py
# Create log directories
RUN mkdir -p /var/log && touch /var/log/haproxy-manager.log /var/log/haproxy-manager-errors.log
RUN chmod 755 /var/log/haproxy-manager.log /var/log/haproxy-manager-errors.log
# Set up cron for certificate renewal with proper permissions and environment
RUN mkdir -p /var/spool/cron/crontabs && \
    echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' > /var/spool/cron/crontabs/root && \
    echo '0 */12 * * * /haproxy/scripts/renew-certificates.sh >> /var/log/haproxy-manager.log 2>&1' >> /var/spool/cron/crontabs/root && \
    chmod 600 /var/spool/cron/crontabs/root && \
    chown root:crontab /var/spool/cron/crontabs/root
# 443/udp carries HTTP/3 (QUIC). EXPOSE is documentation only — the container
# must still be run with `-p 443:443/udp` for the UDP listener to be reachable.
EXPOSE 80 443 443/udp 8000
# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf --max-time 5 http://localhost:8000/health && curl -s --max-time 5 -o /dev/null http://localhost/ || exit 1
CMD ["/haproxy/scripts/start-up.sh"]