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

# haproxy is PINNED to a reviewed UPSTREAM version (HAPROXY_UPSTREAM), not to one
# Debian package revision. It was previously unpinned, so the binary could move
# under us at Debian's timing - an upstream release that rejected our config would
# have broken an unrelated commit's build, or worse, shipped an edge that refuses
# to start (see the `haproxy -c` gate below for why that matters: a config HAProxy
# rejects leaves the container Up with 80/443 unbound and /health still 200).
#
# History: this used to pin the exact Debian version (3.0.11-1+deb13u3). Debian
# security then shipped 3.0.11-1+deb13u4 (same upstream 3.0.11, same arch set) and
# the exact pin silently froze the image on the OLDER, unpatched revision, and
# would hard-fail the build as soon as u3 left the archive. Debian security
# revisions of the SAME upstream version are exactly what we want to take, so:
#   * an apt preference (Pin: version 3.0.11-*) makes apt install the NEWEST
#     Debian revision of that upstream version on any architecture;
#   * the build then FAILS unless the installed package AND `haproxy -v` both
#     report that upstream version, so a major/minor bump (3.0 -> 3.1, 3.0.12)
#     can never arrive by accident: that still needs this ARG changed and the
#     `haproxy -c` gate below to pass.
# The pin and the gate compose: pinned = the version moves deliberately; the gate
# answers immediately whether the new binary still accepts fleet config.
#
# To move to another upstream version: change HAPROXY_UPSTREAM, rebuild, let the
# gate verify. Check what Debian offers with:  apt-cache madison haproxy
ARG HAPROXY_UPSTREAM=3.0.11
# OPTIONAL internal package cache, e.g. --build-arg PKG_CACHE=https://192.168.1.40
# (CT130 pkg-cache, https only; CI sets it only after probing the cache with the
# pinned CA). Unset = the upstream Debian repositories, exactly as before. The
# apt sources are restored before this RUN ends (restore FAILS the build if any
# reference to the cache is left), so no shipped layer carries the cache address.
# Canonical script + docs: cloud-apache-container (scripts/pkg-cache-repos.sh,
# docs/pkg-cache.md there); this repo carries byte-identical copies.
ARG PKG_CACHE=
COPY ./scripts/pkg-cache-repos.sh /usr/local/sbin/pkg-cache-repos.sh
COPY ./keys/pkg-cache/ /usr/local/share/pkg-cache/
RUN /usr/local/sbin/pkg-cache-repos.sh apt && \
    apt update -y && apt dist-upgrade -y && \
    printf 'Package: haproxy\nPin: version %s-*\nPin-Priority: 1001\n' "${HAPROXY_UPSTREAM}" > /etc/apt/preferences.d/haproxy-upstream-pin && \
    apt install socat haproxy cron certbot curl jq net-tools -y && apt-mark hold haproxy && \
    rm -f /etc/apt/preferences.d/haproxy-upstream-pin && \
    deb_ver="$(dpkg-query -W -f='${Version}' haproxy)" && \
    case "${deb_ver}" in "${HAPROXY_UPSTREAM}"-*) ;; *) echo "FATAL: installed haproxy ${deb_ver} is not upstream ${HAPROXY_UPSTREAM}" >&2; exit 1;; esac && \
    haproxy -v | head -n1 | grep -F "version ${HAPROXY_UPSTREAM}-" && \
    echo "haproxy pin OK: upstream ${HAPROXY_UPSTREAM}, Debian package ${deb_ver}" && \
    /usr/local/sbin/pkg-cache-repos.sh restore && \
    apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /haproxy
COPY ./templates /haproxy/templates
COPY requirements.txt /haproxy/
COPY haproxy_manager.py /haproxy/
COPY haproxy_gunicorn_worker.py /haproxy/
# Read by GET /api/capabilities (WHP gates whole-site re-bundling on it).
COPY VERSION /haproxy/VERSION
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
#   * it validates against the EXACT haproxy binary in this image. The
#     installed haproxy can move between builds (Debian revisions) - this
#     turns "the new haproxy rejects our config" from a silent production
#     risk into a build failure.
#
# The unit suites run here too. They had never run anywhere automated either,
# and they cost a few seconds.
RUN python3 /haproxy/scripts/test-wpadmin-gate.py \
 && python3 /haproxy/scripts/test-trusted-proxy-gate.py \
 && python3 /haproxy/scripts/test-xmlrpc-rate-limit.py \
 && python3 /haproxy/scripts/test-default-splash.py \
 && python3 /haproxy/scripts/test-access-log-receiver.py \
 && python3 /haproxy/scripts/test-config-rollback.py \
 && python3 /haproxy/scripts/test-cert-write-safety.py \
 && python3 /haproxy/scripts/test-cert-scripts.py \
 && python3 /haproxy/scripts/test-waf-body-inspection.py \
 && python3 /haproxy/scripts/test-gunicorn-socket-timeouts.py \
 && python3 /haproxy/scripts/validate-rendered-config.py
# Create log directories
RUN mkdir -p /var/log/haproxy && touch /var/log/haproxy-manager.log /var/log/haproxy-manager-errors.log
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
# Health check: management API (:8000, short timeout) AND HAProxy (:80).
# See scripts/healthcheck.sh. NOTE: WHP's lib-edge-container.sh passes its own
# --health-cmd, which REPLACES this one on deployed hosts; it must be pointed
# at /haproxy/scripts/healthcheck.sh for the fleet to get the :8000 probe.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /haproxy/scripts/healthcheck.sh
CMD ["/haproxy/scripts/start-up.sh"]