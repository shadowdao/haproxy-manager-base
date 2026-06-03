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
LABEL org.opencontainers.image.title="haproxy-manager-base" \
      org.opencontainers.image.description="HAProxy management API with Let's Encrypt automation, Coraza WAF integration, and template-driven config" \
      org.opencontainers.image.source="https://github.com/shadowdao/haproxy-manager-base" \
      org.opencontainers.image.licenses="MIT"

RUN apt update -y && apt dist-upgrade -y && apt install socat haproxy cron certbot curl jq net-tools -y && apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /haproxy
COPY ./templates /haproxy/templates
COPY requirements.txt /haproxy/
COPY haproxy_manager.py /haproxy/
COPY scripts /haproxy/scripts
COPY trusted_ips.list /etc/haproxy/trusted_ips.list
COPY trusted_ips.map /etc/haproxy/trusted_ips.map
# /etc/haproxy is a named volume in deployed containers, so baked-in files
# under that path get shadowed by the volume on existing deployments.
# Place errorfiles outside the volumed path; the HAProxy config references
# them by absolute path.
COPY errors /haproxy/errors
RUN chmod +x /haproxy/scripts/*
RUN pip install -r requirements.txt
# Create log directories
RUN mkdir -p /var/log && touch /var/log/haproxy-manager.log /var/log/haproxy-manager-errors.log
RUN chmod 755 /var/log/haproxy-manager.log /var/log/haproxy-manager-errors.log
# Set up cron for certificate renewal with proper permissions and environment
RUN mkdir -p /var/spool/cron/crontabs && \
    echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' > /var/spool/cron/crontabs/root && \
    echo '0 */12 * * * /haproxy/scripts/renew-certificates.sh >> /var/log/haproxy-manager.log 2>&1' >> /var/spool/cron/crontabs/root && \
    chmod 600 /var/spool/cron/crontabs/root && \
    chown root:crontab /var/spool/cron/crontabs/root
EXPOSE 80 443 8000
# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -sf --max-time 5 http://localhost:8000/health && curl -s --max-time 5 -o /dev/null http://localhost/ || exit 1
CMD ["/haproxy/scripts/start-up.sh"]