FROM python:3.12-slim
RUN apt update -y && apt dist-upgrade -y && apt install socat haproxy cron certbot curl jq net-tools -y && apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /haproxy
COPY ./templates /haproxy/templates
COPY requirements.txt /haproxy/
COPY haproxy_manager.py /haproxy/
COPY scripts /haproxy/scripts
COPY trusted_ips.list /etc/haproxy/trusted_ips.list
COPY trusted_ips.map /etc/haproxy/trusted_ips.map
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