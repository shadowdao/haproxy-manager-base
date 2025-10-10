FROM python:3.12-slim
RUN apt update -y && apt dist-upgrade -y && apt install socat haproxy cron certbot curl jq net-tools -y && apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /haproxy
COPY ./templates /haproxy/templates
COPY requirements.txt /haproxy/
COPY haproxy_manager.py /haproxy/
COPY scripts /haproxy/scripts
RUN chmod +x /haproxy/scripts/*
RUN pip install -r requirements.txt
RUN echo "0 */12 * * * root test -x /usr/bin/certbot && /usr/bin/certbot -q renew && echo \"reload\" | socat stdio /tmp/haproxy-cli" > /var/spool/cron/crontabs/root
# Create log directories
RUN mkdir -p /var/log && touch /var/log/haproxy-manager.log /var/log/haproxy-manager-errors.log
RUN chmod 755 /var/log/haproxy-manager.log /var/log/haproxy-manager-errors.log
EXPOSE 80 443 8000
# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
CMD ["/haproxy/scripts/start-up.sh"]