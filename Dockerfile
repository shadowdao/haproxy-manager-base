FROM python:3.12-slim
RUN apt update -y && apt dist-upgrade -y && apt install socat haproxy cron certbot -y && apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /haproxy
COPY ./templates /haproxy/templates
COPY requirements.txt /haproxy/
COPY haproxy_manager.py /haproxy/
COPY scripts /haproxy/scripts
RUN chmod +x /haproxy/scripts/*
RUN pip install -r requirements.txt
RUN echo "0 */12 * * * root test -x /usr/bin/certbot -a \! -d /run/systemd/system && perl -e 'sleep int(rand(43200))' && certbot -q renew --no-random-sleep-on-renew" > /var/spool/cron/crontabs/root
EXPOSE 80 443 8000
# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1
CMD ["/haproxy/scripts/start-up.sh"]