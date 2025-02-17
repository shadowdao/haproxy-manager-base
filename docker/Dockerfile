# Multi-stage build
FROM node:14-alpine as frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.8-slim

# Install HAProxy and Certbot
RUN apt-get update && \
    apt-get install -y \
    haproxy \
    certbot \
    python3-certbot \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /etc/haproxy/certs \
    && mkdir -p /var/lib/haproxy \
    && mkdir -p /run/haproxy

# Set up Python environment
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Copy frontend build
COPY --from=frontend-builder /app/frontend/build ./frontend/build

# Copy HAProxy configuration
COPY backend/templates/haproxy.cfg.j2 /etc/haproxy/haproxy.cfg.template

# Install curl for healthcheck
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create data directory
RUN mkdir -p /app/backend/data

# Set permissions
RUN chown -R nobody:nogroup /app/backend/data

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Create run script
RUN echo '#!/bin/sh\n\
python backend/app.py &\n\
haproxy -f /etc/haproxy/haproxy.cfg -db\n' > /start.sh && \
chmod +x /start.sh

EXPOSE 80 443 5000

CMD ["/start.sh"]