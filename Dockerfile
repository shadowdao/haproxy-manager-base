FROM python:3.12-slim
RUN apt update -y && apt dist-upgrade -y && apt install socat haproxy -y && apt clean && rm -rf /var/lib/apt/lists/*
WORKDIR /haproxy
COPY ./templates /haproxy/templates
COPY requirements.txt /haproxy/
COPY haproxy_manager.py /haproxy/
RUN pip install -r requirements.txt
EXPOSE 80 443 8000
#CMD ["python", "app.py"]