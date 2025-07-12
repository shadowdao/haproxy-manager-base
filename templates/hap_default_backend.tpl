# Default backend for unmatched domains
backend default-backend
    mode http
    option http-server-close
    http-request set-header X-Forwarded-Proto https if { ssl_fc }
    http-request set-header X-Forwarded-Port %[dst_port]
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Real-IP %[src]
    
    # Serve the default page HTML response using a local server
    server default-page 127.0.0.1:8080 