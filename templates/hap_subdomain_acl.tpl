
    #Subdomain method {{ domain }}
    acl {{ name }}-acl hdr(host) -i {{ domain }}

    # Detect Server-Sent Events (SSE) connections for {{ domain }}
    # SSE uses Accept: text/event-stream or ?action=stream query parameter
    acl {{ name }}-is-sse hdr(accept) -i -m sub text/event-stream
    acl {{ name }}-is-sse-url urlp(action) -i -m str stream

    # Route SSE traffic to SSE-optimized backend, regular traffic to standard backend
    use_backend {{ name }}-sse-backend if {{ name }}-acl {{ name }}-is-sse
    use_backend {{ name }}-sse-backend if {{ name }}-acl {{ name }}-is-sse-url
    use_backend {{ name }}-backend if {{ name }}-acl
