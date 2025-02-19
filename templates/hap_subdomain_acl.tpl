    
    #Subdomain method {{ domain }}
    acl {{ domain }}-acl hdr(host) -i {{ domain }}
    use_backend {{ name }}-backend if {{ domain }}-acl
