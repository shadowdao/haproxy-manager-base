
    #Wildcard method {{ domain }}
    acl {{ name }}-acl hdr_end(host) -i .{{ base_domain }}
    use_backend {{ name }}-backend if {{ name }}-acl
