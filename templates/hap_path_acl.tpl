    
    #Path Method {{ path }}
    acl {{ path }}-acl path_beg {{ path }}
    use_backend {{ name }}-backend if {{ path }}-acl
