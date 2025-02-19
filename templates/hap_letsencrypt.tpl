    #Let's Encrypt SSL
    acl letsencrypt-acl path_beg /.well-known/acme-challenge/
    use_backend letsencrypt-backend if letsencrypt-acl


    #Pass SSL Requests to Lets Encrypt
    backend letsencrypt-backend
    server letsencrypt 127.0.0.1:8688

