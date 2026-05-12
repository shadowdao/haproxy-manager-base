#!/usr/bin/env python3
"""Container init: DB schema, certbot account, config generation, HAProxy start.

Runs once per container start, BEFORE gunicorn workers spawn. Keeping init out
of the WSGI app's module-load path avoids fork-time races (multiple workers
attempting to start_haproxy() simultaneously, certbot lock contention, etc.).
"""
import sys

sys.path.insert(0, '/haproxy')
import haproxy_manager  # noqa: E402  (sys.path manipulation must come first)

haproxy_manager.do_initial_setup()
