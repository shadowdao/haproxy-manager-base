#!/usr/bin/env bash

# Exit on error
set -eo pipefail
cron &
python /haproxy/haproxy_manager.py
