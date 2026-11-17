#!/usr/bin/env python3
"""Bound the management-API (:8000) gunicorn access log file.

Why
---
Gunicorn's access log used to go to stdout (`--access-logfile -`), i.e. every
:8080 default-page / blocked-IP / suspended-site hit and every :8000 API call
became a `docker logs` line. With the journald docker log driver that is one
journal entry per request (journald's default rate limit, 10000 msgs / 30 s per
sending service, can then SUPPRESS the crash-dump lines the relay emits) and it
floods Graylog. Now:
  * :8080 (default page) has NO access log at all;
  * :8000 (API) writes its access log to API_ACCESS_LOG (default
    /var/log/haproxy/api-access.log, in the haproxy-logs volume), NOT stdout;
  * gunicorn ERROR logging (tracebacks, worker timeouts) stays on stderr.
This process keeps that file bounded: copy-truncate rotation at
HAPROXY_API_ACCESS_LOG_MAX_BYTES (default 20 MiB), HAPROXY_API_ACCESS_LOG_BACKUPS
generations (default 3), rotated copies mode 0640 (same policy as
haproxy-stderr.log). Truncating in place is safe because gunicorn opens the
file in append mode. Several gunicorn processes share the file, so renaming it
is not an option.

Bound: size is checked every HAPROXY_API_ACCESS_LOG_POLL seconds (default 30),
so the live file can exceed the limit only by what the API writes in one
interval (a few hundred bytes per call).
"""
import os
import shutil
import sys
import time


def _env_num(name, default, cast=int):
    try:
        v = cast(os.environ.get(name, default))
        return v if v > 0 else default
    except (TypeError, ValueError):
        return default


def rotate_if_needed(path, max_bytes, backups):
    """Copy-truncate rotate. Returns True if it rotated."""
    try:
        if os.path.getsize(path) <= max_bytes:
            return False
        for i in range(backups, 1, -1):
            src = '%s.%d' % (path, i - 1)
            if os.path.exists(src):
                os.replace(src, '%s.%d' % (path, i))
        shutil.copyfile(path, path + '.1')
        os.chmod(path + '.1', 0o640)
        with open(path, 'r+b') as fh:
            fh.truncate(0)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        sys.stderr.write('gunicorn-access-rotate: rotate failed: %s\n' % exc)
        return False


def main():
    path = os.environ.get('HAPROXY_MGR_API_ACCESS_LOG', '/var/log/haproxy/api-access.log')
    max_bytes = _env_num('HAPROXY_API_ACCESS_LOG_MAX_BYTES', 20 * 1024 * 1024)
    backups = _env_num('HAPROXY_API_ACCESS_LOG_BACKUPS', 3)
    poll = _env_num('HAPROXY_API_ACCESS_LOG_POLL', 30.0, float)
    while True:
        try:
            rotate_if_needed(path, max_bytes, backups)
        except Exception as exc:  # never die; the supervisor loop restarts us anyway
            sys.stderr.write('gunicorn-access-rotate: %r\n' % exc)
        time.sleep(poll)


if __name__ == '__main__':
    main()
