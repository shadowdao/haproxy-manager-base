#!/usr/bin/env python3
"""Idempotent haproxy liveness check — driven by the in-container supervisor loop.

Why this exists
---------------
haproxy runs as a *background child of PID 1* (gunicorn) — it is started once at
container init (scripts/init.py -> do_initial_setup -> start_haproxy) and then
left running. Nothing supervises it after that. If the haproxy master process
dies mid-life (SIGABRT -> exit 134, segfault, or an OOM of the haproxy master),
the container stays "up" because gunicorn is still PID 1, so Docker's
`--restart` policy never fires. haproxy then stays down until the *external*
host watchdog (haproxy-watchdog.sh) notices port 80 is dead for ~3 minutes and
does a full `docker restart` — which drops every in-flight connection.

This script closes that gap: called on a short interval by the supervisor loop
in start-up.sh, it re-launches haproxy *in place* within one interval.

Safety
------
start_haproxy() is guarded by `is_process_running('haproxy')` (psutil-based, so
it works in this container which has no `ps`), so calling this while haproxy is
healthy is a cheap no-op. It only ever acts when haproxy is genuinely gone.
"""
import sys

sys.path.insert(0, '/haproxy')
import haproxy_manager  # noqa: E402  (sys.path manipulation must come first)


def main():
    if haproxy_manager.is_process_running('haproxy'):
        return 0

    haproxy_manager.logger.warning(
        "[haproxy-supervisor] haproxy process not found — attempting in-place restart"
    )
    # start_haproxy() validates the config (and regenerates it if invalid)
    # before launching, and swallows its own errors, so it will not raise here.
    haproxy_manager.start_haproxy()

    if haproxy_manager.is_process_running('haproxy'):
        haproxy_manager.logger.info("[haproxy-supervisor] haproxy restarted in place")
        return 0

    haproxy_manager.logger.error(
        "[haproxy-supervisor] haproxy restart FAILED — still not running after start_haproxy()"
    )
    return 1


if __name__ == '__main__':
    sys.exit(main())
