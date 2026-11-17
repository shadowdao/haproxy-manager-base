#!/usr/bin/env bash
# In-container haproxy supervisor (started in the background by start-up.sh).
#
# haproxy runs as a background child of PID 1 (gunicorn) with NOTHING watching
# it after init. If the haproxy master dies mid-life (e.g. SIGABRT -> exit 134,
# segfault), the container stays "up" (gunicorn is PID 1), Docker's --restart
# policy never fires, and haproxy is down until the external host watchdog
# full-restarts the whole container minutes later (dropping every connection).
# This loop revives haproxy in place within one interval.
#
# The liveness probe is `pidof` (a few ms), NOT python: ensure_haproxy.py imports
# the 4000-line manager (Flask, Jinja, ...) which costs ~0.5 s of CPU per run and
# was affordable at 15 s but not at 2 s. python only runs when haproxy is gone.
# 2026-11 evidence: every watchdog abort took the whole edge down for 15-52 s,
# most of it detection latency + start; the default is now 2 s (was 15).
#
# Two backoffs:
#   * a restart attempt that FAILS (config HAProxy rejects): the loop doubles its
#     delay up to HAPROXY_SUPERVISOR_MAX_BACKOFF (default 30 s) instead of
#     re-rendering/re-validating the same broken config every 2 s;
#   * haproxy that starts fine but DIES again within HAPROXY_SUPERVISOR_QUICK_DEATH
#     seconds (default 10) of that start (a crash loop): extra wait before the
#     next restart, stepping through HAPROXY_SUPERVISOR_BACKOFF_STEPS (default
#     "2 5 10 30", each capped at MAX_BACKOFF). A run that survives
#     HAPROXY_SUPERVISOR_STABLE seconds (default 60) resets it. The first death
#     after a long run is still revived within one interval.
#
# All knobs are validated as positive INTEGERS (seconds); anything else (e.g. 0.5,
# "abc") falls back to the default instead of killing this subshell under set -e.
set -eo pipefail

_posint() { # _posint VALUE DEFAULT
    case "$1" in
        ''|*[!0-9]*) echo "$2" ;;
        *) if [ "$1" -ge 1 ]; then echo "$1"; else echo "$2"; fi ;;
    esac
}

INTERVAL="$(_posint "${HAPROXY_SUPERVISOR_INTERVAL:-}" 2)"
MAX_BACKOFF="$(_posint "${HAPROXY_SUPERVISOR_MAX_BACKOFF:-}" 30)"
QUICK_DEATH="$(_posint "${HAPROXY_SUPERVISOR_QUICK_DEATH:-}" 10)"
STABLE="$(_posint "${HAPROXY_SUPERVISOR_STABLE:-}" 60)"
STEPS=""
for s in ${HAPROXY_SUPERVISOR_BACKOFF_STEPS:-2 5 10 30}; do
    v="$(_posint "$s" 0)"
    [ "$v" -ge 1 ] && STEPS="${STEPS} ${v}"
done
[ -n "${STEPS}" ] || STEPS=" 2 5 10 30"

# step N (1-based, past the end = last), capped at MAX_BACKOFF
_step() {
    local n="$1" i=0 v=0
    for s in ${STEPS}; do
        i=$((i + 1)); v="$s"
        [ "${i}" -ge "${n}" ] && break
    done
    [ "${v}" -gt "${MAX_BACKOFF}" ] && v="${MAX_BACKOFF}"
    echo "${v}"
}

delay="${INTERVAL}"
last_start=-1    # SECONDS at our last successful (re)start; -1 = none yet
quick=0          # consecutive deaths within QUICK_DEATH of a start
while true; do
    sleep "${delay}"
    if pidof -q haproxy; then
        delay="${INTERVAL}"
        if [ "${last_start}" -ge 0 ] && [ $((SECONDS - last_start)) -ge "${STABLE}" ]; then
            quick=0; last_start=-1
        fi
        continue
    fi
    if [ "${last_start}" -ge 0 ]; then
        up=$((SECONDS - last_start))
        if [ "${up}" -lt "${QUICK_DEATH}" ]; then
            quick=$((quick + 1))
            wait_s="$(_step "${quick}")"
            echo "haproxy-supervisor: haproxy died ${up}s after start (quick death #${quick}); waiting ${wait_s}s before restart" >&2
            sleep "${wait_s}"
            pidof -q haproxy && continue
        elif [ "${up}" -ge "${STABLE}" ]; then
            quick=0
        fi
    fi
    if python /haproxy/scripts/ensure_haproxy.py 2>&1; then
        delay="${INTERVAL}"
        last_start="${SECONDS}"
    else
        delay=$(( delay * 2 ))
        [ "${delay}" -gt "${MAX_BACKOFF}" ] && delay="${MAX_BACKOFF}"
    fi
done
