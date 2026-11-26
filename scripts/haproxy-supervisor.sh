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
# was affordable at 15 s but not at 2 s. 2026-11 evidence: every watchdog abort
# took the whole edge down for 15-52 s, most of it detection latency + start.
#
# FAST PATH (2026-11-26, whp02 abort: python took 16 s just to LOG "process not
# found" on an I/O-starved host). When haproxy is gone the loop relaunches it
# DIRECTLY FROM BASH against the config on disk (the one the dead master loaded
# successfully minutes ago): `haproxy -c -f cfg` first, then the same command,
# flags, user and detach trick as haproxy_manager.spawn_haproxy_master()
# (`haproxy -W -db -S /tmp/haproxy-cli,level,admin -f cfg`, stderr appended to the
# stderr log, re-parented to PID 1 so gunicorn reaps it). Only if that fails
# (config missing/invalid, haproxy exits or never logs "Loading success.") does
# it fall back to `python ensure_haproxy.py` (regenerates + validates + starts).
# Never starts a second master: pidof is re-checked after validation, right
# before the launch. Every step is logged with a UTC millisecond timestamp.
#
# While a recovery is in progress the loop keeps HAPROXY_SUPERVISOR_MARKER
# (default /tmp/haproxy-restarting) containing "<epoch-seconds> <supervisor pid>"
# so the host watchdog (WHP panel/internal/watchdog/haproxy.go) can see the
# in-place restart is underway and not `docker restart` on top of it. It is
# removed when the recovery finishes (success or failure).
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

INTERVAL="$(_posint "${HAPROXY_SUPERVISOR_INTERVAL:-}" 1)"
MAX_BACKOFF="$(_posint "${HAPROXY_SUPERVISOR_MAX_BACKOFF:-}" 30)"
QUICK_DEATH="$(_posint "${HAPROXY_SUPERVISOR_QUICK_DEATH:-}" 10)"
STABLE="$(_posint "${HAPROXY_SUPERVISOR_STABLE:-}" 60)"
START_WAIT="$(_posint "${HAPROXY_START_WAIT:-}" 10)"
CFG="${HAPROXY_SUPERVISOR_CFG:-/etc/haproxy/haproxy.cfg}"
BIN="${HAPROXY_SUPERVISOR_BIN:-haproxy}"
MASTER_SOCK="${HAPROXY_SUPERVISOR_SOCKET:-/tmp/haproxy-cli}"
MARKER="${HAPROXY_SUPERVISOR_MARKER:-/tmp/haproxy-restarting}"
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

# --- logging / timing helpers -------------------------------------------------
_now_ms() {
    if [ -n "${EPOCHREALTIME:-}" ]; then
        local t="${EPOCHREALTIME/./}"      # microseconds
        echo $(( t / 1000 ))
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}
_log() { # _log LEVEL MESSAGE...   (stderr = container stderr, like the old echo)
    local lvl="$1"; shift
    printf '%s [haproxy-supervisor] %s: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" "${lvl}" "$*" >&2
}

_stderr_log() { # same fallback as haproxy_manager._stderr_log_path()
    local p="${HAPROXY_STDERR_LOG:-/var/log/haproxy/haproxy-stderr.log}"
    if mkdir -p "$(dirname "${p}")" 2>/dev/null && (umask 027; : >>"${p}") 2>/dev/null; then
        echo "${p}"
    else
        echo /tmp/haproxy-stderr.log
    fi
}

_marker_set()   { printf '%s %s\n' "$(date +%s)" "$$" >"${MARKER}" 2>/dev/null || true; }
_marker_clear() { rm -f "${MARKER}" 2>/dev/null || true; }
trap _marker_clear EXIT

# Direct bash relaunch. Return 0 = haproxy is up (started here or already
# running), 1 = caller must fall back to ensure_haproxy.py.
fast_relaunch() {
    local t0="$1" t cfg_ms log_path offset text i
    if [ ! -r "${CFG}" ]; then
        _log WARN "fast path skipped: config ${CFG} missing/unreadable"
        return 1
    fi
    if ! command -v "${BIN}" >/dev/null 2>&1; then
        _log WARN "fast path skipped: ${BIN} not found on PATH"
        return 1
    fi
    if ! timeout 20 "${BIN}" -c -q -f "${CFG}" >/dev/null 2>&1; then
        _log WARN "fast path skipped: '${BIN} -c -f ${CFG}' rejected the on-disk config"
        return 1
    fi
    t="$(_now_ms)"; cfg_ms=$(( t - t0 ))
    _log INFO "on-disk config valid (+${cfg_ms} ms)"
    # Idempotency: never a second master. Re-check right before launching (the
    # validation above took time; the API's start_haproxy may have won).
    if pidof -q haproxy; then
        _log INFO "haproxy is already running; nothing to start"
        return 0
    fi
    log_path="$(_stderr_log)"
    offset="$(stat -c %s "${log_path}" 2>/dev/null || echo 0)"
    # Same detach as spawn_haproxy_master(): the double fork re-parents haproxy to
    # PID 1 (gunicorn reaps it; a zombie child of this loop would keep pidof true).
    ( chmod 0640 "${log_path}" 2>/dev/null
      "${BIN}" -W -db -S "${MASTER_SOCK},level,admin" -f "${CFG}" \
          </dev/null >>"${log_path}" 2>&1 & )
    t="$(_now_ms)"
    _log INFO "launched '${BIN} -W -db -S ${MASTER_SOCK},level,admin -f ${CFG}' (+$(( t - t0 )) ms)"
    # Wait for "Loading success." (deadline HAPROXY_START_WAIT; alive + no [ALERT] at
    # the deadline also counts), exactly like spawn_haproxy_master().
    for i in $(seq 1 $(( START_WAIT * 10 ))); do
        text="$(tail -c +$(( offset + 1 )) "${log_path}" 2>/dev/null || true)"
        case "${text}" in
            *"Loading success."*)
                t="$(_now_ms)"
                _log INFO "haproxy up in place: config loaded (+$(( t - t0 )) ms since detection)"
                return 0 ;;
        esac
        # exited (or never came up) after the 1 s grace: stop waiting
        if [ "${i}" -gt 10 ] && ! pidof -q haproxy; then break; fi
        sleep 0.1
    done
    if pidof -q haproxy; then
        case "${text}" in *"[ALERT]"*) ;; *)
            _log INFO "haproxy up in place: alive, slow to log (+$(( $(_now_ms) - t0 )) ms since detection)"
            return 0 ;;
        esac
    fi
    _log ERROR "direct relaunch failed: $(printf '%s' "${text}" | tail -n 3 | tr '\n' '|')"
    return 1
}

# Recover a missing haproxy: fast path, then the python fallback.
recover() {
    local t0
    t0="$(_now_ms)"
    _marker_set
    _log WARN "haproxy process not found — attempting in-place restart (direct relaunch first)"
    if fast_relaunch "${t0}"; then
        _marker_clear
        return 0
    fi
    _log WARN "falling back to ensure_haproxy.py (+$(( $(_now_ms) - t0 )) ms)"
    if python /haproxy/scripts/ensure_haproxy.py 2>&1; then
        _log INFO "ensure_haproxy.py succeeded (+$(( $(_now_ms) - t0 )) ms since detection)"
        _marker_clear
        return 0
    fi
    _log ERROR "ensure_haproxy.py failed (+$(( $(_now_ms) - t0 )) ms)"
    _marker_clear
    return 1
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
            _log WARN "haproxy died ${up}s after start (quick death #${quick}); waiting ${wait_s}s before restart"
            sleep "${wait_s}"
            pidof -q haproxy && continue
        elif [ "${up}" -ge "${STABLE}" ]; then
            quick=0
        fi
    fi
    if recover; then
        delay="${INTERVAL}"
        last_start="${SECONDS}"
    else
        delay=$(( delay * 2 ))
        [ "${delay}" -gt "${MAX_BACKOFF}" ] && delay="${MAX_BACKOFF}"
    fi
done
