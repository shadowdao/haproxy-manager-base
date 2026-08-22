#!/usr/bin/env bash
#
# show-edge-ip-rates.sh — real, current per-IP rate counters from the HAProxy
# `web` stick table.
#
# WHAT THIS CAN TELL YOU
#   The `web` stick table (templates/hap_listener.tpl) stores exactly four
#   counters per client IP:
#       conn_cur, conn_rate(10s), http_req_rate(10s), http_err_rate(30s)
#   Those are INSTANTANEOUS values — the current concurrency and the current
#   sliding-window rates. This script prints them, and nothing else.
#
# WHAT THIS CANNOT TELL YOU
#   * Who has been tarpitted, denied, or rate-limited. The stick table stores
#     NO history and NO counter of past enforcement actions. It has no gpc0 /
#     gpc1 / gpc(N) / gpc_rate / glitch_rate columns at all — any tool that
#     claims to read them from this table is fabricating numbers.
#   * Anything about an IP that has gone quiet: entries expire after 10m.
#
#   Real enforcement events live in the HAProxy ACCESS LOG, which is on the
#   DOCKER HOST at /var/log/haproxy.log (it does NOT exist inside this
#   container). The log-format carries the HAProxy termination state plus
#   cip= (real client IP), host=, ua= and id= (the request UUID shown on the
#   block page, which correlates with customer support tickets).
#
#   Ready to run ON THE HOST:
#       # last 20 tarpitted (PT--) or denied (PR--) requests
#       grep -aE ' (PT|PR)--' /var/log/haproxy.log | tail -20
#       # everything HAProxy answered 429/403 to, newest last
#       grep -aE ' (429|403) ' /var/log/haproxy.log | tail -20
#       # everything for one client IP
#       grep -a 'cip=203.0.113.7' /var/log/haproxy.log | tail -50
#       # look up one request reference from a support ticket
#       grep -a 'id=<uuid-from-the-block-page>' /var/log/haproxy.log
#
# USAGE
#   show-edge-ip-rates.sh [-a|--all]
#     -a, --all   also show rows whose counters are all zero (off by default:
#                 a table with hundreds of idle entries is pure noise)
#
# ENVIRONMENT
#   SHOW_ALL=1               same as --all
#   HAPROXY_SOCKET=<path>    override the CLI socket (default /tmp/haproxy-cli)
#   HAPROXY_TABLE_DUMP=<file>
#                            parse a previously captured `show table web` dump
#                            from a file instead of talking to the socket.
#                            Supported seam for offline analysis of a captured
#                            support bundle, and for testing this parser.
#
# NOTE ON THE SOCKET
#   /tmp/haproxy-cli is HAProxy's MASTER CLI socket, so worker commands need an
#   `@1` prefix. Without it HAProxy answers "Unknown command: 'show' ..." AND
#   socat still exits 0 — so exit status is worthless here and this script
#   inspects the RESPONSE BODY instead.

set -euo pipefail

SOCKET="${HAPROXY_SOCKET:-/tmp/haproxy-cli}"
TABLE="web"

# Fields this script expects the `web` stick table to store. Keep on ONE line
# in this exact NAME=(a b c d) shape — the contract test greps for it, and the
# parser below is driven entirely by it.
EXPECTED_FIELDS=(conn_cur conn_rate http_req_rate http_err_rate)

# Which of EXPECTED_FIELDS to sort on (descending). Falls back to the first
# field if this name is not in the list.
SORT_FIELD="http_req_rate"

SHOW_ALL="${SHOW_ALL:-0}"
while [ $# -gt 0 ]; do
    case "$1" in
        -a|--all) SHOW_ALL=1 ;;
        -h|--help) sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; echo "Usage: $0 [-a|--all]" >&2; exit 2 ;;
    esac
    shift
done

die() { echo "ERROR: $*" >&2; exit 1; }

# First non-blank line of a blob.
#
# Deliberately NOT `printf ... | sed -n '/./{p;q;}'`. sed quits after the first
# match and closes the pipe; on a real 550-entry table dump printf is still
# writing and takes SIGPIPE, so under `set -o pipefail` the whole command
# substitution returns 141 and `set -e` kills the script -- silently, with no
# output at all. That is the same class of failure this script exists to stop
# hiding, so it does not get to happen here. A plain read loop has no pipeline
# and no early close.
first_nonblank() {
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            *[![:space:]]*) printf '%s\n' "$line"; return 0 ;;
        esac
    done <<EOF
$1
EOF
    return 0
}

# Return 0 if the CLI response body is a rejection rather than table data.
# Checked on the body because socat's exit status is 0 either way.
body_is_rejected() {
    local first
    first=$(first_nonblank "$1")
    case "$first" in
        "Unknown command"*|"No such table"*|"Permission denied"*) return 0 ;;
        *) return 1 ;;
    esac
}

send_cmd() {
    printf '%s\n' "$1" | socat stdio "$SOCKET" 2>/dev/null
}

# ---------------------------------------------------------------- fetch data
BODY=""
SOURCE=""
if [ -n "${HAPROXY_TABLE_DUMP:-}" ]; then
    [ -r "$HAPROXY_TABLE_DUMP" ] || die "HAPROXY_TABLE_DUMP is set but '$HAPROXY_TABLE_DUMP' is not readable."
    BODY=$(cat "$HAPROXY_TABLE_DUMP")
    SOURCE="file $HAPROXY_TABLE_DUMP"
else
    [ -S "$SOCKET" ] || die "HAProxy CLI socket not found at $SOCKET (is HAProxy running, and are you inside the haproxy-manager container?)"
    command -v socat >/dev/null 2>&1 || die "socat is not installed; cannot talk to $SOCKET"

    # Master socket form first, then the plain stats-socket form.
    BODY=$(send_cmd "@1 show table $TABLE" || true)
    SOURCE="socket $SOCKET (@1 show table $TABLE)"
    if [ -z "${BODY//[[:space:]]/}" ] || body_is_rejected "$BODY"; then
        FALLBACK=$(send_cmd "show table $TABLE" || true)
        if [ -n "${FALLBACK//[[:space:]]/}" ] && ! body_is_rejected "$FALLBACK"; then
            BODY="$FALLBACK"
            SOURCE="socket $SOCKET (show table $TABLE)"
        else
            echo "ERROR: HAProxy rejected BOTH '@1 show table $TABLE' and 'show table $TABLE'." >&2
            echo "  @1 response : $(first_nonblank "$BODY")" >&2
            echo "  bare response: $(first_nonblank "$FALLBACK")" >&2
            echo "  Check the socket is HAProxy's CLI and that the table '$TABLE' exists" >&2
            echo "  (a config reload without the frontend would drop it)." >&2
            exit 1
        fi
    fi
fi

# ------------------------------------------------------------- header checks
HEADER=$(first_nonblank "$BODY")
case "$HEADER" in
    "# table: $TABLE,"*) : ;;
    *)
        echo "ERROR: unexpected first line from '$SOURCE'." >&2
        echo "  expected it to start with: # table: $TABLE," >&2
        echo "  got                      : $HEADER" >&2
        exit 1
        ;;
esac

TBL_SIZE=$(printf '%s\n' "$HEADER" | sed -n 's/.*size:\([0-9]*\).*/\1/p')
TBL_USED=$(printf '%s\n' "$HEADER" | sed -n 's/.*used:\([0-9]*\).*/\1/p')
[ -n "$TBL_SIZE" ] || TBL_SIZE="?"
[ -n "$TBL_USED" ] || TBL_USED="?"

# ------------------------------------------------------------------- parsing
# awk emits:
#   W \t <field>:<window-seconds-or-dash> ...       (one line, from first row)
#   R \t <sortkey> \t <ip> \t <value per EXPECTED_FIELDS in order>
# and exits 1 after reporting any row missing an expected field.
PARSED=""
if ! PARSED=$(printf '%s\n' "$BODY" | awk -v fieldlist="${EXPECTED_FIELDS[*]}" -v sortfield="$SORT_FIELD" '
BEGIN {
    nf = split(fieldlist, F, " ")
    sortidx = 1
    for (i = 1; i <= nf; i++) if (F[i] == sortfield) sortidx = i
    wprinted = 0
}
/^#/ { next }
!/key=/ { next }
{
    split("", val, " "); split("", win, " ")
    for (i = 1; i <= NF; i++) {
        tok = $i
        p = index(tok, "=")
        if (p == 0) continue
        lhs = substr(tok, 1, p - 1)
        rhs = substr(tok, p + 1)
        b = index(lhs, "(")
        if (b > 0) {
            nm = substr(lhs, 1, b - 1)
            win[nm] = substr(lhs, b + 1, length(lhs) - b - 1)
        } else {
            nm = lhs
            win[nm] = ""
        }
        val[nm] = rhs
    }

    missing = ""
    for (i = 1; i <= nf; i++) if (!(F[i] in val)) missing = missing (missing == "" ? "" : ", ") F[i]
    if (missing != "") {
        printf "ERROR: stick table row is missing expected field(s): %s\n", missing > "/dev/stderr"
        printf "  offending row: %s\n", $0 > "/dev/stderr"
        printf "  this script expects the web table to store: %s\n", fieldlist > "/dev/stderr"
        print  "  Those expectations and the templates/hap_listener.tpl `store` clause have DRIFTED." > "/dev/stderr"
        print  "  Fix one or the other; refusing to print 0 for a counter HAProxy never reported." > "/dev/stderr"
        exit 1
    }
    if (!("key" in val)) {
        printf "ERROR: stick table row has no key= field: %s\n", $0 > "/dev/stderr"
        exit 1
    }

    if (!wprinted) {
        line = "W"
        for (i = 1; i <= nf; i++) {
            w = win[F[i]]
            if (w ~ /^[0-9]+$/) w = sprintf("%g", w / 1000); else w = "-"
            line = line "\t" F[i] ":" w
        }
        print line
        wprinted = 1
    }

    nonzero = 0
    row = ""
    for (i = 1; i <= nf; i++) {
        v = val[F[i]]
        if (v + 0 != 0) nonzero = 1
        row = row "\t" v
    }
    printf "R\t%s\t%s\t%d%s\n", val[F[sortidx]] + 0, val["key"], nonzero, row
}
'); then
    exit 1
fi

# ------------------------------------------------------------------ printing
WINSPEC=$(printf '%s\n' "$PARSED" | sed -n 's/^W\t//p' || true)

echo "==================================================================="
echo "  HAProxy edge IP rates — table '$TABLE' (current values only)"
echo "==================================================================="
echo "Source     : $SOURCE"
echo "Tracked    : ${TBL_USED} of ${TBL_SIZE} slots in use"
if [ "$SHOW_ALL" = "1" ]; then
    echo "Filter     : showing ALL tracked IPs"
else
    echo "Filter     : showing only IPs with a non-zero counter (use --all for every row)"
fi
echo

# Column headers, with each counter's window rendered in SECONDS (HAProxy
# reports the window in milliseconds, e.g. conn_rate(10000) = 10s).
HDR=$(printf "%-18s" "IP Address")
i=0
for f in "${EXPECTED_FIELDS[@]}"; do
    w=$(printf '%s\n' "$WINSPEC" | tr '\t' '\n' | sed -n "s/^${f}://p")
    if [ -n "$w" ] && [ "$w" != "-" ]; then
        label="${f}/${w}s"
    else
        label="$f"
    fi
    HDR="$HDR $(printf '%18s' "$label")"
    i=$((i + 1))
done
echo "$HDR"
printf '%s\n' "$HDR" | sed 's/./-/g'

ROWS=$(printf '%s\n' "$PARSED" | sed -n 's/^R\t//p' || true)
shown=0
if [ -n "$ROWS" ]; then
    while IFS=$'\t' read -r sortkey ip nonzero rest; do
        [ -n "${ip:-}" ] || continue
        if [ "$SHOW_ALL" != "1" ] && [ "$nonzero" = "0" ]; then
            continue
        fi
        line=$(printf "%-18s" "$ip")
        oldifs="$IFS"; IFS=$'\t'
        # shellcheck disable=SC2086
        set -- $rest
        IFS="$oldifs"
        for v in "$@"; do
            line="$line $(printf '%18s' "$v")"
        done
        echo "$line"
        shown=$((shown + 1))
    done < <(printf '%s\n' "$ROWS" | sort -t"$(printf '\t')" -k1,1nr)
fi

if [ "$shown" -eq 0 ]; then
    if [ "$SHOW_ALL" = "1" ]; then
        echo "(no IPs currently tracked)"
    else
        echo "(no IP currently has a non-zero counter — re-run with --all to list idle entries)"
    fi
fi

echo
echo "==================================================================="
echo "These are CURRENT values. The table keeps no history and no record of"
echo "past tarpits/denials. For actual enforcement events, read the access"
echo "log ON THE DOCKER HOST (it does not exist in this container):"
echo "  grep -aE ' (PT|PR)--' /var/log/haproxy.log | tail -20     # tarpit / deny"
echo "  grep -aE ' (429|403) ' /var/log/haproxy.log | tail -20    # rate-limit / block"
echo "  grep -a 'cip=<IP>' /var/log/haproxy.log | tail -50        # one client"
echo "  grep -a 'id=<uuid>' /var/log/haproxy.log                  # one request reference"
echo
echo "Operator actions (via the MASTER CLI socket — the @1 prefix is required):"
echo "  printf '@1 show table $TABLE key <IP>\\n'  | socat stdio $SOCKET"
echo "  printf '@1 set table $TABLE key <IP> data.http_req_rate 0\\n' | socat stdio $SOCKET"
echo "  printf '@1 clear table $TABLE key <IP>\\n' | socat stdio $SOCKET   # drop one entry"
echo "  printf '@1 clear table $TABLE\\n'          | socat stdio $SOCKET   # drop ALL entries"
echo "==================================================================="
