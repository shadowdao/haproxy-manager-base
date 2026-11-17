#!/usr/bin/env bash
# Final publish gate: every <repo>:<tag> must resolve, carry exactly the
# platforms the assemble step reported, and have ONE index digest across all
# tags and all registries. Any miss or mismatch exits 1.
#
#   verify-published-tags.sh --platforms linux/amd64,linux/arm64 \
#       --repo <registry/path> [--repo ...] --tag <tag> [--tag ...]
#
# The index digest is computed in a buildx-VERSION-INDEPENDENT way. CI run 5381
# showed buildx v0.28.0 ignores `--format '{{.Manifest.Digest}}'` and prints the
# whole inspect text, while 0.38 prints a bare digest. So the digest comes from:
#   1. sha256 of the raw manifest bytes (`inspect --raw`) - always, authoritative
#      (a content digest IS the sha256 of the manifest bytes);
#   2. the strictly anchored `Digest:` line of the default text output, if present;
#   3. the `--format '{{.Manifest.Digest}}'` output, ONLY if it is a bare digest
#      (0.28's full-text output is ignored here, not an error).
# Every source that is available must agree, else the ref fails.
# Platforms are read from the raw JSON (also version independent).
#
# Env: IMAGETOOLS overrides the command (default "docker buildx imagetools");
# the CI step sets it to "$BUILDX imagetools"; the test suite uses a stub.
set -uo pipefail

IMAGETOOLS=${IMAGETOOLS:-docker buildx imagetools}
platforms=""; repos=(); tags=()
while [ $# -gt 0 ]; do
  case "$1" in
    --platforms) platforms=${2-}; shift 2 ;;
    --repo) repos+=("${2-}"); shift 2 ;;
    --tag) tags+=("${2-}"); shift 2 ;;
    *) echo "verify-published-tags: unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$platforms" ] && [ ${#repos[@]} -gt 0 ] && [ ${#tags[@]} -gt 0 ] \
  || { echo "::error::verify-published-tags: --platforms, --repo and --tag are required"; exit 2; }
command -v jq >/dev/null || { echo "::error::verify-published-tags: jq is required"; exit 2; }

want=$(printf '%s' "$platforms" | tr ',' '\n' | sort | tr '\n' ' ')
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
digest_re='^sha256:[0-9a-f]{64}$'
ref_digest=""; ref_name=""; fail=0

for r in "${repos[@]}"; do
  for t in "${tags[@]}"; do
    ref="${r}:${t}"
    raw="$work/raw"
    if ! timeout 90 $IMAGETOOLS inspect --raw "$ref" >"$raw" 2>"$work/err" || [ ! -s "$raw" ]; then
      echo "::error::MISSING or unreadable: ${ref}: $(head -c 300 "$work/err")"; fail=1; continue
    fi
    # Raw bytes as served, and with trailing newlines stripped (some buildx
    # versions append one when printing); the content digest is one of the two.
    h1="sha256:$(sha256sum <"$raw" | cut -d' ' -f1)"
    h2="sha256:$(printf '%s' "$(cat "$raw")" | sha256sum | cut -d' ' -f1)"

    # Source 2: strictly anchored top-level "Digest:" line of the text output.
    textd=""
    if timeout 90 $IMAGETOOLS inspect "$ref" >"$work/text" 2>/dev/null; then
      mapfile -t lines < <(grep -E '^Digest:[[:space:]]+sha256:[0-9a-f]{64}[[:space:]]*$' "$work/text" | sed -E 's/^Digest:[[:space:]]+//; s/[[:space:]]+$//')
      [ ${#lines[@]} -eq 1 ] && textd=${lines[0]}
    fi
    # Source 3: bare --format output, only when it really is a bare digest.
    fmtd=""
    if out=$(timeout 90 $IMAGETOOLS inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null); then
      out=$(printf '%s' "$out" | tr -d '[:space:]')
      [[ "$out" =~ $digest_re ]] && fmtd=$out
    fi

    d=""
    for cand in "$textd" "$fmtd"; do
      [ -n "$cand" ] || continue
      if [ "$cand" != "$h1" ] && [ "$cand" != "$h2" ]; then
        echo "::error::digest cross-check FAILED for ${ref}: reported ${cand}, raw manifest hashes to ${h1}"; fail=1; d="!"; break
      fi
      d=$cand
    done
    [ "$d" = "!" ] && continue
    [ -n "$d" ] || d=$h2
    [[ "$d" =~ $digest_re ]] || { echo "::error::bad digest for ${ref}: ${d}"; fail=1; continue; }
    if [ -z "$textd$fmtd" ]; then
      echo "::warning::no reported digest for ${ref}; using sha256 of the raw manifest"
    fi

    if ! got=$(jq -r '.manifests[]? | select(.platform.os != "unknown") | "\(.platform.os)/\(.platform.architecture)"' "$raw" 2>/dev/null | sort | tr '\n' ' '); then
      echo "::error::unparseable manifest for ${ref}"; fail=1; continue
    fi
    if [ "$got" != "$want" ]; then
      echo "::error::platform mismatch for ${ref}: have [${got}] want [${want}]"; fail=1
    fi
    echo "ok ${ref} ${d} [${got}]"
    if [ -z "$ref_digest" ]; then ref_digest="$d"; ref_name="$ref"
    elif [ "$d" != "$ref_digest" ]; then
      echo "::error::digest mismatch: ${ref}=${d} vs ${ref_name}=${ref_digest}"; fail=1
    fi
  done
done
[ "$fail" = 0 ] || { echo "::error::tag verification FAILED"; exit 1; }
echo "verified: ${tags[*]} in ${#repos[@]} registries, digest ${ref_digest}, platforms ${platforms}"
