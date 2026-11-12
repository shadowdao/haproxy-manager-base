#!/bin/bash
## Test for mirror-index-copy.sh. CI/dev only; needs docker + buildx + jq and a
## THROWAWAY registry on REG (default localhost:5055):
##   docker run -d --name mirror-test-reg -p 127.0.0.1:5055:5000 registry:2
## (remove it afterwards). Never point REG at a real registry. Builds only
## FROM scratch images, so it needs no network beyond the registry.
## Set MIRROR_TEST_UPSTREAM=docker.io/library/python@sha256:... to also run the
## copy against a real multi-arch upstream digest (anonymous read-only pull).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
REG="${REG:-localhost:5055}"
case "$REG" in localhost:*|127.0.0.1:*) ;; *) echo "REG must be a localhost throwaway registry"; exit 2;; esac
curl -fsS -m5 "http://${REG}/v2/" >/dev/null || { echo "no registry on ${REG}"; exit 2; }
run="t$$"; work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; failn=0
ok()  { echo "PASS: $1"; pass=$((pass+1)); }
bad() { echo "FAIL: $1"; failn=$((failn+1)); }
digest() { docker buildx imagetools inspect "$1" --format '{{.Manifest.Digest}}'; }

mkimg() { # mkimg REPO:TAG PLATFORM  -> tiny FROM-scratch image
  printf 'FROM scratch\nLABEL t=%s\n' "$2-$run" >"$work/Dockerfile"
  docker buildx build -q --platform "$2" --provenance=false --sbom=false \
    --output "type=image,name=${1},push=true" "$work" >/dev/null || { echo "build $1 failed"; exit 2; }
}
mkimg "${REG}/${run}/amd64:v" linux/amd64
mkimg "${REG}/${run}/arm64:v" linux/arm64
A=$(digest "${REG}/${run}/amd64:v"); B=$(digest "${REG}/${run}/arm64:v")
# synthetic two-platform upstream index, and a single-platform one
docker buildx imagetools create -t "${REG}/${run}/multi:v" "${REG}/${run}/amd64@${A}" "${REG}/${run}/arm64@${B}" >/dev/null 2>&1 || exit 2
MULTI=$(digest "${REG}/${run}/multi:v"); SINGLE="$A"

# 1. two-platform source: pass, digest preserved, tag lands on source digest
if "$here/mirror-index-copy.sh" "${REG}/${run}/multi@${MULTI}" "${REG}/${run}/dst:1" >"$work/o1" 2>&1 \
   && [ "$(digest "${REG}/${run}/dst:1")" = "$MULTI" ]; then ok "multi-arch copy passes and digest round-trips ($MULTI)"; else bad "multi-arch copy"; cat "$work/o1"; fi

# 2. single-platform source: must FAIL loudly and must not create the real tag
if "$here/mirror-index-copy.sh" "${REG}/${run}/amd64@${SINGLE}" "${REG}/${run}/dst2:1" >"$work/o2" 2>&1; then bad "single-platform source was accepted"; else
  grep -q 'is not a multi-platform index\|missing linux/arm64' "$work/o2" && ok "single-platform source rejected: $(grep -m1 '::error::' "$work/o2")" || { bad "failed for the wrong reason"; cat "$work/o2"; }
  if docker buildx imagetools inspect "${REG}/${run}/dst2:1" >/dev/null 2>&1; then bad "real tag created despite failure"; else ok "real tag not created on failure"; fi
fi

# 3. existing multi-arch tag must survive a failing (single-platform) refresh
before=$(digest "${REG}/${run}/dst:1")
if "$here/mirror-index-copy.sh" "${REG}/${run}/amd64@${SINGLE}" "${REG}/${run}/dst:1" >"$work/o3" 2>&1; then bad "downgrade accepted"; else
  [ "$(digest "${REG}/${run}/dst:1")" = "$before" ] && ok "previously multi-arch :tag untouched after failed refresh" || bad ":tag moved to single-platform"; fi

# 4. malformed references are refused before any registry traffic
"$here/mirror-index-copy.sh" "${REG}/x:tag" "${REG}/${run}/d:1" >/dev/null 2>&1 && bad "tag-only source accepted" || ok "non-digest source refused"
"$here/mirror-index-copy.sh" "${REG}/x@sha256:$(printf 'a%.0s' {1..64})" 'bad dst' >/dev/null 2>&1 && bad "bad dst accepted" || ok "bad destination refused"

# 5. optional: real upstream digest
if [ -n "${MIRROR_TEST_UPSTREAM:-}" ]; then
  u="${MIRROR_TEST_UPSTREAM}"
  if "$here/mirror-index-copy.sh" "$u" "${REG}/${run}/up:1" >"$work/o5" 2>&1 && [ "$(digest "${REG}/${run}/up:1")" = "${u#*@}" ]; then ok "upstream index copied with identical digest ${u#*@}"; grep '^ok:' "$work/o5"; else bad "upstream copy"; tail -5 "$work/o5"; fi
fi
echo "passed=$pass failed=$failn"; [ "$failn" -eq 0 ]
