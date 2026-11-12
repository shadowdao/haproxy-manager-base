#!/bin/bash
## mirror-index-copy.sh SRC DST — CI only (not copied into images).
##   SRC  registry/path@sha256:<index digest>   (digest-pinned upstream reference)
##   DST  registry/path:<tag>                   (the mirror tag consumers FROM)
##
## Registry-to-registry copy of the WHOLE upstream image index (every
## platform), then assertions. No local `docker pull`, so nothing is flattened
## to the runner's platform (the old pull/tag/push step re-published only the
## amd64 manifest, leaving the mirror without an arm64 variant).
##
## Ordering (protects a previously multi-arch DST tag):
##   1. copy SRC -> DST_REPO:<tag>-staging      (real tag untouched)
##   2. assert staging: index lists every REQUIRED platform and its digest
##      equals the digest in SRC
##   3. only then point DST at that digest (registry-side, no data transfer)
##   4. re-assert on DST
## A failure at 1/2 exits non-zero before the real tag is touched. A failure
## at 4 cannot be rolled back by this script (the tag already moved) but it is
## loud and the same digest was already proven at step 2.
##
## Env: REQUIRED_PLATFORMS (default "linux/amd64 linux/arm64").
##      IMAGETOOLS (default "docker buildx imagetools"), for tests/skopeo-free CI.
##      (buildx talks plain HTTP to a localhost registry, so the test needs no flags.)
set -euo pipefail

SRC="${1:?usage: mirror-index-copy.sh SRC@sha256:DIGEST DST_REPO:TAG}"
DST="${2:?usage: mirror-index-copy.sh SRC@sha256:DIGEST DST_REPO:TAG}"
REQUIRED_PLATFORMS="${REQUIRED_PLATFORMS:-linux/amd64 linux/arm64}"
read -r -a IMGTOOLS <<<"${IMAGETOOLS:-docker buildx imagetools}"

fail() { echo "::error::mirror-index-copy: $*" >&2; exit 1; }

# Validate shapes (registry host may carry :port, e.g. localhost:5055).
[[ "$SRC" =~ ^[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}$ ]] || fail "bad source reference '${SRC}'"
[[ "$DST" =~ ^[a-z0-9][a-z0-9._:/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || fail "bad destination '${DST}'"
src_digest="${SRC#*@}"
dst_repo="${DST%:*}"; dst_tag="${DST##*:}"
STAGING="${dst_repo}:${dst_tag}-staging"

# assert_ref REF: REF must be an index listing every required platform, and
# its manifest digest must equal the upstream index digest.
assert_ref() {
  local ref="$1" raw have want got
  raw=$("${IMGTOOLS[@]}" inspect "$ref" --raw) || fail "cannot inspect ${ref}"
  have=$(jq -r '[.manifests[]? | select(.platform.os != "unknown") | "\(.platform.os)/\(.platform.architecture)"] | unique | join(" ")' <<<"$raw")
  [ -n "$have" ] || fail "${ref} is not a multi-platform index (single-platform manifest?); platforms: none"
  for want in $REQUIRED_PLATFORMS; do
    case " $have " in *" $want "*) ;; *) fail "${ref} is missing ${want} (has: ${have})" ;; esac
  done
  got=$("${IMGTOOLS[@]}" inspect "$ref" --format '{{.Manifest.Digest}}') || fail "cannot read digest of ${ref}"
  [ "$got" = "$src_digest" ] || fail "${ref} digest ${got} != upstream ${src_digest}"
  echo "ok: ${ref} platforms=[${have}] digest=${got}"
}

echo "::group::copy index ${SRC} -> ${STAGING}"
"${IMGTOOLS[@]}" create -t "$STAGING" "$SRC"
echo "::endgroup::"
assert_ref "$STAGING"

echo "::group::promote staging -> ${DST}"
"${IMGTOOLS[@]}" create -t "$DST" "${dst_repo}@${src_digest}"
echo "::endgroup::"
assert_ref "$DST"
echo "mirror ok: ${DST} == ${src_digest}"
