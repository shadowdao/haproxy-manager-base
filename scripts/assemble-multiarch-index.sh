#!/usr/bin/env bash
# Assemble the multi-arch index tag(s) from per-platform images that were
# already pushed BY DIGEST (no tag). Used by the trusted x86 publish job
# (see .gitea/workflows/build-push-coraza.yaml; template for the other WHP
# image repos, docs/arm64/IMAGE-PIPELINE-PLAN.md section 4.1/4.4).
#
#   assemble-multiarch-index.sh \
#       --amd64 sha256:<digest> \
#       --arm64 sha256:<digest> --arm64-outcome success|failure|cancelled|skipped \
#       --repo <registry/path> [--repo <other registry/path> ...] \
#       --tag <tag> [--tag <tag> ...] [--builder <buildx builder>]
#
# Rules (all enforced here so the workflow stays thin and these are testable):
#   * amd64 is mandatory. A missing/malformed amd64 digest, or an amd64 digest
#     that does not inspect as linux/amd64, aborts with exit 1 and publishes
#     NOTHING (the same "build failed, no tag" outcome as before multi-arch).
#   * arm64 is attached ONLY when its step outcome is exactly "success" AND the
#     digest is well-formed AND it inspects as linux/arm64. Otherwise the tag is
#     published amd64-only (warning, exit 0). The arm64 digest must come from
#     THIS run's step output - the workflow never reads it from a registry tag,
#     so a previous build's arm64 can never be re-attached to a newer amd64.
#   * every --tag is created in every --repo from <repo>@<digest> sources in
#     that same repo (both digests were pushed to every --repo by the build).
#
# Env: IMAGETOOLS overrides the command (default: "docker buildx imagetools");
# the test suite points it at a stub.
set -euo pipefail

IMAGETOOLS=${IMAGETOOLS:-docker buildx imagetools}
amd64=""; arm64=""; outcome="skipped"; builder=""
repos=(); tags=()

die() { echo "assemble-multiarch-index: $*" >&2; exit 1; }
warn() { echo "::warning::assemble-multiarch-index: $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --amd64) amd64=${2-}; shift 2 ;;
    --arm64) arm64=${2-}; shift 2 ;;
    --arm64-outcome) outcome=${2-}; shift 2 ;;
    --repo) repos+=("${2-}"); shift 2 ;;
    --tag) tags+=("${2-}"); shift 2 ;;
    --builder) builder=${2-}; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

re='^sha256:[0-9a-f]{64}$'
[ ${#repos[@]} -gt 0 ] || die "need at least one --repo"
[ ${#tags[@]} -gt 0 ] || die "need at least one --tag"
[[ $amd64 =~ $re ]] || die "amd64 digest missing or malformed ('$amd64'); refusing to publish"

bflag=(); [ -n "$builder" ] && bflag=(--builder "$builder")

# arch_of <ref>: prints the image config's architecture ("" on any failure).
arch_of() {
  # shellcheck disable=SC2086
  $IMAGETOOLS inspect "${bflag[@]}" "$1" --format '{{json .Image}}' 2>/dev/null \
    | python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("architecture",""))' 2>/dev/null || true
}

for r in "${repos[@]}"; do
  [ "$(arch_of "$r@$amd64")" = amd64 ] || die "$r@$amd64 does not inspect as linux/amd64; refusing to publish"
done

use_arm64=0
if [ "$outcome" != success ]; then
  warn "arm64 step outcome is '$outcome': publishing amd64-only (no arm64 digest is carried over)"
elif ! [[ $arm64 =~ $re ]]; then
  warn "arm64 step reported success but its digest is missing/malformed: publishing amd64-only"
elif [ "$arm64" = "$amd64" ]; then
  warn "arm64 digest equals the amd64 digest: publishing amd64-only"
else
  use_arm64=1
  for r in "${repos[@]}"; do
    if [ "$(arch_of "$r@$arm64")" != arm64 ]; then
      warn "$r@$arm64 does not inspect as linux/arm64: publishing amd64-only"
      use_arm64=0; break
    fi
  done
fi

for r in "${repos[@]}"; do
  targs=(); for t in "${tags[@]}"; do targs+=(-t "$r:$t"); done
  srcs=("$r@$amd64"); [ "$use_arm64" = 1 ] && srcs+=("$r@$arm64")
  echo "assemble-multiarch-index: $r tags=${tags[*]} sources=${#srcs[@]} ($([ "$use_arm64" = 1 ] && echo 'amd64+arm64' || echo 'amd64-only'))"
  # shellcheck disable=SC2086
  $IMAGETOOLS create "${bflag[@]}" "${targs[@]}" "${srcs[@]}"
done
echo "platforms=$([ "$use_arm64" = 1 ] && echo linux/amd64,linux/arm64 || echo linux/amd64)"
