#!/usr/bin/env bash
# LOCAL end-to-end rehearsal of the build-push-coraza.yaml multi-arch logic
# against THROWAWAY registries. Never touches repo.anhonesthost.net / ghcr.io.
#
#   docker run -d --name e2ereg1 -p 127.0.0.1:5077:5000 registry:2
#   docker run -d --name e2ereg2 -p 127.0.0.1:5078:5000 registry:2
#   REG1=127.0.0.1:5077 REG2=127.0.0.1:5078 scripts/e2e-coraza-multiarch.sh
#   (then: docker rm -f e2ereg1 e2ereg2; docker buildx rm e2ebuilder)
#
# If the Docker daemon is not on this machine (remote/VM daemon), publish the
# registries on an address both sides reach (e.g. -p 172.17.0.1:5077:5000) and
# set REG1/REG2 to it; plain-HTTP is enabled for them in the builder config.
# Scenario 1: both platforms build, pushed by digest to TWO registries,
#             index assembled; checks both platforms + attestations present.
# Scenario 2: arm64 forced to fail (bad upstream tag) while a STALE arm64
#             digest from scenario 1 is still known: the tag must become
#             amd64-only and must not contain the stale arm64 digest.
set -euo pipefail
cd "$(dirname "$0")/.."
REG1=${REG1:?set REG1}; REG2=${REG2:?set REG2}
B=${BUILDER:-e2ebuilder}
R1=$REG1/cloud-hosting-platform/coraza-spoa
R2=$REG2/shadowdao/coraza-spoa
if ! docker buildx inspect "$B" >/dev/null 2>&1; then
  cfg=$(mktemp)
  printf '[registry."%s"]\n http=true\n insecure=true\n[registry."%s"]\n http=true\n insecure=true\n' "$REG1" "$REG2" > "$cfg"
  docker buildx create --name "$B" --driver docker-container --driver-opt network=host --buildkitd-config "$cfg" --bootstrap >/dev/null
fi
OUT="type=image,\"name=$R1,$R2\",push-by-digest=true,name-canonical=true,push=true"
build() { # build <arch> [extra args]; prints digest
  local arch=$1; shift; local meta; meta=$(mktemp)
  docker buildx build --builder "$B" --platform "linux/$arch" --output "$OUT" --metadata-file "$meta" "$@" ./coraza-spoa >&2
  python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$meta"
}
inspect() { docker buildx imagetools inspect --builder "$B" "$@"; }

echo "=== scenario 1: both platforms ==="
AMD=$(build amd64); ARM=$(build arm64)
echo "amd64=$AMD arm64=$ARM"
IMAGETOOLS="docker buildx imagetools" scripts/assemble-multiarch-index.sh --builder "$B" \
  --amd64 "$AMD" --arm64 "$ARM" --arm64-outcome success --repo "$R1" --repo "$R2" --tag latest
for r in "$R1" "$R2"; do echo "--- $r:latest"; inspect "$r:latest" | grep -E 'Digest:|Platform:'; done

echo "=== scenario 2: forced arm64 failure, stale arm64 digest ($ARM) still in hand ==="
if NEWARM=$(build arm64 --build-arg CORAZA_SPOA_VERSION=v0.0.0-does-not-exist 2>/dev/null); then echo "BUG: forced failure succeeded"; exit 1; fi
echo "arm64 step failed as forced"
scripts/assemble-multiarch-index.sh --builder "$B" \
  --amd64 "$AMD" --arm64 "$ARM" --arm64-outcome failure --repo "$R1" --repo "$R2" --tag latest
for r in "$R1" "$R2"; do
  echo "--- $r:latest"; inspect "$r:latest" | grep -E 'Digest:|Platform:'
  if inspect "$r:latest" | grep -q 'linux/arm64'; then echo "FAIL: arm64 still attached"; exit 1; fi
  if inspect "$r:latest" --raw | grep -q "$ARM"; then echo "FAIL: stale arm64 digest present"; exit 1; fi
done
echo "E2E OK"
