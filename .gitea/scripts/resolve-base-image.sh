#!/bin/bash
## resolve-base-image.sh IMAGE:TAG — CI only (not copied into images).
## Prints IMAGE@sha256:<digest> for a Docker Hub tag, looked up DIRECTLY at
## registry-1.docker.io over HTTPS (never via the pkg-cache mirror), so the
## build can say `FROM IMAGE@sha256:...` and the mirror can only serve
## content-addressed blobs that BuildKit verifies. Exits non-zero (prints
## nothing on stdout) if the lookup fails; the workflow then skips the mirror
## and pulls the tag directly from Docker Hub. HEAD requests do not count
## against Docker Hub pull rate limits.
## Canonical copy: cloud-apache-container/.gitea/scripts/resolve-base-image.sh
## (docs/pkg-cache.md there); other repos carry identical copies.
set -euo pipefail
ref="${1:?usage: resolve-base-image.sh IMAGE:TAG}"
name_re='^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)?$'
tag_re='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'
name="${ref%:*}"; tag="${ref##*:}"
[ "$name" != "$ref" ] || { echo "resolve-base-image: '$ref' has no :tag" >&2; exit 2; }
[[ "$name" =~ $name_re ]] || { echo "resolve-base-image: bad image name '$name'" >&2; exit 2; }
[[ "$tag" =~ $tag_re ]] || { echo "resolve-base-image: bad tag '$tag'" >&2; exit 2; }
repo="$name"; [[ "$repo" == */* ]] || repo="library/$repo"   # official images

curl_opts=(-fsS --proto '=https' --retry 3 --retry-all-errors --max-time 20)
token=$(curl "${curl_opts[@]}" "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${repo}:pull" |
        python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
[ -n "$token" ] || { echo "resolve-base-image: no Docker Hub token for $repo" >&2; exit 1; }
hdrs=$(curl "${curl_opts[@]}" -I \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.oci.image.index.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json' \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "https://registry-1.docker.io/v2/${repo}/manifests/${tag}")
digest=$(printf '%s\n' "$hdrs" | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:" {print $2}' | tail -n1)
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "resolve-base-image: no valid digest for $ref (got '${digest}')" >&2; exit 1; }
printf '%s@%s\n' "$name" "$digest"
