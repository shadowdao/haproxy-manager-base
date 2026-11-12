# coraza-spoa sidecar

A sidecar container that runs [Coraza-SPOA](https://github.com/corazawaf/coraza-spoa) as a WAF engine for `haproxy-manager`. HAProxy consults it per-request via the SPOE/SPOP protocol; Coraza evaluates the request against OWASP CRS rules and tells HAProxy whether to allow or block.

## Design constraints

- **`haproxy-manager` does NOT depend on this sidecar.** The base image works standalone (used in other projects and home networks) without WAF. SPOE config in the generated `haproxy.cfg` is opt-in via an env var on `haproxy-manager`.
- **Fail-open when the sidecar is unhealthy.** `option set-on-error continue` in the HAProxy SPOE config means request flow continues uninspected if coraza-spoa is unreachable, rather than 503-ing customer traffic.
- **Detect-only globally; enforce explicitly.** See `overrides.conf` for the day-one enforce list. Most CRS rules log without blocking until we've tuned per-customer false positives.

## Deployment shape

Two containers per host, both on the `client-net` docker network:

```
haproxy-manager        (existing) — ports 80, 443, 8000
   │ SPOE TCP/9000 → reach coraza-spoa by container DNS
   ▼
coraza-spoa            (this image)
   port 9000 (SPOE) — NOT exposed on host; internal network only
   /var/log/coraza    — bind-mounted to host for AI Monitor consumption
```

Typical `docker run`:

```bash
mkdir -p /var/log/coraza
chown 65532:65532 /var/log/coraza   # distroless nonroot UID

docker run -d \
    --name coraza-spoa \
    --network client-net \
    --restart unless-stopped \
    -v /var/log/coraza:/var/log/coraza \
    your-registry.example.com/cloud-hosting-platform/coraza-spoa:latest
```

Then on the `haproxy-manager` container, add the env var:

```
-e HAPROXY_CORAZA_SPOE_BACKEND=coraza-spoa:9000
```

The haproxy-manager template engine sees the env var and renders the SPOE config block pointing at this sidecar. Without the env var, no SPOE blocks render — the haproxy-manager image's behavior is unchanged.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | Multi-stage build (golang:1.25 → distroless), pinned to upstream coraza-spoa tag |
| `config.yaml` | SPOA listener config + one named application `haproxy` |
| `overrides.conf` | Day-one enforce list (`ctl:ruleEngine=On` for high-confidence rule IDs) |
| `README.md` | This file |

## Audit log

`/var/log/coraza/audit.log` — JSON, one event per line, RelevantOnly (only requests that triggered ≥1 rule are logged). AI Monitor should be configured to tail this on each host.

Entries include rule IDs, matched patterns, request metadata, and action taken (`log` for detect-only, `deny` for enforced). Use the JSON `action` field to filter blocked vs. observed.

## Upgrading the pin

CRS rules are bundled into the coraza-spoa binary at build time, so the CRS version is whatever ships with the pinned coraza-spoa tag. To upgrade:

1. Check upstream releases: <https://github.com/corazawaf/coraza-spoa/releases>
2. Skim the CHANGELOG for new/changed rules in the `overrides.conf` ID ranges.
3. Bump `ARG CORAZA_SPOA_VERSION` in the Dockerfile.
4. Push to `main` — the Gitea workflow at `.gitea/workflows/build-push-coraza.yaml` rebuilds + pushes `:latest`.
5. On each host, run `container-manager.sh recreate coraza-spoa` to pull the new image.

## Tuning false positives

When a legitimate request triggers a blocked rule, the audit log shows the rule ID. Two ways to silence it:

1. **Per-rule exception** in `overrides.conf`: `SecRuleRemoveById <id>` (full disable) or `SecRuleRemoveTargetById <id> "<target>"` (targeted exception).
2. **Drop from the enforce list**: remove the rule's ID range from the `ctl:ruleEngine=On` overrides; it falls back to detect-only.

After tuning, push the change — CI rebuilds, then `recreate coraza-spoa` on each host to apply.

## Multi-arch (linux/amd64 + linux/arm64)

The image is built for both platforms **without QEMU**: the two Go stages are
`FROM --platform=$BUILDPLATFORM` (the in-house `golang:1.25` mirror is amd64-only,
which is enough) and the binary is cross-compiled with
`CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH`. The catalog-extractor runs at
build time on the build platform; its JSON output is architecture-neutral. Only the
final distroless stage is per target platform. The amd64 image content is
byte-identical to the pre-multi-arch build (measured: same rootfs tree, same
`/coraza-spoa` sha256).

CI (`.gitea/workflows/build-push-coraza.yaml`, one job on the trusted x86 runner):
amd64 and arm64 are each pushed **by digest, untagged, to both registries**
(Gitea + GHCR; the same digest lands in both), then
`scripts/assemble-multiarch-index.sh` creates `:latest` in each registry with
`docker buildx imagetools create` from `<repo>@<amd64>` and `<repo>@<arm64>`.
The arm64 step is `continue-on-error`; when it fails the tag is published
amd64-only, as before, and the arm64 digest is only ever taken from the current
run's step output (a previous build's arm64 is never re-attached).

Attestations: buildx provenance is kept per platform. A by-digest push with
attestations is a small per-platform index (image + `attestation-manifest`);
`imagetools create` over two of them yields one index with all four entries
(amd64, its attestation, arm64, its attestation), each attestation still pointing
at its own platform manifest; `imagetools inspect --format '{{json .Provenance}}'`
shows both. Nothing flattens or drops them.

Local rehearsal (no real registry is touched): `scripts/e2e-coraza-multiarch.sh`
(usage in its header).
