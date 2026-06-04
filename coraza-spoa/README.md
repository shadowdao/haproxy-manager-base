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
