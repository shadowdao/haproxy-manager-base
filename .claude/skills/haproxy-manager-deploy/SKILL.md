---
name: haproxy-manager-deploy
description: Use when shipping a haproxy-manager-base code change — editing templates, the Dockerfile, the Python manager, the coraza-spoa subdir, or static assets like errors/, then getting it onto whp01 or staging. Trigger eagerly on phrases like "deploy haproxy", "ship the haproxy change", "rebuild haproxy-manager", "update the WAF block page", "recreate haproxy-manager", or any time the next step would involve `git push` from this repo, `docker pull` on the image, or `container-manager.sh recreate`. Walks the Gitea-CI-auto-build + recreate flow, surfaces the named-volume shadowing foot-gun, and includes post-deploy verification.
---

# haproxy-manager-base commit / build / deploy

This is procedural discipline for changes to `haproxy-manager-base`. The repository builds via Gitea Actions on push, not via a local build script (the WHP flow uses `build-release.sh`; this one doesn't — don't conflate them, see the `whp-deploy` skill in the whp repo for that one). Each step has caught a real foot-gun.

## The pipeline at a glance

```
edit code (local)
   └─> commit + push
         └─> Gitea Actions auto-build (build-push.yaml / build-push-coraza.yaml)
               ├─> publishes :latest tag to repo.anhonesthost.net
               └─> wait for image (~2-4 min)
                     └─> recreate container on target server
                           └─> verify
```

Do not skip the verify step. The container can come up "healthy" while still serving stale config or missing a baked-in file (see Step 5).

---

## Step 0a — Resolve the target host (never hardcoded)

This skill deliberately does **not** bake in a server hostname — this repo is mirrored to a public remote, so a real FQDN in the skill would leak into commits. Instead, resolve the deploy target into a `DEPLOY_HOST` shell variable that every `ssh` command below uses.

```bash
HOST_FILE=".claude/skills/haproxy-manager-deploy/target-host.local"
DEPLOY_HOST="$(cat "$HOST_FILE" 2>/dev/null)"
```

- **If `$DEPLOY_HOST` is non-empty**, use it — that's the user's saved target. The file is gitignored, so the real hostname never lands in a commit.
- **If it's empty**, ask the user which server this deploy targets (e.g. production vs. staging) and what its hostname or SSH alias is. Then offer to save it so future deploys don't have to ask:

  ```bash
  echo 'the-host-they-gave.example' > "$HOST_FILE"   # gitignored — safe to store the real FQDN here
  ```

Confirm `$DEPLOY_HOST` is set before running any `ssh` step:

```bash
[ -n "$DEPLOY_HOST" ] || echo "DEPLOY_HOST not set — ask the user for the target server"
```

All commands below assume the variable is set in the same shell session (`ssh root@"$DEPLOY_HOST" ...`).

---

## Step 0 — Confirm before pushing

If the user just said "deploy" or "ship the haproxy fix", confirm what's actually changing: a template, the Python manager, the coraza-spoa subdir (separate image, separate workflow), or a static asset. Look at `git status` and `git diff` and read the diff back to the user if it's non-trivial.

Anything that affects the customer-facing block path (e.g. `templates/hap_listener.tpl`, `errors/403-waf.html`) is **visible to every visitor on every site**. Authorization is per-deploy, not standing.

---

## Step 1 — Know which workflow your change triggers

- `build-push.yaml` builds `haproxy-manager-base:latest` (the main image). Triggered by changes anywhere outside `coraza-spoa/`.
- `build-push-coraza.yaml` builds `coraza-spoa:latest`. Triggered by changes inside `coraza-spoa/`.
- `mirror-base-image.yaml` is a scheduled job mirroring upstream base images; unrelated to feature deploys.

If you've changed both subtrees in one push, both workflows fire — note that the order they finish isn't guaranteed.

---

## Step 2 — Beware the `/etc/haproxy` named volume shadow

If your change adds a NEW file that the running container needs (a baked-in asset, an errorfile, a new config snippet), **do not place it under `/etc/haproxy/` in the Dockerfile**. That path is a Docker named volume in deployed containers — image content only seeds the volume on first creation, so existing deployments will not see your new file even after a recreate.

Safe paths for baked-in assets:
- `/haproxy/...` (the image's WORKDIR — not volumed)
- Anywhere outside `/etc/haproxy`, `/etc/letsencrypt`

Reference the asset by absolute path from the haproxy config templates (e.g. `lf-file /haproxy/errors/403-waf.html`).

See `feedback-haproxy-named-volume` memory for the full pattern.

---

## Step 3 — Commit + push

Standard commit format with trailing `Co-Authored-By:` line. Match the recent commit message style (`git log --oneline -5`). Stage files explicitly by name.

```bash
git push origin main
```

Pushing immediately triggers the Gitea Actions build.

---

## Step 4 — Wait for the build

The Go build inside coraza-spoa takes ~2-3 minutes; the haproxy-manager-base build is faster (~1-2 min). Don't bother polling the runs UI — just pull on the target server until the digest changes:

```bash
ssh root@"$DEPLOY_HOST" 'until docker pull -q repo.anhonesthost.net/cloud-hosting-platform/haproxy-manager-base:latest 2>&1 | tail -1 | grep -qE "Image is up to date|Status: Downloaded"; do sleep 15; done'
```

`-q` suppresses the noisy layer progress so the grep can match cleanly. If you started this command before the CI build finished, it'll loop until the new image lands; once the digest matches, it exits.

To confirm you got the new image, check the image-creation time vs your push:

```bash
ssh root@"$DEPLOY_HOST" 'docker images repo.anhonesthost.net/cloud-hosting-platform/haproxy-manager-base --format "{{.CreatedSince}}"'
```

It should say "X minutes ago" matching the build wait, not "yesterday".

---

## Step 5 — Verify the new image has what you think it has, BEFORE recreating

The image is `gcr.io/distroless/static-debian12:nonroot`-based, no shell. To peek inside, run a one-shot with a sh entrypoint override (only works if you put one in the image — coraza-spoa is distroless and won't have sh; haproxy-manager-base is Python-based and does):

```bash
# haproxy-manager-base (has sh):
ssh root@"$DEPLOY_HOST" 'docker run --rm --entrypoint sh repo.anhonesthost.net/cloud-hosting-platform/haproxy-manager-base:latest -c "ls /haproxy/errors/ && head -5 /haproxy/errors/403-waf.html"'

# coraza-spoa (distroless, no sh) — use docker create + docker cp instead:
ssh root@"$DEPLOY_HOST" 'docker create --name _peek repo.anhonesthost.net/cloud-hosting-platform/coraza-spoa:latest && docker cp _peek:/etc/coraza/config.yaml - | tar xO; docker rm _peek'
```

This step exists because the CI build can succeed but ship the wrong file (wrong commit pulled, build cache issue, etc.). Catching it here is one step earlier than catching it from a customer report.

---

## Step 6 — Recreate the container

```bash
ssh root@"$DEPLOY_HOST" '/root/whp/scripts/container-manager.sh recreate haproxy-manager'
```

For coraza-spoa changes:
```bash
ssh root@"$DEPLOY_HOST" '/root/whp/scripts/container-manager.sh recreate coraza-spoa'
```

`container-manager.sh recreate` does: stop, remove, docker pull (idempotent if already pulled), start with the right flags from settings.json. **It reads `/docker/whp/settings.json` for things like `coraza_waf.mode`**, so if the user has toggled mode while you were building, the recreated container reflects the current setting — not whatever it was when you started.

---

## Step 7 — Verify the deploy

For haproxy-manager:

```bash
ssh root@"$DEPLOY_HOST" '
echo "=== container ==="
docker ps --filter name=haproxy-manager --format "image: {{.Image}} status: {{.Status}}"
echo "=== healthy ==="
docker inspect haproxy-manager --format "{{.State.Health.Status}}"
echo "=== haproxy config valid ==="
docker exec haproxy-manager haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1 | tail -3
echo "=== new asset reachable inside container ==="
docker exec haproxy-manager ls -la /haproxy/errors/ 2>&1 | tail -3
echo "=== panel health ==="
curl -fsS -m 5 -o /dev/null -w "PANEL=%{http_code}\n" http://127.0.0.1:8000/health
'
```

Pass criteria:
- Container status = healthy
- haproxy config validates (warnings OK, errors not)
- Your new asset (if any) is at the expected path inside the running container
- Panel returns 200

If any check fails, the change still went out — diagnose immediately. Don't say "deploy complete" before this clears.

---

## Step 8 — End-to-end test if customer-visible

If your change affects what a visitor sees (block pages, redirects, security responses), do a synthetic test that exercises the actual path. For WAF block-page changes, the recipe is:

```bash
# Inject a temporary ACL that forces the WAF deny path on a custom header,
# fire one request, observe the rendered response, then revert + reload.
ssh root@"$DEPLOY_HOST" '
docker exec haproxy-manager cp /etc/haproxy/haproxy.cfg /tmp/cfg-bak
docker exec haproxy-manager sh -c "sed -i \"/http-request send-spoe-group coraza coraza-req/a\\\\    http-request set-var(txn.coraza.action) str(deny) if { req.hdr(x-force-waf-block) -m str yes }\" /etc/haproxy/haproxy.cfg"
docker exec haproxy-manager sh -c "echo reload | socat stdio /tmp/haproxy-cli" >/dev/null
sleep 1
curl -sSk -D - -H "x-force-waf-block: yes" -H "Host: <live-vhost>" "https://localhost/" | head -40
# revert
docker exec haproxy-manager cp /tmp/cfg-bak /etc/haproxy/haproxy.cfg
docker exec haproxy-manager sh -c "echo reload | socat stdio /tmp/haproxy-cli" >/dev/null
'
```

**Pick a real `<live-vhost>`.** The `Host:` header must match a domain currently served by this haproxy-manager, or the request won't route to the WAF path. Don't hardcode a customer hostname in this skill — pull a live one at test time (any entry from the panel's domain list, or `docker exec haproxy-manager ls /etc/letsencrypt/live`) and substitute it.

**The injection point matters.** Insert AFTER `http-request send-spoe-group coraza coraza-req`, because the SPOE call overwrites `txn.coraza.action` based on the real Coraza verdict — if you inject before it, your override is wiped.

**The reload mechanism matters.** Use `echo reload | socat stdio /tmp/haproxy-cli` — the container is python-based but doesn't have `kill` in PATH, and `docker kill --signal=HUP` signals the python manager (PID 1), not haproxy.

---

## Recovery hints

- **`docker pull` exits "Image is up to date" but your change isn't there** — CI hasn't finished yet. Check `https://repo.anhonesthost.net/cloud-hosting-platform/haproxy-manager-base/actions` for in-progress runs.
- **Container recreates but new file is missing inside** — you put the file under `/etc/haproxy/` and the named volume shadows it. See Step 2. Move the file under `/haproxy/` (or another non-volumed path) and rebuild.
- **HAProxy `lf-file` page renders but CSS is broken / percentages stripped** — literal `%` in the file body must be doubled (`100%%`). HAProxy log-format expansion eats single `%`. See `haproxy-lf-file-percent-escape` memory.
- **Synthetic test returns 200 from gunicorn instead of the block page** — your test ACL is being overwritten by the SPOE call. Inject after `send-spoe-group`, not before.
- **`docker exec haproxy-manager kill -HUP 1` fails** — the python-based container doesn't have `kill` in PATH. Use the haproxy admin socket: `echo reload | socat stdio /tmp/haproxy-cli`.

---

## Why this skill is rigid

The pipeline is short, but the volume-shadowing trap and the SPOE-overwrite trap during testing each cost a 5-10 minute debugging detour during the session this skill was authored from. Both are silent failures — your change goes out, the container is healthy, and you only notice the bug when a customer report (or a careful synthetic test) surfaces it. The verification steps exist to catch them before that happens.
