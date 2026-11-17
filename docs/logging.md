# Container logging policy (what reaches `docker logs`)

`docker logs haproxy-manager` (and the docker logging driver: json-file today,
journald -> Graylog under WHP PR #260) must carry only low-volume, high-value
lines. Per-request logs stay out of it.

| Source | Destination | Volume |
|---|---|---|
| HAProxy edge access log (1.5M lines/day) | `/var/log/haproxy/access.log` via `haproxy-log-receiver.py` (20 MiB cap, gzip generations) | NOT in `docker logs` |
| HAProxy master stderr (ALERT, crash dumps) | `haproxy-stderr.log` -> `haproxy-stderr-relay.py` -> stdout (benign, rate limited) / stderr (crash evidence) | rare |
| Supervisor / relay / init lines | stdout / stderr | rare |
| gunicorn :8080 default-page / blocked-IP / suspended-site | NO access log | none |
| gunicorn :8000 management API access log | `/var/log/haproxy/api-access.log` (haproxy-logs volume, mode 0640), rotated by `scripts/gunicorn-access-rotate.py` (copy-truncate, 20 MiB x 3) | NOT in `docker logs` |
| gunicorn error log (tracebacks, worker timeouts) | stderr (`--error-logfile -`) | rare |

## Why

Before this change both gunicorns ran with `--access-logfile -`, so each :8080
hit and each :8000 API call was one docker stdout line. With the journald
driver that is one journal entry per request: journald's default rate limit
(10000 messages / 30 s per sending service) can then suppress the very
crash-dump lines the relay emits, and Graylog would be flooded.

## Knobs

`HAPROXY_MGR_API_ACCESS_LOG` (path), `HAPROXY_API_ACCESS_LOG_MAX_BYTES`
(20971520), `HAPROXY_API_ACCESS_LOG_BACKUPS` (3), `HAPROXY_API_ACCESS_LOG_POLL`
(30 s; the live file can exceed the cap by at most one interval of API traffic).

## Not done

Failed-auth (401/403) lines are NOT mirrored to stdout; they are in the file
(grep the status column). Add a rate-limited mirror later if wanted.

## Tests

`python3 scripts/test-gunicorn-access-logging.py` (runs in the image build):
real gunicorn, a burst of default-page requests produces zero stdout lines,
API requests land in the file not stdout, handler exceptions still reach
stderr, and rotation is bounded.

Deploying this needs a NEW rc image built from `feat/haproxy-upgrade`
(VERSION stays 2026.11.5 until then).
