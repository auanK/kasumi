# Daemon HTTP API

The browser uses the daemon's HTTP API at `http://127.0.0.1:3137` by default. Local IPC clients discover their separate port from the private `daemon.control.json` in the Kasumi application data directory. Authenticated `GET /v1/status` includes `ipc_port` and `web_port`.

The [OpenAPI contract](api/openapi.yaml) describes every registered operation, request, response and event format.

## Listener and login

To change the browser address, port, or allowed proxy hosts, use the Web UI (**System -> Service -> Web UI & network access**), run `kasumi web listen <addr[:port]> [--allow-host <host>] [--skip-host-check | --no-skip-host-check]`, or create/edit `web.json` beside `config.toml` and restart the daemon. For example, the following configuration exposes the Web UI on all interfaces (`0.0.0.0:3137`, e.g. Tailscale/LAN servers) while also allowing a reverse proxy serving `kasumi.example` or `*.ts.net`.

```json
{
  "bind": "0.0.0.0",
  "port": 3137,
  "allowed_hosts": ["kasumi.example", "*.ts.net"],
  "skip_host_check": false
}
```

The browser listener accepts session cookies. The CLI uses a separate, dynamically assigned loopback IPC port with token authentication. Setting `"port": 0` selects a dynamic port (`0` on default loopback shares cleanly with IPC/discovery). When bound to `0.0.0.0` or `::`, direct IPv4/IPv6 literals in `Host` (including Tailscale `100.x.y.z` and LAN addresses) are automatically accepted; `allowed_hosts` also supports `*.domain` wildcard patterns, and `"skip_host_check": true` bypasses `Host` checks behind trusted reverse proxies. Configure the Web UI password on loopback (or via `kasumi web set-password`) before selecting a non-loopback bind address; remote access refuses to start if no password is configured. For HTTPS termination, preserve the public Host and have a loopback proxy overwrite `X-Forwarded-Proto` with `https`. Include the public port in `allowed_hosts` when the browser sends it.

Browser mutations with a body use `Content-Type: application/json`. Every browser mutation requires a matching `Origin` or `Referer`. After login, include the session cookie and an `X-CSRF-Token` header.

| Method and resource | Request and result |
| --- | --- |
| `GET /v1/auth/status` | Returns `configured`, `authenticated` and, for an authenticated browser, its `csrf_token`. |
| `POST /v1/auth/password` | First setup takes `bootstrap_token` from the owner-only `web-bootstrap.token` file, a `password` of at least 8 characters, and an optional `username` (defaults to `admin`). Subsequent changes take `current_password`, the new `password`, session authentication and an optional new `username`. A successful change revokes all sessions. |
| `POST /v1/auth/username` | Takes `current_password`, `username`, and session authentication (`X-CSRF-Token`). Updates the configured login username while keeping the current browser session active. |
| `POST /v1/auth/login` | Send the configured `username` and `password`. Returns the CSRF token and sets an HttpOnly, SameSite=Strict cookie (`Max-Age=2592000`). Failed attempts trigger progressive per-address backoff and HTTP 429. |
| `POST /v1/auth/logout` | Revokes the current session and clears its cookie. |

The daemon stores a randomly salted Argon2id verifier in the private `web-password.json` file. Sessions expire after 7 days of inactivity or 30 days total and their hashed records are persisted in the owner-only `web-sessions.json` file across daemon restarts. Explicit logout (`POST /v1/auth/logout`) and password changes revoke all persisted sessions and clear the cookie. Restarting the daemon still rotates any outstanding `web-bootstrap.token`.

## Status and events

The existing `/v1/status`, `/v1/events`, `/v1/sync`, `/v1/pause`, `/v1/resume`, `/v1/unlock`, `/v1/lock`, `/v1/cancel`, `/v1/reload` and `/v1/stop` routes also accept browser authentication. A browser unlock sends the profile name in `profile` with its credentials in the JSON body. A credential input consists of either a 64-digit hexadecimal `master_key` or a `password` and `salt_password` pair.

| Method and resource | Result |
| --- | --- |
| `GET /v1/events/stream` | Server-sent events. `log` events carry a sequence ID, timestamp, kind, profile name and detail. `status` events supply profile progress and job snapshots. Use `Last-Event-ID` or `?since=` to resume from the live ring. |
| `GET /v1/logs` | Reads current and rotated logs. Optional `profile`, `lines` (1–1000) and `full=false` select the profile, history length and omission of detail. |
| `POST /v1/autostart` | Send `enabled: true` or `false`. Updates user-session autostart and returns the resulting status. |
| `GET /v1/web/config` | Returns configured `bind`, `port`, live `active_port`, `allowed_hosts`, and `skip_host_check`. |
| `PATCH /v1/web/config` | Updates `bind`, `port`, `allowed_hosts`, and/or `skip_host_check` in `web.json` (fails closed on non-loopback bind without a configured password) and returns `restart_required: true`. |
| `GET /v1/diagnostics` and `GET /v1/diagnostics/{profile}` | Local health, daemon, storage, rclone and ignore-file diagnostics. |

## Profiles

| Method and resource | Request and result |
| --- | --- |
| `GET /v1/profiles` and `GET /v1/profiles/{name}` | Full profile configuration, local state, activity and daemon status. |
| `POST /v1/profiles` | Send `name`, `local_dir`, `remote_dir`, credentials, optional `key_storage` and profile settings. `verify: true` checks the remote before saving the profile. |
| `PATCH /v1/profiles/{name}` | Change local or remote paths, retention, watch, pause, sync interval, bandwidth, concurrency or rclone configuration using the field names returned by GET. A concurrent update returns 409. |
| `POST /v1/profiles/{name}/clone` or `/rename` | Send the destination `name`. A clone starts paused. |
| `POST /v1/profiles/{name}/storage` | Set `key_storage` to `vault`, `file` or `memory`. Supply the key through the key endpoint when switching to a new persistent store. |
| `POST /v1/profiles/{name}/key` | Supply credentials. Set `replace: true` to replace an existing different key. |
| `DELETE /v1/profiles/{name}` | Requires `confirm: true` in the body. The synchronized directory is preserved. |
| `POST /v1/profiles/{name}/test` | Tests the configured remote and returns its readiness and authentication state. |
| `GET /v1/rclone/remotes` | Lists locally configured rclone remotes. |
| `POST /v1/profiles/{name}/ignore/check` | Send a `paths` array. Each item includes its disposition and matching rule. |
| `POST /v1/profiles/{name}/ignore/init` | Accepts `preset` (default, dev, office or minimal), `dry_run` and `force`. |

## Remote explorer

All resources below are relative to `/v1/remote/{profile}/`. Supply logical file paths as URL-encoded UTF-8 query values.

| Method and resource | Request and result |
| --- | --- |
| `GET summary` | History, shared activities and physical content sizes in bytes for the current tree, retained history and orphans. `unknown_sizes` counts objects without size metadata. |
| `GET heads`, `GET commits`, `GET commits/{id}` | Logical heads, reachable commits with parents and authorship, or one commit with its physical variants. |
| `GET tree` | Optional `head` or `commit` selects a revision. Optional `prefix` selects a subtree. Multiple heads require an explicit selection. |
| `GET stat`, `GET log` | Send `path`. Stat optionally accepts `commit` and includes the pack hash or ordered chunks when applicable. Log returns the file's history. |
| `GET diff` | Send `from` and `to` commit IDs for tree changes. Add `path` for side-by-side text up to 1 MiB per revision. A missing side is null. |
| `GET download` | Send `path` and optional `commit`. A single HTTP bytes range, including suffix and open-ended ranges, returns 206. Chunked reads authenticate only the overlapping chunks. |
| `POST restore` | Send `dst`, optional `prefix` and `commit`. Defaults to `dry_run: true`. |
| `GET objects`, `GET orphans`, `GET writers`, `GET epochs`, `GET health` | Physical inventory, orphan candidates, writers and barriers, retention epochs and vault health. |

## Conflicts and jobs

| Method and resource | Request and result |
| --- | --- |
| `GET /v1/conflicts/{profile}` | Lists canonical paths and their preserved artifacts. |
| `GET /v1/conflicts/{profile}/diff` | Send canonical `path` and the full listed `artifact` path. Returns up to 1 MiB per side as hex, original sizes and truncation flags. |
| `POST /v1/conflicts/{profile}/resolve` | Send `path`, `choice` (`keep_canonical` or `keep_artifact`), optional `artifact` and `dry_run`. |
| `POST /v1/profiles/{name}/preview` | Starts a read-only status preview. |
| `POST /v1/maintenance/{profile}/{operation}` | Starts `fsck`, `gc`, `repack` or `resolve-missing`. GC supports `min_age_hours` and repack supports `reclaim_dirty`. Mutating operations default to dry-run. Send `dry_run: false` and `confirm: true` to execute. |
| `POST /v1/maintenance/{profile}/sync` | Queues a sync with optional `initial`, `repair`, `audit_inventory`, `allow_empty_local`, `bandwidth_limit` and `transfer_concurrency`. The job result includes sync counters and the inventory audit when requested. |
| `POST /v1/maintenance/{profile}/remove-writer` | Send the `writer_id` returned by remote writers inspection. Queues removal of that marker. |
| `POST /v1/maintenance/{profile}/remove-barrier` | Requires `confirm_abandoned: true`. Send the `barrier_id` returned by remote writers inspection to select an explicit marker. Omitting the ID uses the CLI's selection rules. |
| `GET /v1/jobs/{id}` | Returns the job state, latest progress and final result or error. |

Job submissions return HTTP 202 with an ID and a `Location` header. The daemon accepts one active job per profile and up to four overall. It keeps the latest 64 job records in memory. Clients can follow progress in the SSE status events and fetch the final result using the job ID.
