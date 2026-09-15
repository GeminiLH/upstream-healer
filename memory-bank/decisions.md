# Decisions & Gotchas — Upstream Healer

> Last updated: 2026-09-15.

## Design decisions

- **NPM MariaDB credentials via container env, not config**: `NPMClient`
  discovers DB credentials from the NPM container's environment
  (`printenv | grep DB_MYSQL_`) so secrets stay out of the healer repo and
  config files (see `app/services/npm.py` docstring). Credentials are cached
  per client instance.
- **Never restart NPM**: recovery ends with a graceful `nginx -s reload`
  only — other proxied sites must stay up.
- **Grace period before recovery** (default 10 min) so reboots/maintenance
  don't trigger false alerts.
- **Scan strategy**: prefer the `arp-scan` binary; fall back to scapy
  (LAN ARP request for the MAC) in `app/services/scanner.py`.
- **Host identity is MAC + port**, allowing the same MAC on multiple ports;
  duplicate pairs rejected (enforced in CLI + DB migration in
  `database._migrate_host_identity`).
- **SQLite stored-procedure-free migration**: table-rebuild pattern
  (`hosts_new` → rename) for schema changes, run in `init_db()`.
- **Dev vs prod compose**: `docker-compose.yml` = healer only (Pi prod);
  `docker-compose.dev.yml` = full stack incl. NPM + MariaDB + one-shot
  `seed` service, all on host networking (ARP scans need the LAN).
  Seeded `failtest` host is intentionally dead to exercise recovery end-to-end.
- **Seed retry logic**: MariaDB error codes indicating NPM is still
  migrating (`_MIGRATING_ERRNOS`) are retried up to `_SEED_RETRIES` times —
  first-attempt failure means "not finished yet", not "broken".

## Hard rules (user directives)

- **NEVER commit `upstream healer notes.txt`.** It is in `.gitignore`
  (line 28, "Sensitive local notes") and currently untracked. It holds live
  credentials (Telegram bot token, GitLab PATs, LAN IPs/MACs). Never
  `git add -f` it, never quote its contents, and keep it ignored.
- **GitLab is the primary repository.** All commits, pushes, and CI/pipeline
  work target the `gitlab` remote:
  `ssh://git@192.168.86.38:32768/monster/upstream_healer.git`
  (SSH host `192.168.86.38` port `32768`, project path `monster/upstream_healer`).
- **GitHub (`origin` → `git@github.com:GeminiLH/upstream-healer.git`) is
  legacy and can be ignored** in all workflows — but do **NOT** remove the
  remote, the GitHub repo, or any legacy GitHub-related files.
- **NPM is interacted with via `docker exec` — never via the web UI** (user
  directive, 2026-09-15). Relevant containers on the batcave box:
  `nginx-app-1` (NPM app: exec e.g. `printenv | grep DB_MYSQL_`, `nginx -t`,
  `nginx -s reload`) and `nginx-db-1` (MariaDB: exec `mysql proxy_manager`).
  The NPM web UI (`:8181`) is not reachable from this workstation, so from
  here the equivalents are direct MariaDB SQL over `:3306` and the manual
  `dev_debug` CI job for container state/log inspection.

## CI / pipeline verification (VERIFIED WORKING — 2026-07-09, re-verified 2026-09-15)

Access is in the repo-root **`.env.local`** file (git-ignored; loaded with
`set -a; . ./.env.local; set +a`). **Never commit it**, never print its values
in logs or the memory bank.
⚠️ Do NOT rename it back to `.env`: `Settings` (app/config.py) declares
`model_config = {"env_file": ".env"}` with pydantic's `extra="forbid"`, so any
foreign key in `.env` (like these tokens) breaks the app AND all test
collection with `ValidationError: extra_forbidden`.

- `GITLAB_READ_TOKEN` — fine-grained PAT (user `Cline_API`); verified for
  project, pipeline, and job reads.
- `GITLAB_PIPELINE_TOKEN` — fine-grained PAT; verified for pipeline/job reads
  (it lacks *user*-level scope, so `/api/v4/user` fails by design — use
  project-scoped endpoints). Intended for triggering/running jobs.
- **GitLab base URL (verified)**: `http://192.168.86.38:32769` (port map:
  32768→git-ssh, 32769→web-80, 32770→web-443; HTTPS 32770 not reachable from
  this dev host, use 32769).
- **Project id: 4** (`monster/upstream_healer`, default branch `main`).
- Verified endpoints (project id 4):
  - `GET  /api/v4/projects/4/pipelines?per_page=3` — latest pipelines
  - `GET  /api/v4/projects/4/pipelines/:id/jobs` — job statuses
  - `GET  /api/v4/projects/4/jobs/:id/trace` — job log output
  - `POST /api/v4/projects/4/pipelines/:id/retry` — re-run pipeline
- Pipeline stages (pipeline #36 on HEAD `0311e56e`, verified 2026-09-15):
  `lint`, `unit_tests`, `build_image` → `deploy_dev` → `dev_down` (all
  success); manual jobs: `deploy_test`, `deploy_production`, `dev_debug`.
- **Post-commit workflow**: push to `gitlab/main` → poll
  `GET /api/v4/projects/4/pipelines?ref=main&per_page=1` until `status` is a
  finished state (success/failed/canceled) → list jobs, report failures with
  `trace` → manual deploy jobs require explicit user confirmation before
  triggering.
- **Manual jobs can be triggered with the pipeline token** (verified
  2026-09-15, `dev_debug` job 638 → success):
  `POST /api/v4/projects/4/jobs/:id/play` with `GITLAB_PIPELINE_TOKEN`.
  Use `dev_debug` any time the dev stack misbehaves — it prints container
  states, restart/OOM/exit details, and 80-line log tails of `nginx-db-1`,
  `nginx-app-1`, `upstream-healer`.

## Gotchas

- `upstream healer notes.txt` contains **live secrets** (Telegram bot token,
  GitLab API/runner tokens) and ad-hoc LAN data. Do not quote it in code,
  tests, or docs.
- `.venv/` in the repo is a Windows venv — unusable on Linux; use system
  `python3` (deps installed globally) in this environment.
- `npm_db_path_in_container` (`/data/database.sqlite`) is a legacy default;
  NPM in the dev stack uses **MariaDB** (`nginx-db-1`), so the SQLite path is
  not where NPM stores state in dev.
- `docker exec nginx-app-1 sqlite3 /data/database.sqlite` fails in dev
  ("No such file or directory") for the same reason — query MariaDB instead.
- The seeder only creates a telegram channel when env vars
  `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_IDS` are set AND no channel exists yet;
  UI-configured channels are never touched.
- GitLab CI deploy jobs need `needs:optional` syntax for `unit_tests`
  (fixed in commits 4bbdfd7 / bbddb45) — preserve if editing CI.

## KNOWN BUGS — verified live in dev 2026-09-15 (via `dev_debug` job 638)

1. **`app/services/npm.py:256` — `get_all_hosts` SELECT is broken on the
   current NPM schema.** It selects `protocol`, `ssl_removed`,
   `client_body_buffer`, `proxy_buffer_size` — none of which exist. Error
   1054 (`"Unknown column 'protocol' in 'field list'"`), logged by the
   deployed healer. Real `proxy_host` columns (SHOW COLUMNS, MariaDB
   10.11): `id, created_on, modified_on, owner_user_id, is_deleted,
   domain_names, forward_host, forward_port, access_list_id, certificate_id,
   ssl_forced, caching_enabled, block_exploits, advanced_config, meta,
   allow_websocket_upgrade, http2_support, forward_scheme, enabled,
   locations, hsts_enabled, hsts_subdomains, trust_forwarded_proto`.
   Consequence: the healer's NPM host sync silently returns `[]`.
2. **`scripts/seed_dev.py:432` — the `proxy_host` INSERT omits
   `owner_user_id`, `access_list_id`, `certificate_id`** (all NOT NULL, no
   defaults) → seeding fails on a fresh NPM DB with "cannot be null", yet
   the seed container exits 0, so the DB is left with 0 proxy_host rows.
   Must supply these values (owner = a real `user` row).
3. **Dev sandbox NPM DB state** (`nginx-db-1`): schema migrated to
   20260131163528, but `user`, `access_list`, and `certificate` tables are
   **empty** — the NPM setup wizard was never completed on the dev box.
   Until then the NPM web UI shows the setup wizard, and seeder fixes must
   either bootstrap a dev admin row or tolerate this state. Direct SQL from
   this workstation works: `pymysql` → `192.168.86.38:3306`
   (user `proxymanager`, sandbox password — see compose defaults).
