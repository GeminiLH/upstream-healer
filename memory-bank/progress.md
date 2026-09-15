# Progress — Upstream Healer

> Snapshot: 2026-09-15 (after live dev-stack verification via the `dev_debug`
> CI job — found 2 real bugs, see decisions.md "KNOWN BUGS").
> **Verify before acting**: `git status`, `git log -5`,
> then run `python3 -m pytest tests/ -q`.

## Current state

- Branch: `main` (tracking `gitlab/main`; also pushed to `origin`/GitHub).
- HEAD: `0311e56e` (memory-bank commit; pipeline #36 on gitlab/main —
  lint / unit_tests / build_image / deploy_dev / dev_down all **success**,
  verified 2026-09-15). Prior: `cb09b16` tests fix.
- Health (verified this snapshot): **105 tests pass**; **ruff clean**
  (`python3 -m ruff check app/ scripts/ tests/` → all checks passed).
  The F541 at `app/cli.py:243` (stray `f` prefix in `check-npm-db`) was
  fixed with `ruff check --fix` — the fix lives inside the uncommitted
  `app/cli.py` WIP.
- Dev stack on batcave (verified via `dev_debug` job 638): all containers
  up, 0 restarts, no OOM. **But see KNOWN BUGS below** — the deployed
  healer's NPM sync and the dev seeder are both broken on the current
  schema.
- Working tree has **uncommitted WIP** (4 files, +546/−334):

```
M app/cli.py            (large: +823/−...)  new CLI subcommands + check-npm-db diagnostic
M app/main.py           diagnostic endpoints logging + SQLite host comparison
M app/services/npm.py   diagnostic logging in get_all_hosts / cred caching
M scripts/seed_dev.py   verbose logging of seed + proxy_host link flow
```

## Uncommitted WIP details

### `app/cli.py` — new admin commands + diagnostic
- `check-npm-db`: multi-step diagnostic (Docker daemon → NPM container →
  DB credentials via `exec_run("printenv | grep DB_MYSQL_")` → proxy host rows).
- `list-events`: `--host-id`, `--limit`, `--days` (both ≥ 1), joins `hosts`
  for names, time-filtered by `parse_timestamp`.
- `disable-host HOST_ID`: sets `enabled = 0`, errors if not found.
- `add-telegram --name --bot-token --chat-ids` (comma list): inserts channel
  **enabled** and one `notification_rules` row per `EVENT_TYPES`.
- `list-telegram`, `disable-telegram CHANNEL_ID`.
- (Fixed 2026-07-09) F541 at line 243 — stray `f` prefix removed via `ruff --fix`.

### `app/main.py` — diagnostic instrumentation
- `/diagnostic` + `/api/diagnostic` now log steps and also fetch
  `SELECT name, domain, npm_proxy_host_id FROM hosts` for on-page comparison
  between NPM and SQLite host state.

### `app/services/npm.py` — logging only
- `get_all_hosts()`: logs row count + per-host `domain/forward` lines;
  exceptions now logged with `exc_info=True` (was `logger.warning`).
- Credential cache hit logs at debug.

### `scripts/seed_dev.py` — troubleshooting logging
- Verbose logs of: settings (db_path, npm_db_*), seed host count, each
  proxy_host seeding attempt, `_wait_for_mysql` outcome, and a post-apply
  verification dump of all hosts + their `npm_proxy_host_id`.

## Test expectations (from recent commits)

Recent `fix(tests)` commits (b8a6bb1, 0aace39, cb09b16) updated
`tests/test_seed_dev.py` / related for the **6-host** seed set:
5 hosts linked to NPM proxy_host ids; hosts include plex, homeassistant,
portainer (plus vault, jellyfin, failtest). `insert_ids` and states counts
were updated to match.

## Immediate next steps

1. ~~Ruff F541~~ — done 2026-07-09 (`ruff check --fix app/cli.py`); lint is clean.
2. **Fix the two KNOWN BUGS** (decisions.md):
   a. `app/services/npm.py:256` — rewrite the `get_all_hosts` SELECT to real
      columns (`forward_scheme`, `ssl_forced`, `http2_support`,
      `advanced_config`, …); update any tests asserting the old column names.
   b. `scripts/seed_dev.py:432` — the `proxy_host` INSERT must supply
      `owner_user_id`, `access_list_id`, `certificate_id` (resolve from the
      NPM `user`/`access_list`/`certificate` tables, or bootstrap the dev
      admin row first — those tables are empty in the sandbox because the
      NPM setup wizard was never completed there).
3. After the fixes: push to `gitlab/main`, let `deploy_dev` run, then
   re-trigger `dev_debug` and confirm the healer logs show real proxy_host
   rows instead of the 1054 error.
4. Review/trim the WIP diagnostic logging — some of it (per-row host logs)
   is noisy for production; consider demoting to debug.
5. Commit the WIP in logical pieces (CLI commands; diagnostic logging) once
   verified, then push to `gitlab/main`.
6. Optional: document `check-npm-db` in README under "Docker exec administration".

## Live-verification recipe (no docker/SSH from this workstation)

- Dev stack status/logs: trigger the manual **`dev_debug`** job
  (`POST /api/v4/projects/4/jobs/<job_id>/play` with `GITLAB_PIPELINE_TOKEN`,
  find `<job_id>` from `GET /api/v4/projects/4/pipelines/<latest>/jobs`),
  then read its `trace` — it prints container states, restart/OOM/exit
  details, and 80-line log tails of `nginx-db-1`, `nginx-app-1`,
  `upstream-healer`.
- Direct DB checks: `pymysql` → `192.168.86.38:3306` (dev MariaDB
  `proxy_manager`; sandbox creds in `docker-compose.dev.yml` defaults).
- NPM interaction rule: `docker exec` on the batcave box — never the web UI
  (ports 8181/8182 are not reachable from the LAN).

## Conventions (keep these when editing)

- CLI: argparse subcommands; success → JSON to stdout; failure → message +
  non-zero exit.
- Timestamps: use `parse_timestamp`/`format_timestamp` from `app/config.py`.
- Never restart the NPM container; only `nginx -s reload`.
- Host identity = MAC + port (unique pair).
- Ruff: E+F, long lines allowed. Tests: pytest-asyncio auto mode.
