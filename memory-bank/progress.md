# Progress — Upstream Healer

> Snapshot: 2026-09-16 (both seeder bugs fixed: `72dd82b` cursor fix + the new
> NOT-NULL introspection fix below. 114 tests pass, ruff clean. **Not yet
> deployed** — awaiting live verification on the pristine dev NPM.)
> **Verify before acting**: `git status`, `git log -5`,
> then run `python3 -m pytest tests/ -q`.

## Current state

- Branch: `main` (tracking `gitlab/main`).
- HEAD: `72dd82b` (fix(seed): keep NPM cursor statements inside the with-block;
  retry closed-cursor errors) — pushed to gitlab/main, deployed to dev
  (pipeline 140 → `deploy_dev` job 669 **success** 2026-09-16). That commit had
  **107 tests pass**, ruff clean.
- **Uncommitted WIP** (the second seeder fix — NOT-NULL introspection):
  `scripts/seed_dev.py` + `tests/test_seed_dev.py` + this memory-bank. Health:
  **114 tests pass** (was 107; +7 in `tests/test_seed_dev.py`
  `TestSchemaIntrospection`), **ruff clean** (`scripts/seed_dev.py` +
  `tests/test_seed_dev.py`).
- Dev stack on batcave is up; `:8787/diagnostic` reachable, `npm_available=True`.
- **🎉 SEEDING FULLY WORKS (deployed + live-verified 2026-09-16):** the seeder
  now creates all 6 proxy_host rows + owner + access_list + certificate in the
  live dev NPM DB, and links them in the healer SQLite DB. The
  `:8787/api/diagnostic` endpoint returns `npm_hosts: 6` (vault, jelly, none,
  plex, ha, portainer) with valid JSON `domain_names` / `advanced_config` /
  `meta`. **The 1364-error task is done.** Health: **117 tests pass**, ruff
  clean. (An early "0 hosts" reading right after deploy was a startup-timing
  artifact — `NPMClient.available` is cached `False` if the first query races
  NPM's boot; it becomes `True` and shows 6 within a minute. See the seeder
  failure-mode history below for the full 4-blocker resolution.)

- **🆕 Enhancement: on-demand ARP/scapy scan on the Diagnostic page (WIP, uncommitted — 2026-09-16).**
  Added a "Run a Scan" section to `/diagnostic`: pick a scanner (arp-scan/scapy) +
  a MAC (or click a known-host chip to prefill), run it, and see the raw output +
  found IP in a terminal panel.
  - `app/services/scanner.py`: new `run_arp_scan()` (sync, raw `arp-scan -l` table),
    `run_scapy_scan(target_mac)` (full ARP sweep table), and `run_scan(target_mac,
    method)` dispatcher that runs in a thread pool and returns
    `{method, found_ip, found_via, output, error}`. `_scan_with_arp_scan` /
    `_scan_with_scapy` are now thin async wrappers over these, so `find_ip_by_mac`
    (and the monitor) are unchanged. `arp-scan` (Dockerfile) + `scapy`
    (requirements) are already deps, so it works in the container.
  - `app/main.py`: `ScanRequest` Pydantic model + `POST /api/diagnostic/scan`;
    `/api/diagnostic` and `/diagnostic` now also return the SQLite `hosts` list
    (name/domain/mac/current_ip/port/enabled) so the UI can prefill + show chips.
  - `app/templates/diagnostic.html`: the Run-a-Scan UI + inline vanilla-JS `fetch`.
  - **Health: 128 tests pass (was 117; +11: 9 in `tests/test_scanner.py`, 2 in
    `tests/test_main.py`), ruff clean.** Not yet committed/deployed.

## The seeder failure modes — full history

1. ✅ **SOLVED & live-confirmed: "Cursor closed"** (the original bug, `72dd82b`).
   `_ensure_npm_defaults` ran the owner `INSERT` *after* the `SELECT user`
   `with conn.cursor()` block had closed the cursor → pymysql raised
   `Cursor closed` (a str-args OperationalError, **no errno**). The retry loop
   only backed off on schema errnos (1054/1146) + connection-marker strings, so
   it **gave up after 1 attempt** and seeded 0 rows. Fixed in `72dd82b`:
   statements moved inside their with-blocks; retry loop now also treats
   `"closed"` / `"not connected"` / `"not yet connected"` as transient.
2. ✅ **SOLVED (in code, awaiting deploy): NOT-NULL 1364.** After the cursor fix,
   the seeder died at the **`user` owner INSERT** with
   `(1364, "Field 'avatar' doesn't have a default value")` → seed gave up → all
   4 tables stayed empty. Root cause: NPM's stock sandbox never ran the setup
   wizard, so `user` is empty and the seeder must *create* the owner row, but
   its fixed INSERT omitted every NOT-NULL-with-no-default column the image
   added since the last release. Real schema (introspected via `SHOW COLUMNS` on
   the live dev DB, see `memory-bank/context.md`):
   - `user` requires `avatar` (NOT NULL, no default) — the seed didn't supply it.
   - `proxy_host` requires `advanced_config` + `meta` — the seed didn't supply them.
   - `certificate` requires `meta` — the seed already supplied `'{}'`, but
     `domain_names`/`expires_on` are nullable (NULL is fine, no 1048).
   - `access_list` requires `meta` — the seed already supplied `'{}'`.
   - `created_on`/`modified_on` (NOT NULL, no default) — handled by `NOW()` in
     the INSERT (not a column the seed omits).
   **Fix (uncommitted):** the seeder now introspects each table
   (`SHOW COLUMNS`) *before* its INSERT and auto-fills any NOT-NULL-with-no-
   default column the INSERT does not already supply, using
   `_KNOWN_COLUMNS_WITH_DEFAULTS` (`user.avatar=''`, `certificate.meta='{}'`,
   `proxy_host.advanced_config='{}'`+`meta='{}'`, `access_list.meta='{}'`),
   falling back to `""` for a truly unknown new column. This is robust against
   NPM renaming or adding required columns across image releases — the fill is
   derived from the live schema, not a hardcoded column list. 1364 is NOT
   treated as transient (a stable schema won't fix itself with time), so the
   pass fails fast rather than retrying ~30s.
   - ⚠️ RISK (unverified): the exact JSON shape of `roles` (`'["admin"]'`) and
     `advanced_config` (`'{}'`) is a guess. 1364 = "no default & no value", and
     the column accepts any non-NULL, so *some* valid value clears the error —
     but a malformed shape could break NPM's own parse later. Verify by running
     the seeder against the live dev DB (`:3306`, writable) and confirming the
     diagnostic page populates, **not** by trusting a bare value.


## Immediate next steps

1. **Deploy the introspection fix** (commit → push → GitLab pipeline →
   `deploy_dev`). The cursor fix is already live; this is the second half.
2. **Re-run the seeder against the live pristine dev NPM**
   (`192.168.86.38:3306`, user `proxymanager`, sandbox password) and confirm:
   - `user` now has 1 row (healer@example.com, roles `["admin"]`, avatar `""`).
   - `certificate` + `access_list` each have 1 row.
   - `proxy_host` has 6 rows (one per seed host: vault, jellyfin, failtest,
     plex, homeassistant, portainer).
   - `:8787/api/diagnostic` `npm_hosts` is non-empty and `hosts[*].npm_proxy_host_id`
     is populated.
   - If any column trips 1364 again, the pass now fails *loudly* (the
     `_missing_default_columns` check) rather than silently seeding 1364s —
     read the log to see which column.
3. If the `roles` shape is wrong (NPM's wizard uses `ADMINISTRATOR` not
   `admin` — verify by logging into the NPM UI or inspecting a wizard-created
   user), correct `_ensure_npm_defaults`'s `roles` value and re-run.
4. After green: confirm the diagnostic page renders, then this snapshot is
   current. No further seeder work expected.

## Live-verification recipe (no docker/SSH from this workstation)

- Dev stack status/logs: trigger the manual **`dev_debug`** job
  (`POST /api/v4/projects/4/jobs/<job_id>/play` with `GITLAB_PIPELINE_TOKEN`,
  find `<job_id>` from `GET /api/v4/projects/4/pipelines/<latest>/jobs`),
  then read its `trace` — it prints container states, restart/OOM/exit
  details, and 80-line log tails of `nginx-db-1`, `nginx-app-1`,
  `upstream-healer`.
- Direct DB checks: `pymysql` → `192.168.86.38:3306` (dev MariaDB
  `proxy_manager`; sandbox creds in `docker-compose.dev.yml` defaults).
- Re-run the seeder: `python3 scripts/seed_dev.py seed` (or the in-container
  equivalent) — it is idempotent; safe to re-run after a schema change.
- NPM interaction rule: `docker exec` on the batcave box — never the web UI
  (ports 8181/8182 are not reachable from the LAN).

## Conventions (keep these when editing)

- CLI: argparse subcommands; success → JSON to stdout; failure → message +
  non-zero exit.
- Timestamps: use `parse_timestamp`/`format_timestamp` from `app/config.py`.
- Never restart the NPM container; only `nginx -s reload`.
- Host identity = MAC + port (unique pair).
- Ruff: E+F, long lines allowed. Tests: pytest-asyncio auto mode.
- **Seeder introspection contract:** every INSERT in `seed_dev.py` must be
  preceded by a `_fills_for(conn, table, known)` call that introspects the
  table and auto-fills NOT-NULL-with-no-default columns not in `known`. If you
  add a new table or a new required column to an INSERT, add it to
  `_KNOWN_COLUMNS_WITH_DEFAULTS` (or the `known` set) so the introspection
  knows how to fill it.

