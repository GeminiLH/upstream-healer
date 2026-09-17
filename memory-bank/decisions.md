# Decisions & Gotchas — Upstream Healer

> Last updated: 2026-09-16.

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
  - ⚠️ **Do NOT invent other ports.** `8929`/`89xx` are *not* GitLab ports —
    they are NPM ports and have nothing to do with this instance. Always use
    `:32769` for the GitLab Web/API. A session that "recalled" `8929` got
    connection-refused and wrongly concluded the API was unreachable.
  - The tokens (`GITLAB_READ_TOKEN`, `GITLAB_PIPELINE_TOKEN`) are in the
    git-ignored `.env.local` at repo root — load with `set -a; . ./.env.local`.
    `GITLAB_PIPELINE_TOKEN` is sufficient for all project-scoped pipeline/job
    reads; `GITLAB_READ_TOKEN` is a separate PAT.
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
- **pymysql error-shape trap (learned the hard way, 2026-09-16):** a
  cursor/connection-lifecycle misuse ("Cursor closed", "Not yet connected")
  is raised as a *str-args* `OperationalError` with **no numeric errno**,
  whereas a real SQL failure (missing column = 1364, unknown column = 1054,
  missing table = 1146, null-into-NOT-NULL = 1048) carries a numeric errno
  in `exc.args[0]`. Any retry/backoff logic that keys off `err_no` MUST also
  check the *string* form — otherwise lifecycle errors look "non-retryable"
  and the seeder silently gives up. This is exactly why the "Cursor closed"
  bug seeded 0 rows without an obvious trace.
- **NPM tables have NOT-NULL-with-no-default columns that must be explicitly
  supplied on INSERT** (strict mode; a NULL *also* fails these). On the live
  dev `jc21/nginx-proxy-manager` image the columns the current seeder
  **omits** are: `user.avatar` (the one that actually fires 1364),
  `proxy_host.advanced_config` + `proxy_host.meta`, and `certificate.meta`.
  (`user.roles` IS already supplied by the seed as `'["admin"]'` — do not list
  it as missing; but re-verify that JSON shape is what NPM expects.) The schema
  *changes between NPM image releases*, so prefer introspecting `SHOW COLUMNS`
  and auto-filling over hardcoding a fixed column list.

## Scanner / multi-subnet gotchas

- **NEVER assign `conf.iface = <name>` in the scapy path — use `srp(...,
  iface=...)` instead (fixed 2026-09-16).** A multi-subnet scapy sweep set
  `conf.iface` to the per-network egress (e.g. `"enp6s0"`). On scapy 2.6.1
  (pinned in `requirements.txt`), mutating the *global* `conf.iface` leaves
  `conf.route.default_iface` unset, so when scapy resolves a destination it
  does `int("enp6s0")` → `ValueError: "enp6s0" is not a valid numeric value`
  (emitted as `ERROR:`), which **aborts the entire sweep** — zero responders.
  Passing `iface=` per `srp` call keeps the default resolution path intact.
  Regression: `tests/test_scanner.py::TestRunScapyScan::test_per_sweep_failure_is_isolated`.
- **`run_scapy_scan` sweeps each subnet in its own try/except.** One subnet
  failing to sweep (route resolution, no route, permission) logs a warning and
  `continue`s — it no longer fails the whole multi-subnet run. (This is the
  same "one bad subnet must not kill the rest" principle as the arp-scan
  `(skipped ...)` notes.)
- **arp-scan note: a `/32` (or `/31`) is a *host*, not a network.** It has no
  usable broadcast, so it is not ARP-sweepable. `run_arp_scan` now emits a
  specific `(skipped <cidr>: single host, not an ARP-swept network — add its
  /24 ...)` note instead of the misleading "no local interface" (the interface
  is usually *present*; the address is just a single host). If a user added a
  specific IP (e.g. `192.168.70.0/32`) and expected a whole-LAN sweep, the real
  fix is to enter the `/24` (e.g. `192.168.70.0/24`).

## Seeder / NPM-sync bug history — RESOLVED vs CURRENT (verified live in dev)

Track these carefully; the failure mode has changed layer by layer. As of the
introspection fix (uncommitted WIP, 2026-09-16) **both** seeder bugs (#1 cursor
closed, #4 NOT-NULL 1364) are fixed in code; #4 awaits deploy + live
verification. The #2 (`protocol` 1054 in `npm.py`) needs re-verification and #3
is stale/disproven — do not re-implement.

1. ✅ **RESOLVED (commit `72dd82b`, live-confirmed 2026-09-16): "Cursor closed".**
   `_ensure_npm_defaults` originally ran its owner `INSERT` *after* the
   `SELECT user` `with conn.cursor()` block closed the cursor. pymysql raises
   closed-cursor misuse as a **str-args** `OperationalError` ("Cursor closed",
   "Not yet connected") — **no `errno`** — so the seeding retry loop (which
   only backed off on schema errnos + a few connection-marker strings) gave up
   after one attempt and seeded **zero** rows. The heal (not a symptom) is:
   (a) every statement now lives *inside* its `with conn.cursor()` block, and
   (b) the retry loop treats `"closed"` / `"not connected"` /
   `"not yet connected"` as transient. Regression: `tests/test_seed_dev.py
   TestCursorLifecycle` uses a faithful `_ClosingCursor`/`_ClosingConn` that
   raises "Cursor closed" post-`__exit__`; the buggy layout fails against it,
   the fixed layout seeds all 6 hosts.
2. ⚠️ **HISTORICAL (status: RE-VERIFY — may have been fixed in the WIP that
   later became part of the deployed build):** the earlier 1054
   (`"Unknown column 'protocol'"`) from `app/services/npm.py` `get_all_hosts`.
   ⚠️ Do NOT assume this is fixed just because the seeder progressed — the
   seeder writing rows and the healer's `get_all_hosts` reading them are
   *independent* code paths. Confirm `get_all_hosts`'s SELECT uses only real
   columns before trusting the diagnostic page.
3. ❌ **STALE / DISPROVEN — do NOT re-implement this.** The prior note
   "the `proxy_host` INSERT omits `owner_user_id`/`access_list_id`/
   `certificate_id` (NOT NULL) → cannot be null". That was a *previous*
   code state. The current `scripts/seed_dev.py` INSERT **already supplies all
   three** via an explicit column list (owner resolved from the NPM `user`
   table, access_list + certificate bootstrapped). The live DB confirms the
   seeder now gets *past* this INSERT. Do not re-add/rewrite these.
4. ✅ **FIXED (in code, uncommitted — awaiting deploy + live verification):**
   **1364, NOT-NULL with no default** — the *next* layer after the cursor fix.
   On the live dev NPM (`jc21/nginx-proxy-manager`), the seeder's **first**
   INSERT (`user` owner) failed with
   `(1364, "Field 'avatar' doesn't have a default value")` → seed gave up →
   `user`/`access_list`/`certificate`/`proxy_host` all stayed **0 rows** → the
   `:8787/diagnostic` page showed "No proxy hosts found". The real schema
   (introspected via `SHOW COLUMNS` on the live dev DB) has these
   NOT-NULL-with-no-default columns the seed **omitted** (the 1364 fires on
   `avatar` first, in definition order — the rest are the same class):
   - `user`: **`avatar`** (varchar(255)). (`roles` is supplied as `'["admin"]'` —
     unverified shape, not the cause of 1364.)
   - `proxy_host`: **`advanced_config`** (text), **`meta`** (longtext).
   - `certificate`: **`meta`** (longtext).
   - `access_list`: `meta` (longtext) — the seed already passes `"{}"`, so no
     change needed there.
   **The fix** (`scripts/seed_dev.py`, deployed): the seeder introspects each
   table via `SHOW COLUMNS` *before* its INSERT and auto-fills any
   NOT-NULL-with-no-default column the INSERT doesn't already supply, using
   `_KNOWN_COLUMNS_WITH_DEFAULTS` (`user.avatar=''`, `certificate.meta='{}'`,
   `proxy_host.advanced_config='{}'`+`meta='{}'`, `access_list.meta='{}'`),
   falling back to `""` for a truly unknown new column. This is robust against
   NPM renaming or adding required columns across image releases — the fill is
   derived from the live schema, not a hardcoded column list. 1364 is NOT
   treated as transient (a stable schema won't fix itself with time), so the
   pass fails fast rather than retrying ~30s. Regression:
   `tests/test_seed_dev.py TestSchemaIntrospection` (7 tests).

5. **FIXED + DEPLOYED — the full set of NPM schema blockers (resolved
   2026-09-16, live-verified against `192.168.86.38:3306`):** deploying the
   introspection fix surfaced *four more* schema blockers, one per deploy,
   because the seed is a per-table atomic pass and each INSERT fails the
   whole pass. All now fixed, committed, deployed, and **live-verified**
   (the seeder created all 6 proxy_host rows + owner + access_list +
   certificate; idempotent re-run reuses them; zero duplicates):
   - **1064 SQL syntax** — the owner-creation used
     `CREATE USER (email=…, password=…, realm=…)`, a *privileged* MySQL
     statement that does NOT accept an INSERT-style parenthesized column list
     (syntax error). It was also redundant (the `user` row is already
     INSERTed in the same transaction) — **removed** it.
   - **`No module named 'bcrypt'`** — `requirements.txt` lacked `bcrypt`, so
     the owner's password hash came back empty (no password login). **Added**
     `bcrypt==4.2.1`.
   - **1048 then 1292 on `certificate`** — the fallback cert (NPM's built-in
     id 0 is absent on a pristine sandbox; the seed creates its own) seeded
     `domain_names=NULL` (1048) then `expires_on=''` (1292). Live schema:
     `expires_on datetime NOT NULL`, `domain_names longtext NOT NULL CHECK
     (json_valid(domain_names))`, `meta longtext NOT NULL CHECK
     (json_valid(meta))`. **Fixed** to `domain_names="[]"` (valid JSON),
     `expires_on="2999-12-31 23:59:59"` (a `__sql__` datetime literal — not
     NULL and not `''`), `meta="{}"`.
   - **4025 on `proxy_host.domain_names`** — that column is ALSO
     `longtext CHECK (json_valid(domain_names))` (a JSON *array*, not a bare
     hostname). The seed passed the plain domain string. **Fixed** with
     `_proxy_host_domain()` (decode: `["host"]`→`host`, `"host"`→`host`,
     plain→as-is, malformed→as-is) for existing-row matching, and
     `json.dumps([domain])` for the INSERT.
   Regression: `TestSchemaIntrospection::test_fallback_certificate_…` (pins
   the cert values) + `TestProxyHostDomainJson` (pins the helper + the
   JSON-array INSERT shape). 117 tests pass, ruff clean.
   **Takeaway:** the dev NPM (`jc21/nginx-proxy-manager`) schema is stricter
   than the seed assumed in four places. The introscopic `_fills_for` +
   explicit JSON values now handle all of them, and the live-verified deploy
   is the ground truth (do not trust a bare value assumption again).
6. **Dev sandbox NPM DB state** (`nginx-db-1`): schema migrated, but `user`,
   `access_list`, `certificate` are **empty** (setup wizard never ran on the
   dev box). That is *expected* and is why the seeder must bootstrap a dev
   admin row; it is not the bug itself (see #4 for the real blocker). Direct
   SQL from this workstation works: `pymysql` → `192.168.86.38:3306`
   (user `proxymanager`, sandbox password — see compose defaults).

## UI / templates

- **Settings "add subnet" form: 3 fields + how they're used** (template
  `settings.html`; handler `app/main.py::add_subnet`). This is the form the
  2026-09-16 "widen + clarify" UI task touches. The three fields:
  - **Name** — free-text *friendly label* (shown in the subnets table and in the
    host/diagnostic subnet dropdowns). Not validated; any string.
  - **CIDR** — the **network** CIDR. Validated with
    `ipaddress.ip_network(cidr, strict=False)`; `strict=False` accepts
    non-zero host bits and normalises them (`192.168.70.5/24` →
    `192.168.70.0/24`). Must be a *network*, not a `/32` host (see
    "Scanner / multi-subnet gotchas" #5).
  - **Interface** — the *egress* NIC name (optional). **TRAP:** the old
    placeholder was the literal word `auto`, but a stored `interface="auto"`
    is treated as a *real* interface name at scan time and fails ("no such
    device")! **Blank/empty = auto** (the scanner picks the local iface that
    owns the CIDR via `get_default_subnets`). So the placeholder must read
    *leave blank for auto* (not `auto`), and the field should show the actual
    local interface names as examples. Valid values are `ip -o -4 addr` names
    (`enp6s0`, `eth0`, `en0`, …). Only set it when the subnet lives on a
    specific physical NIC that differs from the local one (VLAN/secondary NIC).

- **Widening a page = change *that page's* wrapper, not `<main>`.** `base.html`
  renders `<main class="max-w-6xl mx-auto …">`; each page then wraps its own
  content in a narrower `max-w-*` (`settings.html` + `host_form.html` =
  `max-w-xl` = 576px; `diagnostic.html` = none). The Settings page was stuck at
  `max-w-xl`; widening it to `max-w-3xl`/`4xl` is the whole fix. A Tailwind
  max-width is a *ceiling* — on a phone the content is `width:100%` + `px-4`
  padding, so one change gives "wider on desktop, full-width on a phone" with no
  media query. The form's `grid grid-cols-1 sm:grid-cols-4` already stacks to one
  column on phones, and the subnets table sits in `overflow-x-auto` (scrolls), so
  no phone-specific work is needed.

- **Templates use the Tailwind Play CDN** (in `base.html`: `<script
  src="https://cdn.tailwindcss.com">`), so *any* utility class renders — there is
  no build step / content-scan to update when adding classes. Theme is class-based
  dark mode (`.dark` on `<html>`, toggled in `base.html`). Form-control colours
  come from a global `<style>` block in `base.html` (forces white/slate-900 on
  `input[type=text]/[number]/[password]/[email]`, `select`, `textarea`).
