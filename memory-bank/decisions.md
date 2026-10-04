# Decisions & Gotchas — Upstream Healer

> Last updated: 2026-09-23.

## Design decisions

- **`ip_network(..., strict=False)` is required when normalising a host address to
  its /24** (2026-09-23, "populate from NPM" subnet fallback): `main.py::_subnet_for_ip`
  falls back to the proxy host's own /24 when no known subnet contains its
  `forward_host`. The first draft used `ipaddress.ip_network((addr, 24))`, which
  defaults to `strict=True` and **raises `ValueError: …/24 has host bits set`** for
  a real host address (e.g. `192.168.86.249`) — the /24 of a host is never a
  canonical network address. Use `ip_network((str(addr), 24), strict=False)` so it
  normalises to `192.168.86.0/24`. The "contains" test loop above it already passes
  `strict=False` for the same reason. Caught by
  `test_subnet_for_ip_falls_back_to_24_when_unknown` + `test_form_offers_populate_from_npm`.

- **nmap 7.93 has no `-oJ` — service probes use `-oX -` (XML to stdout)**
  (2026-09-22, "validate flash" bug): the batcave nmap 7.93 build (Debian
  trixie, python:3.12-slim image) has NO JSON output — `nmap.cc` contains no
  "json" and no `oJ` long-option. GNU getopt long-*only* matching is what
  makes `-oX`/`-oG` work as a single argv element: the whole remainder
  matches a long entry (`{"oX", required_argument}`) and the NEXT element is
  its filename — that is why the L3 sweeps' `-oG -` always worked. `-oJ`
  matches no long entry, so it falls to the deprecated short `-o` in the
  optstring (`o:` = argument from the same word): `J` is eaten as a
  *filename* and the intended output argument lands in the *target* list —
  `-oJ -` → "Failed to resolve '-'" (+ a UDP-only scan warning, rc 0, zero
  results); `-oJ <tmpfile>` → "Unable to split netmask from target
  expression: '/tmp/uh-services-…'". The service probe is therefore
  `nmap -Pn -sT -sU -sV -T4 --open -p <spec> -oX - <ip>`: an explicit `-sT`
  (connect scan, no raw-socket privilege) silences the "no TCP scan type"
  warning, `-oX -` is the same proven idiom, and
  `parse_nmap_services_xml()` (stdlib ElementTree, never raises) reads the
  XML from stdout. **Never put `-oJ` in an nmap command.** Verified live
  from the batcave diag log 2026-09-22 (rc 0, clean XML, stderr empty).

- **Validate flow writes diag logs too; `validate-host` CLI added**
  (2026-09-22): `POST /hosts/{id}/validate` is wrapped in
  `diag_log.scan_context(method="validate")`, so `run_service_scan` records
  the exact nmap cmd + rc + raw stdout/stderr in the per-run file (dev-only:
  `UPSTREAM_HEALER_DEBUG_LOG_DIR` is unset in the base compose → prod stays
  silent; the sandbox logs are readable via `scripts/batcave_logs.sh`).
  `app/cli.py` gained `validate-host --name --mac --ip --port
  [--subnet CIDR ...]` for `docker exec upstream-healer python -m app.cli
  validate-host ...` — log-only, JSON to stdout, defaults to every enabled
  subnet. Note `scan_context` is a *sync* `@contextmanager` — `with`, not
  `async with`.

- **ship.sh waits for `manual` before playing deploy_dev** (2026-09-22):
  straight after the auto jobs finish, the deploy_dev job can still be
  `pending`; POST `/play` on a pending job returns HTTP 400 "Unplayable Job"
  and the old ship.sh exited leaving the pipeline un-deployed (bit us
  2026-09-22). The play step now polls the job until `manual` (5 s cadence,
  5 min cap) before the play POST.


- **Scanner worker-thread logging: dispatch via `asyncio.to_thread`, NOT a bare
  `run_in_executor`** (2026-09-21): On Python 3.12 (the dev image)
  `loop.run_in_executor(None, fn)` does **not** copy the `ContextVar` into the
  worker thread, so every `diag_log.emit/proc/exc` inside the sweep thread
  silently no-oped and the per-scan file came back with only the event-loop-side
  lines (an "empty" sweep — this was the batcave/flash debug-log bug). `run_scan`
  now dispatches scapy/nmap/arp-scan via `asyncio.to_thread` (which copies the
  running context), so worker-side lines land. 3.13+ happens to *also* propagate
  into the executor, which is why it regressed invisibly whenever dev ran 3.13 —
  it only bites on the 3.12 image. Added a `diag_log.copy_context()` helper
  documenting the manual `ctx.run` alternative. The regression test drives the
  *real* `run_scan` dispatch — the earlier wiring test called `_run_sweeps`
  in-thread, so it could never catch this.

- **nmap scan is per-CIDR resilient** (2026-09-21): a probe failure on *one*
  subnet no longer aborts the whole sweep — the failed CIDR is noted in `error`
  and the other subnets are still swept. `error` is set only when *every* subnet
  failed, or names the failed one(s) on a partial sweep. Also logs nmap stderr on
  a non-zero rc. On batcave this is what the phantom `192.168.70.0/24` (routed,
  flash side) was doing: its `nmap -sn` failed and the old code returned 0 hosts,
  discarding the ~16 on `192.168.86.0/24`. Now the self/flash nmap scan returns
  the 86.0/24 hosts (incl. flash) with `error` naming `192.168.70.0/24`.

- **Routed/tunnel `nmap -sn` sweeps fast-bail** (2026-09-21, "Fix C"): the
  per-CIDR isolation above *survives* a failed subnet, but the routed `nmap -sn`
  was the failure *source* — on a blackholed gateway it can't ARP, so it fires
  unicast ICMP/TCP pings and every dead host burns its probe+retry window (3
  retries by default); a dead `/24` then hit the 120 s wall and set a scary
  top-level `error="nmap failed on …"`. `_l3_alive_nmap` is now
  classification-aware: routed/tunnel subnets sweep a **single probe round**
  (`--max-retries 0 --host-timeout 3s`, 30 s wall cap) so a dead gateway *finishes
  fast with zero hosts* (→ no failure, no error); directly-attached/broadcast keeps
  the old `--host-timeout 5s` + 120 s cap (a real ARP LAN sweep ≈45 s needs the
  room). Complements the per-CIDR isolation above.

- **Scan debug logging: opt-in, file-based, dev-only** (2026-09-20):
  `app/services/diag_log.py` — one log file per diagnostic scan
  (`/api/diagnostic/scan` wraps its body in `scan_context`), recording the
  machine's own hostname/IPs/MACs, a **WARNING when the target is the
  scanning machine itself** (a host never answers its own ARP/ICMP
  broadcasts — "no match on self" is partly *expected* protocol behaviour),
  per-sweep classification + egress, exact tool commands + raw
  stdout/stderr, exception tails. Gated by `UPSTREAM_HEALER_DEBUG_LOG_DIR`
  (unset = fully off); `UPSTREAM_HEALER_ENV=production` tripwire; size cap
  + rotation; never raises (10 tests). `docker-compose.dev.yml` sets it to
  `/logs` + mounts `/mnt/data/upstream-healer/logs`; the base compose file
  is untouched so test/prod stay silent. Emits live in the scanner at:
  plans, `_run_sweeps`, `run_scapy_scan`, `run_l3_probe`, `_l3_alive_*`,
  `run_nmap_scan`, `run_scan`.
- **batcave + flash are seeded disabled** (2026-09-20; seed renamed `fash` →
  `flash` in `4299a52`): real lab devices for
  positive diagnostic tests (batcave = the sandbox box, MAC b4:2e:99:e9:80:fc;
  flash = dc:a6:32:02:59:63). Seeded `enabled=0` with no domain: their names
  appear in scan results (curated-name priority), but the monitor/recovery
  flow never touches them (no `host_state` row, no NPM proxy). `seed_hosts`
  now honours an `enabled` key (default 1).

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
- **mDNS hostname resolution + a persistent per-MAC name cache** (`10d12fa` +
  `fa191e2`): the diagnostic scan resolves real hostnames in a layered chain,
  highest first — a monitored host's curated DB name → a live mDNS/avahi name
  (`app/services/mdns.py`, a `zeroconf` browse with an **8 s window** run
  *concurrently* with the ARP sweep) → a **persistent per-MAC `mdns_names`
  cache** → reverse-DNS PTR. The browse is *racy* (a quiet device may not answer
  in the window), so the cache makes naming **monotonic**: names only add/update,
  never vanish — a name disappears only when the device is absent from *that* ARP
  sweep. `apply_hostnames` sorts named-first so the table stays visually stable.
  `zeroconf==0.151.3`; the browse degrades to empty maps (never raises) if mDNS is
  unavailable, so a scan is never blocked by name lookup.
- **Tunnel/routed subnets need Layer-3 discovery, not an ARP broadcast** (see
  `app/services/scanner.py::classify_subnet` / `is_tunnel_interface`): a real NIC
  carries the kernel `BROADCAST` flag → an ARP *broadcast* sweep reaches the hosts
  and returns their true MACs. A WireGuard/`tun*`/`gre*` egress is point-to-point
  (no `BROADCAST`) and a gateway-routed subnet is not locally attached → an ARP
  broadcast reaches only the one tunnel peer, so every host would falsely show
  that peer's MAC. Such subnets are swept at **Layer 3** instead: `run_l3_probe`
  tries **scapy ICMP echo** first, then **`nmap -sn`**, then a parallel **`ping`**
  sweep, and emits `--` for the (unresolvable) source MAC; the UI shows a
  **routed** badge. `nmap` is a selectable diagnostic method (`run_nmap_scan`) and
  is in the Dockerfile. **`_l3_alive_nmap` parses `nmap -sn -oG -`** (grepable
  `Host: <ip> (…) Status: up` lines), NOT the human-readable banner — the original
  regex didn't match real output and would have found nothing. `ip` (iproute2) may
  be absent (Windows dev box) → `is_tunnel_interface` falls back to a name
  heuristic; callers pass already-fetched `flags` in to avoid a second `ip -o link`
  round-trip.

## Tooling gotchas (this NFS workstation)

- **`read_files` returned a stale snapshot** of `tests/test_scanner.py` in a prior
  session (wrong docstring/imports/line numbers vs. the file on disk). When a read
  looks inconsistent with an edit/pytest result, **get ground truth from the
  shell**: `sed -n 'A,Bp' <file>`, `grep -n …`, `wc -l`.
- **`run_commands`** takes a `commands` **array of plain strings** (e.g.
  `["python3 -m pytest tests/ -q"]`); passing `{"cmd": "…"}` objects is rejected
  with "Invalid input".
- The repo `.venv` is a **Windows venv** (unusable here) — use the system
  `python3` (3.13, deps installed globally).

## Hard rules (user directives)

- **NEVER commit `upstream healer notes.txt`.** It is in `.gitignore`
  (line 28, "Sensitive local notes") and currently untracked. It holds live
  credentials (Telegram bot token, GitLab PATs, LAN IPs/MACs). Never
  `git add -f` it, never quote its contents, and keep it ignored.
- **GitLab is the primary repository** — the only active remote. All commits,
  pushes, and CI/pipeline work target the `gitlab` remote:
  `ssh://git@192.168.86.38:32768/monster/upstream_healer.git`
  (SSH host `192.168.86.38` port `32768`, project path `monster/upstream_healer`).
  Push **explicitly** — `git push gitlab main` — and never rely on a bare
  `git push` or the local branch's upstream, which can silently point at the
  legacy `origin` remote. CI is GitLab CI (`.gitlab-ci.yml`) on the same
  instance (Web/API `http://192.168.86.38:32769`, project id 4).
- **GitHub (`origin` → `git@github.com:GeminiLH/upstream-healer.git`) is a
  legacy mirror and can be ignored** in all workflows. Beware that it carries
  the *default* remote name `origin`, which is easy to mistake for the primary
  remote — but do **NOT** remove the remote, the GitHub repo, or any legacy
  GitHub-related files.
- **NPM is interacted with via `docker exec` — never via the web UI** (user
  directive, 2026-09-15). Relevant containers on the batcave box:
  `nginx-app-1` (NPM app: exec e.g. `printenv | grep DB_MYSQL_`, `nginx -t`,
  `nginx -s reload`) and `nginx-db-1` (MariaDB: exec `mysql proxy_manager`).
  The NPM web UI (`:8181`) is not reachable from this workstation, so from
  here the equivalents are direct MariaDB SQL over `:3306` and the manual
  `dev_debug` CI job for container state/log inspection.

## CI / pipeline verification (VERIFIED WORKING — 2026-07-09, re-verified 2026-09-15 + 2026-09-19)

Use the **`gitlab-read`** and **`gitlab-pipelines`** MCP tools for all
GitLab API interactions. They are pre-configured with the necessary tokens
and scopes. **Never hand-roll curl calls to GitLab.**

- `gitlab-read` — read pipelines, jobs, traces, artifacts, etc.
- `gitlab-pipelines` — create pipelines, trigger/play manual jobs, deploy, etc.
- Legacy: `ship.sh` still uses direct curl + env vars from `.env.local` —
  this script is for CI/local use. Prefer MCP tools for agent-driven work.

- **GitLab base URL (verified)**: `http://192.168.86.38:32769` (port map:
  32768→git-ssh, 32769→web-80, 32770→web-443; HTTPS 32770 not reachable from
  this dev host, use 32769).
  - ⚠️ **Do NOT invent other ports.** `8929`/`89xx` are *not* GitLab ports —
    they are NPM ports and have nothing to do with this instance. Always use
    `:32769` for the GitLab Web/API. A session that "recalled" `8929` got
    connection-refused and wrongly concluded the API was unreachable.
- **Project id: 4** (`monster/upstream_healer`, default branch `main`).
- Verified endpoints (project id 4):
  - `GET  /api/v4/projects/4/pipelines?per_page=3` — latest pipelines
  - `GET  /api/v4/projects/4/pipelines/:id/jobs` — job statuses
  - `GET  /api/v4/projects/4/jobs/:id/trace` — job log output (plain text with
    ANSI/`00O`-style prefixes; works with **both** tokens — re-verified
    2026-09-20 on job 976, 59 KB). ⚠️ On this instance (gitlab-runner 19.3.1)
    the *newer* alias `…/jobs/:id/log` **404s with both tokens** — use `/trace`.
  - `GET  /api/v4/projects/4/jobs/:id/artifacts` — the job's artifacts zip
    (`unit_tests` uploads `test-results.xml` JUnit `when: always`); a compact
    source of "which test failed + message" when the trace is huge
    (verified 2026-09-20).
  - `POST /api/v4/projects/4/pipelines/:id/retry` — re-run pipeline
  - `POST /api/v4/projects/4/jobs/:id/play` — trigger a *manual* job (this is how
    `deploy_dev` is run from the sandbox). Verified 2026-09-19 (jobs 947/955).
    Needs the *pipeline* token — the read token → 403 `insufficient_scope`.
- Pipeline stages (pipeline #36 on HEAD `0311e56e`, verified 2026-09-15):
  `lint`, `unit_tests`, `build_image` → `deploy_dev` → `dev_down` (all
  success); manual jobs: `deploy_test`, `deploy_production`, `dev_debug`.
- **Fast ship workflow — use `scripts/ship.sh` (2026-09-17):**
  `scripts/ship.sh -m "<msg>" [paths...]` runs pytest + ruff (fail fast) →
  commit → `git push gitlab HEAD:main` → waits for the auto jobs
  (`lint` / `unit_tests` / `build_image`, 10s cadence) → **plays
  `deploy_dev`** (sandbox dev box, safe by default; `--no-deploy` to stop
  after the green auto jobs) → reports with a trace tail on any failure.
  Total wall time ≈ 6 min. Invoke as `bash scripts/ship.sh …` (chmod is
  blocked on the NFS share). Runs fully non-interactive (all git guard
  env/flags from the gotchas below are baked in).
  - ⚠️ **Poll the JOBS, never the pipeline status, to detect "auto done":**
    with the pending manual jobs (`deploy_test` / `deploy_production` /
    `dev_down` / `dev_debug`) the pipeline status sticks at `manual`
    *forever* — a "wait until finished" poller spins indefinitely (cost
    ~20 min in one session, 2026-09-17).
  - `deploy_test` / `deploy_production` remain **manual + explicit user
    confirmation only** — the ship script never touches them.
  - Token: Use the **`gitlab-pipelines`** MCP tool to trigger manual jobs
    (`deploy_dev`, `dev_debug`, etc.). The MCP tool is pre-configured with
    the correct token scope for playing jobs.
- **Manual jobs can be triggered via the `gitlab-pipelines` MCP tool** (verified
  2026-09-15, `dev_debug` job 638 → success).
  Use `dev_debug` any time the dev stack misbehaves — it prints container
  states, restart/OOM/exit details, and 80-line log tails of `nginx-db-1`,
  `nginx-app-1`, `upstream-healer`.

## Gotchas

- **GitLab job lists can be empty right after pipeline creation — never trust
  a vacuous "all green"** (2026-09-22, `6a43c07`): `GET /projects/:id/
  pipelines/:pid/jobs` returns `[]` for a just-created pipeline (job rows are
  populated lazily). ship.sh's step-4 snippet then passed every check over an
  *empty* auto-jobs list (`no failures` + `any(pending…)` is False on `[]`)
  and printed `READY ` with an **empty** deploy_dev id → step 5 silently
  skipped the deploy while printing success ("auto jobs green" at 19 s).
  Now: `len(auto) < 3` → `WARMUP` (re-poll), and a missing `deploy_dev` id
  → `WARMUP` instead of an empty id. Any "poll until green" logic against
  this API must treat *incomplete* data as "not ready", and any silent skip
  of a deploy step is a bug — fail loudly instead.
- `upstream healer notes.txt` contains **live secrets** (Telegram bot token,
  GitLab API/runner tokens) and ad-hoc LAN data. Do not quote it in code,
  tests, or docs.
- `.venv/` in the repo is a Windows venv — unusable on Linux; use system
  `python3` (deps installed globally) in this environment.
- **NFS mount breaks `git` metadata writes (2026-09-17):** the checkout is
  owned by `nfsnobody` while this workstation runs as uid 1000, so git's
  lock-file `chmod` fails ("Operation not permitted") and `.git/config`
  updates **silently do not persist** — e.g. `git branch -u gitlab/main main`
  printed "set up to track" but the config still pointed at `origin`. The
  config *is* mode 777, so the workaround is to edit `.git/config` directly
  (editor/`sed`) and verify with `git branch -vv`. Read-only git commands and
  `git fetch` work fine (SSH to gitlab is key-auth, non-interactive).
  ⚠️ Another trap here: unguarded git in this terminal *hangs waiting for
  input* (pager/ssh prompt) rather than running slowly — always use
  `core.pager=cat`, `GIT_TERMINAL_PROMPT=0`, `GIT_SSH_COMMAND="ssh -o
  BatchMode=yes"`, and `< /dev/null`.
- **aiosqlite connection threads are non-daemon — every test MUST close its DB
  (2026-09-22):** `aiosqlite.core.Connection` *is* a `Thread`. If a test opens a
  connection and never calls `await db.close()`, interpreter shutdown waits on the
  thread forever — pytest prints the "N passed" summary and then never exits
  (symptom: `ship.sh` stalls in step 1 with no new log lines; `pgrep` shows the
  pytest process alive at ~2 s CPU, `cat /proc/<pid>/wchan` = `futex_do_wait`, and
  `ps -eLf` shows one idle extra thread per leaked connection). CI would hang the
  same way. All repo tests close their DB explicitly — keep that contract.
- **Mock patch targets: patch where the code *uses* the name, not where it is
  defined (2026-09-22):** `app/services/monitor.py` does `from
  app.services.scanner import find_ip_by_mac, check_host_reachable`, so patching
  `app.services.scanner.*` in a test leaves monitor's own bindings untouched — the
  real scanner runs (returns `None` quickly in the sandbox), recovery bails early,
  and the DB assertions fail with no exception (very quiet failure mode). Patch
  `app.services.monitor.find_ip_by_mac` / `.check_host_reachable` instead.
- **Recovery tests need the *full* app schema (2026-09-22):** `_start_recovery`
  touches `subnets` (via `list_subnets` when the host has no pinned subnet —
  `list_subnets` swallows the missing-table error itself) and `events` (via
  `send_event` — an INSERT, *always*, even with `notify=False`) → a minimal
  hosts/host_state fixture fails with `sqlite3.OperationalError: no such table:
  events`. `tests/test_monitor_recovery.py::_setup_db` now `executescript`s
  `app.database.SCHEMA` so the fixture cannot drift.
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
- **Live diagnostic-scan API contract (`POST /api/diagnostic/scan`):** the
  `ScanRequest` (`app/main.py:732`) has **one** required field — `target_mac`
  (a blank one 400s, "target_mac is required"); `method` (default `"arp-scan"`),
  `subnet_id` (default `0` = all known subnets) and `subnet_cidr` (default `""`
  = all effective subnets) are all **optional**. So the minimal body is just
  `{"target_mac": "…"}` and it sweeps every effective subnet. **Verified live
  2026-09-21 on the batcave:** `{"target_mac":"…","method":"nmap"}` (no
  `subnet_cidr`) → 200, swept all subnets. There is **no `subnets` list field**
  on the HTTP model — `subnets=[…]` is only a keyword arg on the scanner
  *functions* (`run_scan`/`run_*_scan`), which is what the in-process unit tests
  pass; a body of only `{"subnets":[…]}` 422s purely because `target_mac` is
  missing. Unit tests are the source of truth for the scanner; hit `:8787` only
  to confirm the *deployed* request shape. (Corrects an earlier note that wrongly
  said `subnet_cidr` was required alongside `target_mac`.)
- **`sys.modules["pkg"] = None` does NOT fake a *submodule* import failure once
  it is cached (learned 2026-09-20, pipeline 181; fixed in `7e6577a`).**
  `monkeypatch.setitem(sys.modules, "scapy", None)` only stops a *fresh* import:
  if an earlier test in the session already imported `scapy.all` /
  `scapy.sendrecv`, the import machinery returns the *cached submodule* without
  re-importing the parent package, so `from scapy.all import …` still succeeds
  and the real code path runs. `TestL3AliveScapy::test_import_failure_returns_none`
  then "passed" locally only by luck (non-root: `sr()` raised a socket permission
  error → caught → `None`) while **failing in CI** (root in `python:3.12-slim`
  keeps `NET_RAW`: `sr()` opened a raw socket, burned the 2 s timeout, returned
  `set()` → `assert set() is None` broke). **Rule: to fake an import failure, set
  `None` for EVERY module the import names — package AND submodules** (`scapy`,
  `scapy.all`, `scapy.sendrecv`). And treat any "failure-path" test that passes
  only because a *different*, environment-specific exception is caught
  (permissions, missing binary) as not hermetic — verify it under the CI
  image's conditions, not just the dev box.
- **Diagnostic scan progress: `start_time` must be preserved in-place — never
  replace the `scan_progress` dict (pipeline 233, `a0d2f04`, 2026-09-28).**
  `_publish_discovery_progress` (`app/main.py`) updates the existing
  `scan_progress[scan_id]` entry **in place** (direct key assignment on the
  existing dict). The pre-fix code replaced the dict with a new one the moment
  discovery finished, resetting `start_time` to `time.time()` — `elapsed_time`
  then jumped back to ~0 mid-scan and the UI read as "stuck/frozen" for the
  rest of the port-scan phase. Three-part fix: (1) in-place update in
  `_publish_discovery_progress`; (2) `run_port_scan_incremental` now runs each
  per-host nmap via `asyncio.to_thread` so the event loop stays responsive
  during multi-minute port scans (a blocked loop freezes the UI regardless of
  the timer); (3) `diagnostic.html` keeps the progress card visible on
  completion and shows the final elapsed time (previously the card disappeared,
  hiding the symptom). Regression:
  `tests/test_main.py::test_scan_elapsed_time_never_resets` +
  `::test_scan_elapsed_time_grows_monotonically`.
- **Diagnostic scan progress: freeze `elapsed_time` at completion via
  `final_elapsed_time` (pipeline 234, `ec75221`, 2026-09-28).**
  `GET /api/diagnostic/scan-progress/{scan_id}` (`app/main.py`) previously
  recomputed `elapsed_time = time.time() - start_time` on **every poll**, so
  the number kept ticking up indefinitely after the scan finished. Since
  pipeline 233 the progress card stays visible on completion, the still-growing
  timer read as a scan that never ended. Fix: `_do_scan` writes
  `progress["final_elapsed_time"] = round(time.time() - progress["start_time"],
  2)` at finalisation (just before `status = "complete"`); the endpoint returns
  that frozen value when the key is present, falling back to the live clock
  only while the scan is still running. Regression:
  `tests/test_main.py::test_scan_elapsed_time_freezes_on_completion` (two polls
  0.1 s apart must report the **exact same** value) +
  `::test_scan_elapsed_time_still_grows_while_running` (companion: while
  running, elapsed must keep growing — the freeze only kicks in at
  finalisation).

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
- **`"enp6s0" is not a valid numeric value` — RESOLVED (was TASK 4, parked
  2026-09-18; the arp-scan half fixed by the `--interface` change below).** This
  message has **two** producers, both now handled: (1) the *scapy* `conf.iface` /
  `int("enp6s0")` route bug (above, fixed `00062a6`) and (2) the *arp-scan*
  argument bug (separate note below). After the scapy fix the remaining error came
  from the arp-scan sweep, not scapy — which is why nmap/scapy worked on a subnet
  while arp-scan returned empty. **VALIDATED 2026-09-21 on the batcave** (192.168.86.38,
  the `deploy_dev` box): the NFS-workstation sandbox can't sweep itself (Flatpak: no `ip`/
  `arp-scan` in-sandbox; host copies only under `/run/host`), so the check was run on the
  deployed app via `POST :8787/api/diagnostic/scan` (unauthenticated) →
  `arp-scan -q --retry=3 --interface=enp6s0 192.168.86.0/24` returned `rc=0`, empty
  stderr, **17 hosts** (`error=None`), `found_ip=192.168.86.37` (flash). Bug confirmed gone.
  Three paths into the app's scanner: (1) Diagnostic UI → `POST
  /api/diagnostic/scan` → `run_scan` → `run_arp_scan`/`run_scapy_scan` (the path
  that surfaced the error); (2) recovery monitor (`monitor.py:269`) →
  `find_ip_by_mac(subnets=...)` → `_scan_with_arp_scan`/`_scan_with_scapy`;
  (3) direct `docker exec upstream-healer python -c "from app.services.scanner
  import run_scapy_scan; print(run_scapy_scan('aa:bb:cc:dd:ee:ff',
  subnets=['192.168.86.0/24']))"` → prints the exact `(ip, output, error)`.
- **`run_scapy_scan` sweeps each subnet in its own try/except.** One subnet
  failing to sweep (route resolution, no route, permission) logs a warning and
  `continue`s — it no longer fails the whole multi-subnet run. (This is the
  same "one bad subnet must not kill the rest" principle as the arp-scan
  `(skipped ...)` notes.)
- **`get_local_ip_for_network` returns `(ip, iface)` from `ip route get`.**
  The kernel-reported interface (`dev` field) is always valid and is used as
  the egress interface in `run_scapy_scan`, avoiding the scapy
  `int("enp6s0")` route-bug entirely.  The old approach (matching local IP
  against scapy's `conf.get_if_addresses()`) could leave `egress=None`, which
  caused scapy to use its (possibly corrupted) default interface.  Fixed
  2026-09-17.

- **arp-scan 1.10: `-i` is `--interval` (a number), not the interface — select the
  NIC with `-I`/`--interface`.** The per-sweep command was
  `arp-scan -q --retry=3 -i <iface> <cidr>`. In arp-scan 1.10.0 (Debian bookworm,
  what `python:3.12-slim` ships) the short letters are case-sensitive:
  `-I`/`--interface` = the NIC (a string) while `-i`/`--interval` = a *numeric*
  retry interval. Feeding the NIC name to `-i` made arp-scan run
  `strtoul("enp6s0")`, print `ERROR: "enp6s0" is not a valid numeric value` and
  **exit 1 with zero hosts** — so full arp-scan lists came back empty (the non-zero
  exit was unchecked, so the error banner was silently filtered out). Fixed: the
  sweep uses `--interface=<nic>` (the man-page canonical form) and checks the
  return code, recording a failed sweep instead of treating its error as output.

- **arp-scan note: a `/32` (or `/31`) is a *host*, not a network.** It has no
  usable broadcast, so it is not ARP-sweepable. `run_arp_scan` now emits a
  specific `(skipped <cidr>: single host, not an ARP-swept network — add its
  /24 ...)` note instead of the misleading "no local interface" (the interface
  is usually *present*; the address is just a single host). If a user added a
  specific IP (e.g. `192.168.70.0/32`) and expected a whole-LAN sweep, the real
  fix is to enter the `/24` (e.g. `192.168.70.0/24`).
- **`found_ip` is always `None` for the *nmap* diagnostic — a limitation, NOT a
  bug (and NOT in the recovery path).** `run_nmap_scan` builds each host line
  with the MAC hardcoded to `"--"` (`_host_line(ip, "--", …)`) because
  `nmap -sn -oG` output carries no MAC, and `_match_mac_in_output()` matches real
  MACs (it is written for an arp-scan table) — so with only `"--"` present there
  is nothing to match and `found_ip`/`found_mac` come back `None` (host MACs
  render as `mac: None`). It *does* still list the live hosts (names via the
  mDNS/curated layer), so the target is visible in `hosts[]`, just not pinned to
  `found_ip`. This affects only the on-demand **nmap diagnostic** (it is also a
  L2 broadcast probe, so it can't see a routed/tunnel host regardless); **recovery
  is unaffected** — it uses arp-scan/scapy, which resolve MACs. *Parked (potential
  later item, deliberately not implemented):* resolve MACs for the IPs nmap
  discovers — e.g. a follow-up `ip neigh get <ip>` or a targeted arp-scan of just
  those IPs on the egress NIC — and feed the real MACs to `_match_mac_in_output`
  so `found_ip` populates for nmap too.

## Seeder / NPM-sync gotchas (all resolved — read before touching `scripts/seed_dev.py`)

The seeder's failures surfaced layer by layer and are all **fixed, deployed, and
live-verified** (creates all 6 proxy_host rows + owner + access_list + certificate;
idempotent re-run reuses them, zero duplicates). Keep these gotchas when editing:
- **Cursor-lifecycle errors carry NO numeric errno.** A pymysql "Cursor closed" /
  "Not yet connected" is a *str-args* `OperationalError` with no `errno`, unlike real
  SQL failures (1364 missing-column, 1054 unknown-column, 1146 missing-table,
  1048 null-into-NOT-NULL put the code in `exc.args[0]`). Retry/backoff MUST also
  match the *string* form — or lifecycle errors look non-retryable and the seeder
  silently seeds 0 rows. Regression: `TestCursorLifecycle` (`_ClosingCursor`/`_ClosingConn`).
- **Run every statement *inside* its `with conn.cursor()` block** (the "Cursor
  closed" fix, `72dd82b`) and treat `"closed"`/`"not connected"` as transient.
- **NOT-NULL-with-no-default columns must be explicitly supplied on INSERT** (strict
  mode; a NULL also fails them). The schema *changes between NPM image releases*, so
  the seeder **introspects `SHOW COLUMNS` before each INSERT** and auto-fills any such
  column the INSERT omits (`_fills_for` / `_KNOWN_COLUMNS_WITH_DEFAULTS`:
  `user.avatar=''`, `certificate.meta='{}'`, `proxy_host.advanced_config`+`meta='{}'`,
  `access_list.meta='{}'`; `""` for a truly unknown new column). 1364 is NOT transient
  (a stable schema won't fix itself) → the pass fails fast, not a ~30s retry.
- **JSON-check columns need valid JSON, not bare strings.** `certificate`/`proxy_host`
  `domain_names` are `longtext CHECK (json_valid(…))`: the fallback cert seeds
  `domain_names="[]"`, `expires_on="2999-12-31 23:59:59"` (a `__sql__` datetime, not
  NULL/`''`), `meta="{}"`; `proxy_host.domain_names` is a JSON *array* — use
  `_proxy_host_domain()` for matching + `json.dumps([domain])` on INSERT.
- **NPM bootstrap specifics:** the owner `user` row is a plain INSERT (the old
  `CREATE USER (…)` was a syntax error AND redundant — removed); `bcrypt==4.2.1` is
  required for the password hash; the sandbox DB has empty `user`/`access_list`/
  `certificate` (wizard never ran) so the seeder bootstraps a dev admin. Regression:
  `TestSchemaIntrospection` + `TestProxyHostDomainJson`. (`npm.get_all_hosts` is an
  *independent* read path — confirm its SELECT uses only real columns.)
- **Do NOT re-implement** the disproven note that the `proxy_host` INSERT omits
  `owner_user_id`/`access_list_id`/`certificate_id` — the current INSERT already
  supplies all three.

## Hostname resolution / reverse DNS (added 2026-09-24)

- **`socket.gethostbyaddr()` returns a TUPLE, not an object.** The
  reverse-DNS fallback in `scanner.py` (`resolve_hostnames` and
  `resolve_hostname`) used to read `.hostname` off the result — an attribute
  that never exists — so **every** lookup raised `AttributeError`, the bare
  `except` swallowed it, and the fallback silently never worked in production
  while the unit tests stayed green (they mocked a `SimpleNamespace(hostname=…)`
  — the mock's shape, not the stdlib's shape). Fixed in `7e091a9`:
  `gethostbyaddr(ip)[0]`. **Lesson (pairs with the `_match_mac_in_output`
  dict-attrs gotcha below): when mocking a stdlib function, return the real
  return type — otherwise the test validates the mock, not the code.**
- **nmap's own reverse DNS is empty on this LAN.** nmap discards a PTR when the
  forward A doesn't round-trip, so `nmap -sn -oG` prints `Host: 192.168.86.52
  ()  Status: Up`; glibc's `gethostbyaddr` (PTR only) resolves fine — that's
  why the app-side fallback is the name source, and why no-MAC sweeps must not
  rely on nmap's `Host:` name field. Verified live 2026-09-24: 19 swept hosts,
  `reverse-dns attempted=19 | resolved=16` (`frack.lan`=192.168.86.52,
  `frick.lan`=192.168.86.226, plus pixel-fold/dustinodroid/tl-sg608e/
  `_gateway`…). Hosts with no PTR at all (.24/.27/.248) can be labeled via the
  curated hosts page — `hosts.current_ip` is the last fallback before mDNS.
- **Scan-log endpoint is dev-gated by env, not by flag:** `GET
  /api/diagnostic/scan-log` 404s when `UPSTREAM_HEALER_DEBUG_LOG_DIR` is unset
  (base/prod compose never set it — dev compose sets `/logs` + mounts
  `/mnt/data/upstream-healer/logs`) **or** `ENV == "production"`. The
  env-var gate is the effective one; the ENV tripwire is defense in depth.
  Do not expose per-scan debug content (raw nmap output incl. self-identity
  warnings) on test/prod tiers.

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
  media query. The form's `grid grid-cols-1 sm:grid-cols-2` already stacks to one
  column on phones, and the subnets table sits in `overflow-x-auto` (scrolls), so
  no phone-specific work is needed.

- **Templates use the Tailwind Play CDN** (in `base.html`: `<script
  src="https://cdn.tailwindcss.com">`), so *any* utility class renders — there is
  no build step / content-scan to update when adding classes. Theme is class-based
  dark mode (`.dark` on `<html>`, toggled in `base.html`). Form-control colours
  come from a global `<style>` block in `base.html` (forces white/slate-900 on
  `input[type=text]/[number]/[password]/[email]`, `select`, `textarea`).
