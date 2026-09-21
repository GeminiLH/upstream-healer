# Decisions & Gotchas — Upstream Healer

> Last updated: 2026-09-21.

## Design decisions

- **Scanner worker-thread logging: dispatch via `asyncio.to_thread`, NOT a bare
  `run_in_executor`** (2026-09-21): On Python 3.12 (the dev image)
  `loop.run_in_executor(None, fn)` does **not** copy the `ContextVar` into the
  worker thread, so every `diag_log.emit/proc/exc` inside the sweep thread
  silently no-oped and the per-scan file came back with only the event-loop-side
  lines (an "empty" sweep — this was the batcave/fash debug-log bug). `run_scan`
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
  discarding the ~16 on `192.168.86.0/24`. Now the self/fash nmap scan returns
  the 86.0/24 hosts (incl. flash) with `error` naming `192.168.70.0/24`.

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
- **batcave + fash are seeded disabled** (2026-09-20): real lab devices for
  positive diagnostic tests (batcave = the sandbox box, MAC b4:2e:99:e9:80:fc;
  fash = dc:a6:32:02:59:63). Seeded `enabled=0` with no domain: their names
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

Access is in the repo-root **`.env.local`** file (git-ignored; loaded with
`set -a; . ./.env.local; set +a`). **Never commit it**, never print its values
in logs or the memory bank.

**Token semantics (verified 2026-09-18 — do not guess/swap):** `.env.local`
defines two tokens with *opposite* abilities. `GITLAB_READ_TOKEN` is the
`Cline_API` PAT, scope `read_api` — every project-scoped GET we poll works
(`/projects/:id`, pipeline lists, job status, trace) but **POST play → 403
`insufficient_scope`**. `GITLAB_PIPELINE_TOKEN` is a job token (no user behind
it) — **the only one that can play manual jobs** (every `deploy_dev` play so
far has used it — jobs 811/819/835) but project GETs → 403. So: all *reads*
use the read token, the *play* POST uses the pipeline token — that is how
`ship.sh` is wired. Traps that cost 10+ min of debugging: (1) an **empty**
token surfaces as `404 Project Not Found`, *not* 401/403 — so fail-fast
preflight `GET /api/v4/projects/:id == 200` before any poll loop, and never
treat a 404 as "nothing there"; (2) `${!VAR}` indirect expansion with an unset
VAR is a fatal bash error that left the token empty for the whole script —
read token variables directly. Also: on this Pi GitLab instance, *pipeline
creation* can lag the push by 1–6 min (observed 1 min and 5.5 min for the same
flow); `ship.sh` tolerates it with a 10-min appear window and is **resumable**
— re-running with nothing to commit skips commit+push and resumes pipeline
watch + deploy for the current HEAD.
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
  - Token: `GITLAB_PIPELINE_TOKEN` from the git-ignored `.env.local` —
    sufficient for pipeline/job reads and `POST /api/v4/projects/4/jobs/:id/play`
    (verified for `deploy_dev`, job 811 → success in 34s).
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
  deployed `ScanRequest` requires `target_mac` (str) **and** `subnet_cidr` (str)
  together. A body with only `subnets` (a list) **422s** with `Field required`.
  The unit tests exercise the `subnets`-list form (fine in-process) — but to
  *script against the live API* you must send `target_mac` + `subnet_cidr`. Unit
  tests are the source of truth for the scanner; hit `:8787` only to confirm the
  *deployed* request shape.
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
  while arp-scan returned empty. **Validate the fix in the `deploy_dev` container on the batcave**
  (192.168.86.38) — the NFS-workstation sandbox can't sweep (Flatpak: no `ip`/
  `arp-scan` inside the sandbox; host copies are only reachable under `/run/host`).
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
