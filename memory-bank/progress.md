# Progress — Upstream Healer

> Snapshot: 2026-09-27 — **All CI green, deploy_dev live, MCP tools verified.**
> Pipeline 225 (commit `91b462c`) — lint ✅, unit_tests ✅, build_image ✅,
> deploy_dev ✅ — dev stack running on batcave (6 hosts, UI at :8787).
> GitLab MCP tools confirmed working: `gitlab-read` (GET pipelines/jobs/traces),
> `gitlab-pipelines` (POST /play deploy_dev), `log-servers` (SSH diag-log access).
> 377 tests passing (+ 1 skipped on CI), ruff clean.
> Verify before acting: `git status`, `git log -5`,
> `python3 -m pytest tests/ -q`.

## Latest (2026-09-27) — CI flaky-test fixes + deploy_dev live

- **Five consecutive pipeline failures (219–222) fixed by commits `af4609a`
  through `bf3ff77`:**
  - Pipeline 219/220: `unit_tests` failed — flaky
    `test_scan_endpoint_returns_valid_scan_id` timed out on CI (scan status
    stuck at `starting`). Root cause: background `anyio` task scheduling
    unreliable in the CI container. Fix: `asyncio.sleep()` with longer polling
    + explicit `pytest` import (`8676fbe`, `b59f251`).
  - Pipeline 221: `lint` failed — F401 unused import
    `from app.main import scan_progress` in `test_main.py`. Fix: removed unused
    import (`eb26021`).
  - Pipeline 222: `unit_tests` failed — same flaky test. Fix: skipped on CI
    with `@pytest.mark.skipif` + added `pytest` import to `conftest.py`
    (`bf3ff77`).
- **Pipeline 223 (`bf3ff77`) fully green:** lint ✅, unit_tests ✅ (378 passed,
  1 skipped), build_image ✅, deploy_dev ✅. Dev stack running with 6 seeded
  hosts (vault, jellyfin, failtest, plex, homeassistant, portainer).
- **MCP tool verification (2026-09-27):**
  - `gitlab-read`: `GET /api/v4/projects/4/pipelines` → 5 latest pipelines,
    `GET /jobs/:id/trace` → full job logs, `GET /projects/4` → project info.
  - `gitlab-pipelines`: `POST /projects/4/jobs/1306/play` → HTTP 200,
    deploy_dev job ran and succeeded in ~10 s.
  - `log-servers`: SSH via `batcave_logs.sh` → listed 17 diag log files
    (newest `diag_20260926_234325_arp-scan__1.log`).

## Latest (2026-09-24) — nameless no-MAC sweep fixed + scan debug log endpoint

- **Root cause of the nameless no-MAC sweep was not missing data — the
  reverse-DNS fallback had been silently dead all along.**
  `app/services/scanner.py` (`resolve_hostnames` and `resolve_hostname`) called
  `.hostname` on the result of `socket.gethostbyaddr(ip)` — which returns the
  tuple `(name, aliases, addrlist)` — no `.hostname` attribute → `AttributeError`
  on every lookup → swallowed by the bare `except` → every host without a
  curated/mDNS name rendered `None`. The LAN *does* have PTR records
  (`frack` = 192.168.86.52, `frick.lan` = 192.168.86.226 — confirmed from the
  workstation resolver). Fixed with `gethostbyaddr(ip)[0]` + trailing-dot strip
  in both paths; a `reverse-dns: attempted=/resolved=` line was added to the
  diag log. nmap's *own* reverse DNS is empty on this LAN (nmap drops a PTR
  when the forward A doesn't round-trip — raw output: `Host: 192.168.86.52 ()
  Status: Up`), which is why the app-side fallback is the name source.
- **The tests masked the bug.** 4 mocks in `tests/test_scanner.py` returned
  `SimpleNamespace(hostname=…)` — the mock's shape, not the stdlib's. Switched
  to the real tuple shape so the regression tests exercise the actual code
  path. Rule (pairs with the `_match_mac_in_output` dict-attrs gotcha in
  decisions.md): **when mocking a stdlib function, return the real type**.
- **New "more detail" channel:** `app/services/diag_log.py` gained
  `recent_scans()` (name/size/mtime/size_str, newest first, capped at 10);
  `app/main.py` got `GET /api/diagnostic/scan-log` returning the newest
  `diag_*.log` content (200 KB truncated) + recent-file metadata; 404 when
  `UPSTREAM_HEALER_DEBUG_LOG_DIR` is unset or `ENV == "production"` (dev-only —
  base/prod compose never set the dir). The diagnostic page has a "Scan debug
  log" button + `<pre>` panel (fetch → fill; recent logs listed in the caption).
  3 new endpoint tests (no-dir 404 / prod 404 / dev 200 + content + files list).
- **Live-verified after deploy (`7e091a9`, pipeline 211, `deploy_dev` OK):**
  no-MAC `nmap` sweep → 19 hosts, 16 labeled (pre-fix scan the same day: 7).
  `192.168.86.52 → frack.lan` (the exact IP the user expected) and
  `192.168.86.226 → frick.lan`; also pixel-fold.lan, dustinodroid.lan,
  tl-sg608e.lan, `_gateway`, WDMyCloud, … Unnamed: .24/.27/.248.
- Tests: 372 passed, ruff clean.

## Latest (2026-09-23) — host form: quiet-time to bottom, NPM field up, "populate from NPM"

- **Reordered the host add/edit form** for a cleaner flow
  (`app/templates/host_form.html`): "NPM Proxy Host ID" moved from between
  *Current IP* and *Port* to just above *Domain* (right after *Local device
  name*); the "Quiet time" fieldset moved from between *Domain* and *MAC Address*
  to the bottom, just above the "Enabled (monitor this host)" box. Pure markup
  relocation — no logic change.
- **Selecting an NPM proxy host now offers to populate the record.** Each
  `<option>` carries `data-ip`/`data-port`/`data-domain`/`data-subnet`; a small
  inline `<script>` (placed after the main `<form>`) listens for `change` and
  `confirm()`s a summary, then fills `current_ip`/`port`/`domain` and sets
  `subnet_id` — but only when the derived CIDR is actually present in the subnet
  dropdown (`form.elements['subnet_id']` options are matched by `value`). Pure
  client-side, no server round trip, user can dismiss.
- **Subnet offered where available** (`app/main.py`): new `_subnet_for_ip(host,
  subnets)` picks the first *known* subnet that contains the proxy host's
  `forward_host` (so VLANs wider/narrower than /24 resolve correctly), else falls
  back to the address's own /24; returns `None` for a non-IPv4 forward address
  (an upstream domain) so no subnet is offered. `_render_host_form` attaches it
  to each proxy host (`ph["subnet"] = _subnet_for_ip(...)`).
- **Gotcha caught by the new test:** the /24 fallback had to use
  `ipaddress.ip_network((addr, 24), strict=False)` — the default `strict=True`
  raises "has host bits set" for a host address like `192.168.86.249`. Full note
  in decisions.md.
- 4 tests added in `tests/test_main.py` (`test_subnet_for_ip_*` ×3 +
  `test_form_offers_populate_from_npm`); **334 passed**, ruff clean.

## Latest (2026-09-22) — MAC+port conflict 500 → clear named-host error; ship.sh empty-jobs trap

- **Host edit/add MAC+port conflict returned a 500** (`f7312dd`, live on dev):
  `hosts` has `UNIQUE (mac_address, port)`; `POST /hosts/{id}/edit` ran the
  UPDATE with no pre-check, so assigning another host's MAC+port hit the
  constraint → `IntegrityError` → 500 (the `/add` INSERT had the same bug).
  Fix: pre-flight check in both endpoints → re-render `host_form.html` with a
  rose error banner ("MAC … on port … is already used by host '<name>' —
  every host needs a unique MAC + port combination."), repopulated with the
  submitted values (edit merges them over the existing row so `id` is kept).
  New `_render_host_form_conflict()` helper in `main.py`; `edit_host` also
  gained a 404 for missing hosts (was a silent no-op UPDATE). Template:
  error banner + validate/delete/enabled/JS sections now gated on
  `host and host.id` (repopulated *add* forms have no `id`). 3 tests in
  `test_main.py` (edit conflict / own mac+port / add conflict); **314 passed**,
  ruff clean. Verified live on dev: conflict POST → 200 + banner naming
  `jellyfin`, row unchanged; same-value POST → 303 (urllib shows it as 200
  Dashboard — it follows the 303; curl shows 303).
- **ship.sh declared green from an EMPTY jobs list and silently skipped the
  deploy** (`6a43c07`): GitLab's `GET /pipelines/:id/jobs` can return `[]`
  right after pipeline creation; the step-4 snippet then had `auto = []` →
  "no failures" + `any(...)` over the empty list is False → `READY ` with an
  empty deploy job id → step 5 skipped. Pipeline 201 (`f7312dd`) got no
  deploy; its `deploy_dev` was left `created`/unplayed. Fixed: `len(auto) < 3`
  → `WARMUP`, and a missing `deploy_dev` id → `WARMUP` (fail loudly at the 30
  min deadline, never skip). Re-shipped as `6a43c07` (pipeline 202): full
  flow worked — auto jobs watched properly, `deploy_dev` job 1144 played,
  **deploy_dev SUCCESS**, dev UI 200. 6a43c07 is live on dev.

## Latest (2026-09-22) — validate screens + the nmap 7.93 `-oJ` trap, fixed live

- Edit-screen **Validate** shipped (`4299a52`): Validate button →
  `POST /hosts/{id}/validate` → new `scanner.validate_host_record` (one ARP
  sweep checked both directions, shared mDNS browse, nmap service probe per
  distinct IP, port-state derivation, host_form.html sections + dashboard
  banner) + `cli validate-host`. 305 tests green.
- **`-oJ` trap, root-caused from nmap 7.93 source** (the user's "nmap
  produced no results (rc=0): ... Failed to resolve '-'" error):
  nmap 7.93 (Debian trixie, the Docker image) has **no JSON output** —
  `-oJ` matches no long option, falls to the deprecated short `-o` (optstring
  `o:`), `J` is eaten as its filename, and the output argument lands in the
  *target* list. Full story in decisions.md. Fix in two commits: `811ac94`
  (explicit `-sT` + temp-file `-oJ` — still broken, proving the `-oJ` theory)
  → **`705db59`** = `nmap -Pn -sT -sU -sV -T4 --open -p <spec> -oX - <ip>`
  (same proven idiom as the L3 sweeps' `-oG -`) + `parse_nmap_services_xml`
  (stdlib ElementTree, never raises). **Verified live in the batcave**
  2026-09-22: flash → `22/tcp open ssh OpenSSH 10.0p2 Debian 7+deb13u4`,
  `port_state=closed`, `services_error=null` — the Pi genuinely serves no
  HTTP on :80 (the user's "port 80 closed" reading was correct).
- Validate endpoint now wrapped in `diag_log.scan_context(method="validate")`
  — per-run file in /logs (dev-only; read via `scripts/batcave_logs.sh`)
  with the exact nmap cmd + rc + raw stdout/stderr.
- `scripts/ship.sh` hardened: poll deploy_dev to `manual` before the play
  POST (was 400 "Unplayable Job" when the job was still `pending`).
- Suite: 307 passed, ruff clean.


## Current state

- **Routed-subnet nmap fast-bail (Fix C) — done, deployed + verified live** (2026-09-21):
  `scanner.py::_l3_alive_nmap` is classification-aware — routed/tunnel subnets sweep
  `nmap -sn` with `--max-retries 0 --host-timeout 3s` under a 30 s wall cap so a
  blackholed gateway finishes fast with 0 hosts (→ no top-level error); broadcast
  keeps `5s`/120 s. Closes the row-4 symptom from the 2026-09-21 scan battery (nmap
  full sweep: `error="nmap failed on 192.168.70.0/24"` + a 120 s hang on the phantom
  routed subnet). 127 scanner tests pass; in-process proof: routed blackhole →
  `error=None`, local hosts kept. Deploy via `bash scripts/ship.sh` (or `deploy_dev`).
- **L3 discovery — SHIPPED (pending deploy):** `b09cd4d` — `scanner.py`
  classifies each subnet (real-NIC `BROADCAST` vs point-to-point/gateway via
  `ip -o link` flags) and sweeps tunnel/routed ones at **Layer 3**
  (`run_l3_probe`: scapy ICMP → `nmap -sn` → `ping`), emitting `--` for the
  unresolvable source MAC; `run_nmap_scan` + a selectable **nmap** method
  (`main.py`); the UI (`app/templates/diagnostic.html`) shows a **routed** badge;
  `_l3_alive_nmap` parses `nmap -sn -oG -` (grepable). +44 tests → 255 green.
  Pipeline 181 failed on `TestL3AliveScapy::test_import_failure_returns_none`
  (the `sys.modules` cached-submodule trap — decisions.md gotchas); `7e6577a`
  made that test hermetic and **pipeline 182 is green**. Ship to the dev box =
  Play `deploy_dev` on 182, or `bash scripts/ship.sh` (resumes for HEAD).
- Branch: `main` (tracking `gitlab/main`; GitLab is the primary repo, see
  decisions.md; push explicitly with `git push gitlab main` — never bare).
- HEAD / sync: local = `gitlab/main` at `7e6577a` (L3 test fix) + this
  memory-bank commit; worktree clean. **255 tests pass, ruff clean** (system
  `python3` 3.13; the repo `.venv` is a non-working Windows venv on this NFS
  share — see context.md).
- **mDNS hostnames (done — `10d12fa` + `fa191e2`, deployed to dev 2026-09-19):**
  layered naming in the diagnostic table (highest first): monitored host's DB
  name → live mDNS/avahi (zeroconf browse, 8 s, concurrent with the ARP sweep) →
  persistent per-MAC `mdns_names` cache → reverse-DNS; `apply_hostnames`
  sorts named-first; a name only disappears when the device is absent from
  *that* ARP sweep. Live-verified on the dev box (Apple TV / MacBook Air /
  WD NAS / the box).
- **Subnet/diagnostic batch — shipped + deployed 2026-09-16/17** (all on
  gitlab/main, all test-covered): the batch summary, with the commit-level
  detail still in git log:
  - `8e2f674` **F1** — *actively sweep only selected subnets; never leak
    unselected networks.* Rewrote the scapy/arp-scan selection path in
    `app/services/scanner.py`; the monitor + diagnostic now sweep exactly the
    subnets the user selected (or the merged auto+manual set) and never bleed
    into unselected networks. + `app/main.py`, `diagnostic.html`, +tests.
  - `d10a393` **F2** — *manage auto-detected subnets in Settings.* Added
    per-CIDR **rescan** (re-include a previously-suppressed auto network) and
    **suppress/delete** (stop sweeping a stale auto network) to the Subnets
    card in `settings.html`; new `/settings/subnets/rescan` + `/suppress`
    handlers in `app/main.py`; suppression storage in `scanner.py`. +tests.
  - `0bfc2e5` **F3** — *show hostnames in diagnostic results.* Scanner does a
    reverse-DNS lookup on responders; `diagnostic.html` renders a structured
    hosts table (not a raw dump). +tests.
  - `50e9d31` **F4** — *framework-compat fix.* Migrated `TemplateResponse`
    calls to the new signature (bumped `fastapi` 0.115.6 → 0.141.1, pinned
    `starlette` 0.49.3), and suppressed the
    `anyio.abc.BlockingPortal` **DeprecationWarning** via a `filterwarnings`
    line in `pytest.ini` (this is the startup/test warning you may still see
    if the pin drifts). Touched `app/main.py`, `pytest.ini`, `requirements.txt`.
  - **(shipped — in `6bf798e`)** *Settings subnet UX polish*, three
    fixes on the Subnets card in `settings.html` from direct user feedback:
    (1) a global **"Rescan networks"** button + `/settings/subnets/rescan-all`
    (clears the suppression list so all auto /24s come back) — the missing
    "rescan" the help text always promised; (2) the **Interface** field is a
    `<datalist>` **suggestion** of real NICs from a new `scanner.get_local_interfaces()`
    (`ip -4 -o addr`, any prefix, deduped, skips `lo`, `[]` when `ip` is absent)
    **and** `add_subnet` **validates** it (blank/`auto`/`any`/`default`→auto; an
    unknown NIC is 400'd with the available list); (3) **lay-person CIDR help**
    (`/24`≈256, `/28`≈16, `/32`=single IP, must end in `.0`) + `add_subnet` rejects
    `/31`+. Touched `app/main.py`, `scanner.py`, `settings.html`, `tests/*`.
    178 tests green, ruff clean; **shipped** (`git push gitlab main` + `ship.sh` → deploy_dev).
- The **Settings widen+clarify** task (previously the "Next task") is now
  **done** — `settings.html` is `max-w-3xl` and the three subnet fields carry
  the clarifying hints (see decisions.md "UI / templates").
- **Parked (potential later item — do NOT implement without asking):** make the
  **nmap diagnostic** resolve a target by MAC. Today `run_nmap_scan` hardcodes
  `"--"` for every host's MAC (`nmap -oG` carries none), so `found_ip` is always
  `None` for nmap (it still *lists* hosts via the name layer, and **recovery is
  unaffected** — it uses arp-scan/scapy). The fix: resolve MACs for the IPs nmap
  finds (e.g. `ip neigh get` / a targeted arp-scan of just those IPs) and feed
  them to `_match_mac_in_output` so `found_ip` populates for nmap too. Full
  why/scope in decisions.md "Scanner / multi-subnet gotchas". Related: the
  corrected `/api/diagnostic/scan` contract note there (`target_mac` is the only
  required field; `subnet_cidr`/`subnet_id`/`method` optional — there is no
  `subnets` field on the endpoint model).
- Leftovers from earlier: old manual `deploy_*` jobs on stale pipelines —
  `deploy_test` / `deploy_production` / `dev_down` / `dev_debug` in every
  recent pipeline remain `manual` — **trigger only on explicit user
  confirmation**.

## Multi-subnet design + file map

- **Auto-detection:** `app/services/scanner.py::get_default_subnets()` reads
  `ip -4 -o addr` → `{cidr, interface, source: "auto"}` for each primary
  address of prefix length 24. Skips `127.0.0.0/8` + non-/24 prefixes.
  Returns `[]` if `ip` is missing (graceful — the NFS workstation sandbox has
  no `ip`; the dev container does via `iproute2`).
- **Manual overrides:** new `subnets` table (`id, name, cidr, interface,
  enabled, check_interval_seconds`, `UNIQUE(cidr)`). Managed from the Settings
  page. `UNIQUE(cidr)` is a natural PK-ish key — a CIDR is a network.
- **Per-host pinning:** `hosts.subnet_id` (nullable FK → `subnets.id`,
  `ON DELETE SET NULL` — deleting a subnet un-pins hosts without orphans).
- **Merge semantics:** `list_subnets(db=None)` = manual rows first, then auto
  rows; same-CIDR collisions resolve to the manual row (manual wins, so a
  user-renamed subnet shows the user's name). Called per-scan so a
  newly-plugged-in interface is picked up without a restart.
- **Scanner thread-`subnets: Optional[list[str]]` through every function,
  `None` = historic behaviour (default `arp-scan -l` + local-/24 scapy sweep).
  - `run_arp_scan(subnets=...)` maps CIDRs → `-i <iface>` flags from the
    subnet→iface map; unknown/unparseable subnets get a `(skipped ...)` note.
  - `run_scapy_scan(subnets=...)` loops CIDRs, picking the per-sweep egress via
    `srp(..., iface=<egress>)` (NOT `conf.iface=` — that triggers a scapy
    `int("enp6s0")` route bug that aborts the *whole* sweep; see decisions.md #7).
    Each subnet is swept in its own try/except so one failing subnet is skipped
    with a log line rather than killing the rest.
  - `find_ip_by_mac(subnets=...)` → `_scan_with_arp_scan` / `_scan_with_scapy`;
    `_match_mac_in_output` + `ip_in_subnets` scope arp-scan output so a MAC
    shared across VLANs doesn't false-positive.
- **Monitor:** `_start_recovery` resolves the host's pinned subnet to a CIDR
  (if set) else falls back to `list_subnets(db)`, then calls
  `find_ip_by_mac(mac, subnets=...)`. The `scan_started` event names the
  subnets being swept.
- **API:** `GET/POST /settings/subnets`, `.../{id}/toggle`, `.../{id}/delete`;
  `ScanRequest.subnet_id: int = 0` (0 = "all known"); both host form GET/POST
  carry `subnet_id`.
- **UI:** `diagnostic.html` (subnet dropdown), `settings.html` (Subnets card),
  `host_form.html` (subnet select). No new nav link — subnets live in Settings.


## Diagnostics page (shipped 2026-09-16/18; foundation for the mDNS + L3 work)

All the `/diagnostic` polish is shipped + deployed:
- **Collapsible NPM proxy-host table** + merged scanner-type card + a tightened
  "Run a Scan" layout (the three F-style UI fixes).
- **Settings screen** widened to `max-w-3xl` with clarified subnet fields
  (Name = friendly label; CIDR = whole `/24`; Interface = "leave blank for auto").
- **Scapy `enp6s0` route bug fixed** (`00062a6`, deployed): a *scapy* diagnostic
  scan now returns the full responder table — no more `int("enp6s0")` `ERROR:`.

The scanner is exercised three ways in-container (Diagnostic UI, the recovery
monitor, direct `docker exec`); the `/32`-not-a-network, the `auto`-interface
placeholder, and the `POST /api/diagnostic/scan` request contract all live in
`decisions.md`.

## Done (recent history — full detail in git log)

- **`136a87d` (2026-09-22): monitor recovery tests fixed → pipeline 199 all
  green (`lint` 1116 / `unit_tests` 1117 / `build_image` 1118) → `deploy_dev`
  job 1120 success (18 s); dev UI live on `192.168.86.38:8787` (HTTP 200).**
  The 4 tests added in `014a51a` failed for three independent reasons: (1)
  `_setup_db` built only hosts/host_state, but `_start_recovery` inserts into
  `events` (and reads `subnets`) → now executes `app.database.SCHEMA`; (2) mocks
  patched `app.services.scanner.*` while monitor binds those names via
  `from ... import` → the real scanner ran; now patches `app.services.monitor.*`;
  (3) connections were never closed → non-daemon aiosqlite threads hung pytest
  shutdown after the summary (sandbox; `ps -eLf` showed 4 idle threads = 4 leaked
  conns) → now `await db.close()` per test. Plus ruff cleanup (unused `asyncio`
  import, unused `mock_*` bindings). Details in `decisions.md` (Gotchas).
- **(2026-09-21) arp-scan full-list fix**: the per-sweep command passed the NIC to
  `-i`, but arp-scan 1.10 uses `-i`=`--interval` (numeric) and `-I`=`--interface`.
  `arp-scan -q --retry=3 -i enp6s0 <cidr>` aborted with `"enp6s0" is not a valid
  numeric value` (exit 1, zero hosts) → silently empty results. Now uses
  `--interface=<nic>` and checks the return code. Resolves the parked **TASK 4**
  (the arp-scan half of the `"enp6s0"` error, after the scapy fix in `00062a6`).
  Full root cause in `decisions.md` (Scanner / multi-subnet gotchas). **Verified
  live on batcave 2026-09-21** (`c947d32` + `6603ed7` deployed via `deploy_dev`):
  fired `POST :8787/api/diagnostic/scan` (unauthenticated — see context.md) →
  `arp-scan -q --retry=3 --interface=enp6s0 192.168.86.0/24` gave `rc=0`, empty
  stderr, **17 hosts**, `found_ip=192.168.86.37` (flash), `error=None`.
- `412bda5` (2026-09-17): memory-bank commit → pipeline 160 all green →
  `deploy_dev` job 811 success (34 s); dev UI live on `192.168.86.38:8787`.
- **`scripts/ship.sh`** (2026-09-17, hardened 2026-09-18): one-command ship —
  tests → commit → push gitlab → auto jobs → `deploy_dev`, ~6 min; resumable
  re-runs (token/endpoint wiring in decisions.md; conventions below).
- `00062a6` scapy route-bug fix deployed to dev (pipeline 151) — scapy
  diagnostic scans now return the full responder table.
- **`b09cd4d` → `7e6577a` (2026-09-20):** L3 discovery failed pipeline 181's
  `unit_tests` 1/255 (scapy import-failure test; the `sys.modules` trap —
  decisions.md gotchas); `7e6577a` fixed the test; pipeline 182 green.
- User-facing: Settings → Subnets takes a **network** CIDR (`…0/24`), not `/32`.

## Conventions (keep these when editing)

- **Ship workflow = `bash scripts/ship.sh`** (tests → commit → push gitlab →
  auto jobs → `deploy_dev`, ~6 min, non-interactive). Do not re-invent the
  poll loops by hand — and never poll the *pipeline status* for completion
  (it sticks at `manual` with the pending manual jobs); poll the jobs.
  If it reports *"no pipeline … appeared within 10 min"*, the GitLab instance
  was just slow to register the push — **re-run the same command**; the script
  resumes (skips commit/push when there is nothing to commit) and picks up the
  pipeline for the current HEAD.
- CLI: argparse subcommands; success → JSON to stdout; failure → message +
  non-zero exit.
- Timestamps: use `parse_timestamp`/`format_timestamp` from `app/config.py`.
- Never restart the NPM container; only `nginx -s reload`.
- Host identity = MAC + port (unique pair).
- Ruff: E+F, long lines allowed. Tests: pytest-asyncio auto mode.
- **Scanner backward-compat contract:** every scanner function accepts
  `subnets: Optional[list[str]] = None` and preserves historic behaviour when
  `None`. Do not make `subnets` a required arg.
- **Seeder introspection contract:** every INSERT in `seed_dev.py` must be
  preceded by a `_fills_for(conn, table, known)` call that introspects the
  table and auto-fills NOT-NULL-with-no-default columns not in `known`. If you
  add a new table or a new required column to an INSERT, add it to
  `_KNOWN_COLUMNS_WITH_DEFAULTS` (or the `known` set) so the introspection
  knows how to fill it.
- **Templates use the Tailwind Play CDN** (`base.html`: `<script
  src="https://cdn.tailwindcss.com">`), so ANY Tailwind class works — there is no
  build step / content-scan to update. Theme is class-based dark mode (`.dark` on
  `<html>`, toggled in `base.html`). The global `<style>` in `base.html` forces
  `input[type=text]/[number]/[password]/[email]`, `select`, `textarea` colours;
  `host_form.html` uses a `.form-control` helper class, `settings.html` inlines
  the same classes per-input.
- **UI layout:** `base.html` renders `<main class="max-w-6xl mx-auto px-4 sm:px-6
  lg:px-8 py-8">`; each page wraps its own content in a narrower `max-w-*`
  (`settings.html` + `host_form.html` = `max-w-xl`; `diagnostic.html` = none).
  To widen a page, change *its own* `max-w-*` wrapper, not the `<main>`.

