# Progress — Upstream Healer

> Snapshot: 2026-09-20 — **Scan debug logging + positive-test seed shipped**
> (commit after this note; pipeline via `scripts/ship.sh`, then
> `deploy_dev` plays automatically). Changes: new `app/services/diag_log.py`
> (opt-in per-scan file logs: self-identity header, self-target WARNING,
> per-sweep classification/egress, raw tool output + exceptions; gated by
> `UPSTREAM_HEALER_DEBUG_LOG_DIR`, prod tripwire, capped + rotated, 10
> tests); scanner + `/api/diagnostic/scan` instrumented; dev compose mounts
> `/mnt/data/upstream-healer/logs` → `/logs` (base compose untouched —
> prod stays silent); seeder adds disabled `batcave` + `fash` (real devices,
> names for the diagnostic page); seed tests updated to 8 hosts.
> **Why now:** the user's three batcave diagnostic scans came back no-match
> (arp-scan + "enp6s0 is not a valid numeric value" ERROR / scapy silent /
> nmap no IP) — that ERROR is the scapy `int("enp6s0")` route bug fixed in
> `00062a6`, i.e. batcave runs a pre-00062a6 release; deploying the new build
> ships that fix + the L3/nmap release (b09cd4d) AND turns on logging.
> `deploy_dev` played via the GitLab API (ship.sh's background wait was
> reaped by the tool timeout; jobs 999/1000/1001 green, job 1003
> `deploy_dev` **succeeded** — the sandbox now runs `e650153`, which is
> the first image containing the `00062a6` scapy route fix + the L3/nmap
> release). **Deploy revealed:** the "no match" rows were hosts the user
> had *already* added via the UI — `batcave` (b4:2e…, current_ip NULL) and
> `flash` (dc:a6…, **ip 192.168.86.37**, enabled) — the page renders
> `ip_address if ip_address else hostname`, so they showed as nameless
> "Unresolved (nmap)" rows. The seeder added a second, disabled `batcave`
> row (port 8787 ≠ the user row's port → duplicate; harmless — tell the
> user it can be deleted) but NOT a fash duplicate (the user's `flash`
> row matched the (mac, port) dedupe).
> Verify before acting: `git status`, `git log -5`,
> `python3 -m pytest tests/ -q` (currently 265 passed, ruff clean).

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

