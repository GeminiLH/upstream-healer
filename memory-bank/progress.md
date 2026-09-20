# Progress — Upstream Healer

> Snapshot: 2026-09-20 — **L3 (tunnel/routed) discovery is SHIPPED + pipeline
> 181 is fixed**: `b09cd4d` failed CI on one test (scapy import-failure test —
> the `sys.modules` cached-submodule trap, see decisions.md) → `7e6577a` made
> the test hermetic → **pipeline 182 green** (lint / unit_tests / build_image).
> The dev box still runs the *previous* release — `deploy_dev` on 182 is
> `manual`, waiting on the user.
> **Verify before acting**: `git status`, `git log -5`, then
> `python3 -m pytest tests/ -q` (currently 255 passed, ruff clean).

## Current state

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

