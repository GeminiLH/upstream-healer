# Progress — Upstream Healer

> Snapshot: 2026-09-16 — **scapy route-bug fixed + deployed to dev (pipeline 151,
> `00062a6`); now on UI polish** (the Settings screen is narrow and the "add
> subnet" form fields are self-evident to devs but not to the user — widening it
> + adding clear per-field hints is the next task, see "Next task" below).
> **Verify before acting**: `git status`, `git log -5`, then
> `python3 -m pytest tests/ -q`.

## Current state

- Branch: `main` (tracking `gitlab/main` — re-pointed on 2026-09-17 after it
  silently tracked `origin/main`; the NFS mount blocked git's config write, so
  `.git/config` was edited directly. GitLab is the primary repo, see decisions.md;
  a bare `git push` now goes to `gitlab`.)
- HEAD: `00062a6` (the scapy route-bug fix) — pushed to gitlab/main, **pipeline 151
  all-green**: `lint` / `unit_tests` (152 pass) / `build_image` all success, and
  **`deploy_dev` success** (live on the dev box `192.168.86.38:8787`).
- Just before it: `89ff442` (test-hermeticity fix, pipeline 149) ← `d6abef0`
  (the multi-subnet feature — scanner, monitor, database, main, templates, tests).
- **Health: 152 tests pass, ruff clean** (verified live: `unit_tests` job 752).
- The multi-subnet live smoke test (throwaway DB via `TestClient`) covered:
  `GET /settings` → 200 (Subnets card), `POST /settings/subnets` → 303,
  invalid CIDR → 400, `GET /diagnostic` renders `#scan-subnet`, `GET/POST
  /hosts/add` carry `subnet_id`.
- **Manual jobs in pipeline 151** (`deploy_test` / `deploy_production` /
  `dev_down` / `dev_debug`) are still `manual` — **trigger only on explicit user
  confirmation** (the scapy fix is live on dev; the user has *not* asked for
  test/prod yet).

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


## Next task (UI polish — Settings screen)

User request (2026-09-16, mid-task): *"make the settings screen wider for entering
new subnets, but also clarify what information you expect in the fields, including
what interfaces you expect. There is no reason to keep the screen narrow, but it
should size for a phone."*

**Target file: `app/templates/settings.html`** (template-only; no backend change).
Three pieces:

1. **Widen the page.** The whole page is wrapped in `<div class="max-w-xl">`
   (line 5) = max 576px — that is the bottleneck. Change to `max-w-3xl` or
   `max-w-4xl`. The outer `base.html` `<main>` is already `max-w-6xl`, so only
   this inner wrapper constrains it. `max-w-xl`/`3xl` are fine on phone because
   max-width is a *ceiling* — on a narrow viewport the content is `width:100%` +
   `px-4` padding, so this "widens on desktop, still full-width on a phone" with
   no media query. (`host_form.html` also uses `max-w-xl` — out of scope unless
   the user asks, but the same pattern applies.)

2. **Clarify the "add subnet" form** (the `POST /settings/subnets` form, ~line 101,
   `grid grid-cols-1 sm:grid-cols-4`). The 3 fields map to
   `app/main.py::add_subnet` (line 537):
   - **Name** (`name`, `required`, `Form(...)`) — *free-text friendly label*; what
     the user calls the network. Shown in the table + the host/diagnostic subnet
     dropdowns. e.g. `Home Wi-Fi`, `VLAN 20`, `Guest`. Not validated.
   - **CIDR** (`cidr`, `required`, `Form(...)`) — the **network CIDR**
     `<network>/<prefix>`. Validated with `ipaddress.ip_network(cidr, strict=False)`
     (line 549) — `strict=False` accepts non-zero host bits (`192.168.70.5/24` →
     normalised to `192.168.70.0/24`). **Emphasise in the hint: enter the whole
     network (`…0/24`), not a single host (`…5/32`).** A `/32` is one IP with no
     broadcast → can't be ARP-swept; the scanner now explains that (decisions.md "Scanner /
     multi-subnet gotchas" — the /32 bullet).
   - **Interface** (`interface`, optional, `Form("")` default, stored `None` if
     blank — line 555). The **egress NIC name** ARP/scapy packets leave via.
     Real values = `ip -o -4 addr` names like `enp6s0`, `eth0`, `en0`.
     **CRITICAL UX bug to fix:** the current placeholder is `auto`, but
     `interface="auto"` is treated as a *literal* NIC name and fails ("no such
     device")! Leave **blank** = auto (the scanner picks the local iface for that
     CIDR via `get_default_subnets`). Change the placeholder to `leave blank for
     auto` (or add a helper line) and note example local interface names.

   **Do NOT rename the form fields** (`name`/`cidr`/`interface`) or the
   `action="/settings/subnets"` — the handler reads them by those names.

3. **Responsive/phone sizing.** Keep the form's `grid-cols-1 sm:grid-cols-4`
   (already stacks to 1 column on phones; stays correct once the page is wider).
   The subnets **table** already sits in `overflow-x-auto` (scrolls on phones).

**Validation** (no tests touch templates — render check only): `ruff` clean; a
throwaway `TestClient` `GET /settings` (see `temp_db_file` in `tests/conftest.py`)
rendering the new width + hint text and still posting `name/cidr/interface` to
`/settings/subnets`; then commit → push → spawn pipeline → auto jobs →
`deploy_dev` **on the explicit user-confirmation pattern** (deploy_dev is manual).

## Done (recent history)

- **`412bda5` (2026-09-17)**: memory-bank commit (primary-repo rule + NFS
  gotchas) → pipeline 160 (`lint` / `unit_tests` / `build_image` all green) →
  `deploy_dev` job 811 **success** (34s); dev UI live (HTTP 200 on
  `192.168.86.38:8787`).
- **Fast ship workflow added: `scripts/ship.sh`** (2026-09-17) — one command
  for tests → commit → push gitlab → auto jobs → `deploy_dev`, ~6 min
  end-to-end (replaces the hand-rolled poll loops; see decisions.md). Hardened
  2026-09-18: token selection (`GITLAB_READ_TOKEN`), API preflight, 10-min
  pipeline-appear window, loud play-failure, resumable re-runs.

- Scapy route-bug fix (`00062a6`) is deployed to dev (pipeline 151). Live-verify
  on the dev box when convenient: pick a host pinned to a subnet and run a *scapy*
  diagnostic scan — it must sweep and return the full responder table (no
  `ERROR: "enp6s0" is not a valid numeric value`, no `(no ARP responses received)`).
  The `arp-scan` method is the primary path and always worked; the fix matters for
  the scapy fallback.
- User-facing: on Settings → Subnets, add the **network** CIDR (`…0/24`), not a
  single host (`/32`).

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

