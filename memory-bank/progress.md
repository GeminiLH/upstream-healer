# Progress — Upstream Healer

> Snapshot: 2026-09-16 — **multi-subnet support live + scapy route-bug fixed**
> (feature commit `d6abef0`; the one pipeline break it caused was fixed in
> `89ff442` — **verified green in pipeline 149**; a live smoke test then
> surfaced a scapy route bug in the scapy fallback that broke the *whole* ARP
> sweep, now fixed here — **152 tests pass, ruff clean, not yet committed**).
> **All done.**
> **Verify before acting**: `git status`, `git log -5`, then
> `python3 -m pytest tests/ -q`.

## Current state

- Branch: `main` (tracking `gitlab/main`).
- HEAD: `89ff442` (the test-hermeticity fix) — pushed to gitlab/main, **pipeline
  149 all-green** (`lint` / `unit_tests` 150 pass / `build_image` / `deploy_dev`
  all success; only manual jobs `deploy_test`/`deploy_production`/`dev_down` /
  `dev_debug` remain).
- Just before it: `d6abef0` (the multi-subnet feature — scanner, monitor,
  database, main, templates, tests).
- **Health: 150 tests pass, ruff clean.** Verified live (not just local): the
  `unit_tests` job 736 trace ends `150 passed, 1 warning in 12.37s`.
- The one pipeline break from `d6abef0` was environmental (tests depended on a
  writable `/data` that the `python:3.12-slim` runner lacks); fixed in `89ff442`
  by a `temp_db_file` fixture in `tests/conftest.py`.
- **Live smoke test passed** (throwaway DB via `TestClient`):
  - `GET /settings` → 200, renders the new "Subnets" card.
  - `POST /settings/subnets` (LAN / 192.168.10.0/24) → 303 redirect.
  - `POST /settings/subnets` with invalid CIDR → 400 "Invalid CIDR: 'not-a-cidr'".
  - `GET /diagnostic` → 200, renders `#scan-subnet` select.
  - `GET /hosts/add` → 200, renders the subnet `<select name="subnet_id">`.
  - `POST /hosts/add` with `subnet_id=1` → 303; verified `hosts.subnet_id=1`.

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


## Immediate next steps

1. **Commit + push** the scapy route-bug fix (scanner.py + test_scanner.py +
   this memory-bank update). The 152 tests pass locally and ruff is clean, but
   the fix is **not yet in a pipeline** — `unit_tests` in CI is the next gate.
   (CI runs scapy 2.6.1 on `python:3.12-slim`; the fix is version-agnostic —
   it never assigns `conf.iface`.)
2. **Live-verify the scapy path** after deploy: pick a host pinned to a subnet
   and run a *scapy* diagnostic scan (not arp-scan) — it must sweep **and**
   return the full responder table (no `ERROR: "enp6s0" is not a valid numeric
   value`, no `(no ARP responses received)`). The `arp-scan` method is the
   primary path and always worked; this fix matters for the scapy fallback.
3. **How to enter a subnet (user-facing):** on the Settings page → Subnets
   card, add the **network CIDR** (e.g. `192.168.70.0/24`), *not* a single host
   (`192.168.70.0/32` — that's one IP with no broadcast, so it can't be
   ARP-swept). Enter a `/32` and the scanner now says so explicitly instead of
   the old misleading "no local interface".
4. When ready, the manual jobs in the pipeline (`deploy_test`,
   `deploy_production`, `dev_down`) are still pending — trigger them only on
   explicit user confirmation.

## Conventions (keep these when editing)

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

