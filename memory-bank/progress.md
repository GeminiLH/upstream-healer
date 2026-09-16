# Progress — Upstream Healer

> Snapshot: 2026-09-16 — **multi-subnet support implemented, 150 tests pass,
> ruff clean, smoke-tested end-to-end.** Ready to commit + deploy.
> **Verify before acting**: `git status`, `git log -5`,
> then run `python3 -m pytest tests/ -q`.

## Current state

- Branch: `main` (tracking `gitlab/main`).
- HEAD (pre-this-feature): `5c480a9` (on-demand ARP/scapy scan on diagnostic;
  committed + deployed + live-verified 2026-09-16, pipeline 147 job 722 success).
- **Uncommitted WIP (this session):** multi-subnet support — scanner, monitor,
  database, main, templates, tests, and this memory-bank.
- **Health: 150 tests pass** (was 128; +22 new). **Ruff clean** (verify).
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
  - `run_scapy_scan(subnets=...)` loops CIDRs, picking egress iface via
    `conf.get_if_addresses()` when no explicit `interface`.
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

1. `git add -A && git commit -m "feat: multi-subnet support"` + push to
   `gitlab/main`. Watch the pipeline (tests + lint + build + deploy_dev).
2. After deploy, live-verify on the dev box:
   - `GET :8787/settings` → the Subnets card renders with auto-detected rows
     (the dev container has `iproute2`, so `get_default_subnets()` is non-empty).
   - Add a manual subnet; confirm it appears in the diagnostic page's scan
     dropdown (manual + auto, with the `auto` tag on the discovered ones).
   - Pin a host to a subnet, trigger a force-scan; confirm the `scan_started`
     event names the pinned subnet in the host's event log.
   - Run a scan scoped to a specific subnet from the diagnostic page; confirm
     the output is limited to that network.

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

