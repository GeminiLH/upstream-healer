# Architecture — Upstream Healer

> Last updated: 2026-09-27 (scan-progress endpoint `d2b62f0` documented;
> diag_log service + dev-only scan-log endpoint; no-MAC sweeps now labeled via
> curated-IP / mDNS / reverse-DNS fallback).

## Repository

**GitLab is the primary repository.** `gitlab` remote →
`ssh://git@192.168.86.38:32768/monster/upstream_healer.git` (project
`monster/upstream_healer`; CI in `.gitlab-ci.yml`). Push explicitly with
`git push gitlab main`. `origin` → GitHub `GeminiLH/upstream-healer` is a
legacy mirror — never a push target, never delete (see decisions.md).

## Layout

```
upstream-healer/
├── app/
│   ├── main.py          # FastAPI app: web UI routes, JSON API, /diagnostic, monitor lifecycle
│   ├── cli.py           # `python -m app.cli` admin CLI (JSON out, non-zero exit on error)
│   ├── config.py        # pydantic Settings + timestamp helpers (parse/format/time_ago)
│   ├── database.py      # SQLite schema (CREATE TABLE IF NOT EXISTS) + migrations + get_db dep
│   ├── services/
│   │   ├── monitor.py       # Monitor: background loop, per-host checks, recovery flow
│   │   ├── scanner.py       # MAC→IP discovery: arp-scan→scapy sweep; hostnames; mDNS name cache;
│   │   │                    #   L3 probe for tunnel/routed subnets (scapy ICMP → nmap -sn → ping)
│   │   ├── mdns.py          # mDNS/avahi browse (zeroconf): live hostnames, runs alongside the sweep
│   │   ├── diag_log.py      # opt-in per-scan debug logs (dev-only via UPSTREAM_HEALER_DEBUG_LOG_DIR; recent_scans)
│   │   ├── npm.py           # NPMClient: NPM MariaDB access via docker; proxy_host updates
│   │   └── notifications.py # EVENT_TYPES; send_event → telegram + email channels
│   ├── templates/       # Jinja2: base, dashboard, host_form, host_events, notifications,
│   │                    #   settings, diagnostic, channel_telegram, channel_email
│   └── static/
├── scripts/seed_dev.py  # dev seeder (hosts + NPM proxy_host rows + links)
├── tests/               # pytest: test_cli, test_config, test_database, test_main,
│                        #   test_notifications, test_npm, test_scanner, test_seed_dev
├── docker-compose.yml       # prod (healer only)
├── docker-compose.dev.yml   # full dev stack: healer + NPM + MariaDB + seed
├── .gitlab-ci.yml           # CI: tests/lint/build + dev & deploy jobs
└── memory-bank/         # ← this knowledge base
```

## Configuration (`app/config.py` — `Settings`, pydantic-settings)

| Setting | Default | Notes |
|---|---|---|
| `npm_container` | `nginx-app-1` | NPM container name (overridable via env) |
| `npm_db_path_in_container` | `/data/database.sqlite` | (legacy SQLite path — NPM now uses MariaDB) |
| `npm_db_host` / `npm_db_port` / `npm_db_name` / `npm_db_user` / `npm_db_password` | `nginx-db-1` : 3306 / `proxy_manager` | MariaDB credentials discovered from container env (see decisions) |
| `default_grace_minutes` | 10 | before recovery triggers |
| `check_interval_seconds` | 600 | monitor loop cadence |
| `scan_timeout_seconds` | 30 | LAN scan timeout |
| `host` / `port` | 0.0.0.0 : 8787 | UI/API bind |
| `timezone` | `America/New_York` | timestamp handling |

## SQLite schema (`app/database.py`)

Tables: `hosts` (identity = MAC + port, unique), `settings`, `notification_channels`,
`notification_rules` (per event type), `events`, `host_state`.
- `hosts.npm_proxy_host_id` links a monitored host to an NPM proxy_host row.
- Migrations: `_migrate_host_identity` rebuilds `hosts` (table-rename pattern)
  when the identity definition changes. `init_db()` runs at startup.
- `data/` dir holds the dev DB on the shared checkout.

## Key flows

- **Monitor** (`services/monitor.py`): `Monitor.start()` launches a background
  loop (`_loop` → `_check_all_hosts` → `_process_host` per host) every
  `check_interval_seconds`; `_start_recovery` runs the full recover + notify
  flow; `_cleanup_old_events` prunes old events.
- **Scanner** (`services/scanner.py`): `find_ip_by_mac` tries `arp-scan` CLI
  first, falls back to scapy; `check_host_reachable(ip, port)` for liveness.
  Tunnel/routed subnets (no ARP broadcast) are probed at Layer 3 by
  `run_l3_probe` (scapy ICMP → `nmap -sn` → `ping`); `run_nmap_scan` is a
  selectable diagnostic method.
- **NPM** (`services/npm.py`, `NPMClient`): connects to NPM's MariaDB over
  the dev Docker network; `get_all_hosts()` returns non-deleted `proxy_host`
  rows; credentials cached after first discovery (see decisions.md).
- **Notifications** (`services/notifications.py`): `EVENT_TYPES` list;
  `send_event(event_type, ...)` fans out to enabled telegram/email channels
  respecting `notification_rules` per event type.
- **CLI** (`app/cli.py`): subcommands `add-host`, `list-hosts`, `list-npm-hosts`,
  `check-npm-db`, `edit-host`, `list-events`, `disable-host`, `add-telegram`,
  `list-telegram`, `disable-telegram`. All print JSON.

## Web surface (`app/main.py`)

- Dashboard + host CRUD + notifications + settings pages (templates)
- `/api/...` JSON endpoints; `/diagnostic` (HTML) + `/api/diagnostic` (JSON)
  expose NPM availability, proxy_host rows, and SQLite host rows.
- **Diagnostic hostname flow**: `run_scan` runs the ARP/L3 sweep (arp-scan→scapy,
  or `nmap -sn` for no-MAC) alongside `mdns.browse_mdns()` (8 s window, returns
  `{ip:name, mac:name}`); `apply_hostnames` layers known-DB → live-mDNS →
  cached-mDNS (`mdns_names`) → curated `hosts.current_ip` (for no-MAC sweeps) →
  reverse-DNS (`socket.gethostbyaddr(ip)[0]` — note the TUPLE; fixed in
  `7e091a9`) and sorts named-first; `remember_mdns_names` persists new names.
  Dev-only `GET /api/diagnostic/scan-log` (404 in prod / when
  `UPSTREAM_HEALER_DEBUG_LOG_DIR` unset) serves the newest `diag_*.log` for
  post-mortem detail; the diagnostic page has a "Scan debug log" button.
- **Scan progress (`d2b62f0`)**: `POST /api/diagnostic/scan` returns a
  `scan_id` immediately and runs the scan as a background task that publishes
  into the module-level `scan_progress` dict (states: `starting` →
  `discovered` → `scanning_ports` → `complete`/`error`). The diagnostic page
  polls `GET /api/diagnostic/scan-progress/{scan_id}`, which returns the state,
  partial `hosts` (incrementally as the port scan finishes each host),
  `elapsed_time`, and an ETA (`estimated_duration` ≈ 10 s/host, capped 300 s,
  → `estimated_completion` / `estimated_remaining`).
- **Host add/edit form (`host_form.html`) — "populate from NPM":** field order is
  Name → Local device name → **NPM Proxy Host ID** → Domain → MAC → Current IP →
  Port → Subnet → Grace → Notes → **Quiet time** → Enabled → buttons. The NPM
  `<select>` options carry `data-ip`/`data-port`/`data-domain`/`data-subnet`; an
  inline `<script>` after the form fills the corresponding inputs after a
  `confirm()` when the user picks a proxy host (subnet is set only if its CIDR is
  an option in the subnet dropdown). The backend (`_render_host_form`) enriches
  each proxy host: `domain = _first_domain(domain_names)` and
  `subnet = _subnet_for_ip(forward_host, subnets)` — the latter returns the first
  *known* subnet containing the IP, else the address's own /24 (`strict=False`),
  else `None` for a non-IPv4 forward host. All client-side + a render-time lookup;
  no extra endpoint.
