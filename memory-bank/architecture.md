# Architecture — Upstream Healer

> Last updated: 2026-07-09.

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
│   │   ├── scanner.py       # MAC→IP discovery: arp-scan first, scapy fallback; reachability check
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
- `/api/...` JSON endpoints; `/diagnostic` (HTML) + `/api/diagnostic`
  (JSON) expose NPM availability, proxy_host rows, and — in the current WIP —
  SQLite host rows for comparison.
