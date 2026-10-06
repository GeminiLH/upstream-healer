# Upstream Healer — Comprehensive Implementation Plan

> Generated: 2026-10-05  
> Codebase: 4982 lines across 7 Python files + 8 templates  
> Stack: FastAPI + aiosqlite + Jinja2 + arp-scan/scapy + Nginx Proxy Manager (MariaDB)

---

## Table of Contents

1. [Current Architecture Overview](#1-current-architecture-overview)
2. [Data Models & Database Schema](#2-data-models--database-schema)
3. [Module Breakdown](#3-module-breakdown)
4. [API Endpoints Inventory](#4-api-endpoints-inventory)
5. [Key Workflows](#5-key-workflows)
6. [Integration Points](#6-integration-points)
7. [Testing Strategy](#7-testing-strategy)
8. [Deployment & CI/CD](#8-deployment--cicd)
9. [Known Limitations & Technical Debt](#9-known-limitations--technical-debt)
10. [Future Enhancements](#10-future-enhancements)

---

## 1. Current Architecture Overview

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Upstream Healer (FastAPI)                    │
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ Dashboard│  │ Settings │  │Diagnostic│  │ Notifications    │   │
│  │  (HTML)  │  │  (HTML)  │  │  (HTML)  │  │  (HTML)          │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘   │
│       │              │              │                 │             │
│  ┌────▼──────────────▼──────────────▼─────────────────▼─────────┐  │
│  │                    app/main.py (1670 lines)                   │  │
│  │  - FastAPI routes (dashboard, hosts CRUD, settings,          │  │
│  │    notifications, diagnostics, subnet management)            │  │
│  └──────────────────────────┬───────────────────────────────────┘  │
│                             │                                      │
│  ┌──────────────────────────▼───────────────────────────────────┐  │
│  │                  app/services/                                │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────┐  │  │
│  │  │ scanner.py │ │ monitor.py │ │   npm.py   │ │ mdns.py  │  │  │
│  │  │ (2008 lines│ │ (450 lines│ │ (275 lines)│ │ (160 lines│  │  │
│  │  └────────────┘ └────────────┘ └────────────┘ └──────────┘  │  │
│  │  ┌────────────┐ ┌────────────┐                               │  │
│  │  │notifications│ │  diag_log │                               │  │
│  │  │ (147 lines)│ │ (174 lines)│                               │  │
│  │  └────────────┘ └────────────┘                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                             │                                      │
│  ┌──────────────────────────▼───────────────────────────────────┐  │
│  │                  app/database.py (204 lines)                  │  │
│  │  - SQLite schema + migrations + init                          │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                             │                                      │
│              ┌──────────────┴──────────────┐                       │
│              ▼                              ▼                       │
│  ┌────────────────────┐       ┌────────────────────┐              │
│  │  SQLite DB         │       │  Nginx Proxy Mgr   │              │
│  │  (/data/healer.db) │       │  (MariaDB via      │              │
│  │                    │       │  Docker exec)      │              │
│  └────────────────────┘       └────────────────────┘              │
│                                                                    │
│  External: arp-scan, scapy, nmap, ping, ip, mDNS (zeroconf)       │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Silent operation**: Designed to be unobtrusive — no loud logging, graceful degradation
- **Best-effort discovery**: mDNS, ARP scans, and NPM integration all degrade gracefully
- **MAC-based identity**: Hosts are identified by MAC address (not IP), allowing IP changes to be handled
- **Multi-port monitoring**: Single device can be monitored on multiple ports (same MAC, different ports)
- **Quiet periods**: Hosts can have configured quiet hours to suppress monitoring
- **NPM auto-healing**: When a device's IP changes, Nginx Proxy Manager proxy hosts are automatically updated

---

## 2. Data Models & Database Schema

### Tables

#### `hosts` — Device registry
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AUTOINCREMENT | Primary key |
| `name` | TEXT NOT NULL | Display name |
| `local_device_name` | TEXT | Internal device name |
| `quiet_enabled` | INTEGER DEFAULT 0 | Quiet period enabled |
| `quiet_start` | TEXT | Quiet period start (HH:MM) |
| `quiet_end` | TEXT | Quiet period end (HH:MM) |
| `quiet_mode` | TEXT DEFAULT 'suppress' | 'suppress' or 'monitor' |
| `domain` | TEXT | Optional domain for NPM |
| `mac_address` | TEXT NOT NULL | MAC address (normalized) |
| `current_ip` | TEXT | Last known IP |
| `npm_proxy_host_id` | INTEGER | Linked NPM proxy host |
| `port` | INTEGER DEFAULT 80 | Port to monitor |
| `grace_minutes` | INTEGER DEFAULT 10 | Grace period before alerting |
| `enabled` | INTEGER DEFAULT 1 | Monitoring enabled |
| `subnet_id` | INTEGER | FK → subnets.id |
| `subnet_cidr` | TEXT | Fallback subnet CIDR |
| `notes` | TEXT | Free-form notes |
| `created_at` | TEXT | ISO timestamp |
| `updated_at` | TEXT | ISO timestamp |

**Uniqueness**: `(mac_address, port)` — same device on different ports is allowed.

#### `subnets` — Network segments
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AUTOINCREMENT | Primary key |
| `name` | TEXT NOT NULL | Display name |
| `cidr` | TEXT NOT NULL | e.g., `192.168.86.0/24` |
| `interface` | TEXT | Egress interface |
| `enabled` | INTEGER DEFAULT 1 | Monitoring enabled |
| `check_interval_seconds` | INTEGER | Custom interval |

#### `settings` — Key-value store
| Column | Type | Notes |
|--------|------|-------|
| `key` | TEXT PK | Setting key |
| `value` | TEXT | Setting value |

**Default settings**: `grace_minutes=10`, `check_interval_seconds=600`, `event_retention_days=10`, `telegram_enabled=1`, `email_enabled=1`

#### `notification_channels` — Notification endpoints
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AUTOINCREMENT | Primary key |
| `type` | TEXT NOT NULL | 'telegram' or 'email' |
| `name` | TEXT NOT NULL | Display name |
| `enabled` | INTEGER DEFAULT 1 | Channel enabled |
| `config` | TEXT NOT NULL | JSON config |
| `created_at` | TEXT | ISO timestamp |

#### `notification_rules` — Event-to-channel mapping
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AUTOINCREMENT | Primary key |
| `event_type` | TEXT NOT NULL | Event type |
| `channel_id` | INTEGER NOT NULL | FK → notification_channels.id |
| `enabled` | INTEGER DEFAULT 1 | Rule enabled |

**Event types**: `unreachable`, `scan_started`, `ip_found`, `updated`, `recovered`, `failed`, `manual`

#### `events` — Audit log
| Column | Type | Notes |
|--------|------|-------|
| `id` | INTEGER PK AUTOINCREMENT | Primary key |
| `host_id` | INTEGER | FK → hosts.id (nullable) |
| `event_type` | TEXT NOT NULL | Event type |
| `message` | TEXT | Human-readable message |
| `details` | TEXT | Additional details |
| `created_at` | TEXT | ISO timestamp |

**Retention**: Old events cleaned up based on `event_retention_days` setting.

#### `host_state` — Runtime state
| Column | Type | Notes |
|--------|------|-------|
| `host_id` | INTEGER PK | FK → hosts.id (CASCADE) |
| `status` | TEXT DEFAULT 'unknown' | 'healthy', 'unreachable', 'recovering', 'maintenance' |
| `last_seen_at` | TEXT | ISO timestamp |
| `unreachable_since` | TEXT | ISO timestamp |
| `last_check_at` | TEXT | ISO timestamp |
| `last_ip` | TEXT | Last IP seen |
| `quiet_active` | INTEGER DEFAULT 0 | In quiet period? |
| `quiet_mode` | TEXT | Quiet mode from host |

#### `mdns_names` — mDNS hostname cache
| Column | Type | Notes |
|--------|------|-------|
| `mac` | TEXT PK | MAC address |
| `hostname` | TEXT NOT NULL | Hostname |
| `updated_at` | TEXT | ISO timestamp |

---

## 3. Module Breakdown

### 3.1 `app/main.py` (1670 lines) — FastAPI Application

**Purpose**: HTTP API and HTML template rendering for the web UI.

#### Pydantic Models

| Class | Fields | Purpose |
|-------|--------|---------|
| `ScanRequest` | `target_mac`, `method`, `subnet_id`, `subnet_cidr`, `scan_ports` | Diagnostic scan request |
| `ValidateHostRequest` | `port` | Validate existing host |
| `ValidateNewHostRequest` | `name`, `mac_address`, `port` | Validate new host data |

#### Route Handlers

| Route | Method | Function | Description |
|-------|--------|----------|-------------|
| `/` | GET | `dashboard()` | Main dashboard — renders all hosts with status |
| `/hosts/<id>/events` | GET | `host_events()` | Event log for a specific host |
| `/api/events/<id>/clear` | POST | `clear_events()` | Clear events for a host |
| `/hosts/add` | GET | `add_host_form()` | Add host form |
| `/hosts/add` | POST | `add_host()` | Create a new host |
| `/hosts/<id>/edit` | GET | `edit_host_form()` | Edit host form |
| `/hosts/<id>/edit` | POST | `edit_host()` | Update a host |
| `/hosts/<id>/delete` | POST | `delete_host()` | Delete a host |
| `/hosts/<id>/force-scan` | POST | `force_scan()` | Trigger manual scan for a host |
| `/api/hosts/validate` | POST | `validate_host()` | Validate host record |
| `/api/hosts/validate-new` | POST | `validate_new_host()` | Validate new host data |
| `/notifications` | GET | `notifications_page()` | Notifications config page |
| `/notifications/telegram/add` | GET | `add_telegram_form()` | Add Telegram form |
| `/notifications/telegram/edit/<id>` | GET | `edit_telegram_form()` | Edit Telegram form |
| `/notifications/telegram/add` | POST | `add_telegram()` | Add Telegram channel |
| `/notifications/telegram/edit/<id>` | POST | `edit_telegram()` | Edit Telegram channel |
| `/notifications/email/add` | GET | `add_email_form()` | Add Email form |
| `/notifications/email/add` | POST | `add_email()` | Add Email channel |
| `/notifications/channel/<id>/toggle` | POST | `toggle_channel()` | Toggle channel on/off |
| `/notifications/rule/<id>/<event>/toggle` | POST | `toggle_rule()` | Toggle notification rule |
| `/notifications/channel/<id>/delete` | POST | `delete_channel()` | Delete notification channel |
| `/settings` | GET | `settings_page()` | Settings page |
| `/settings/subnets/add` | POST | `add_subnet()` | Add a subnet |
| `/settings/subnets/<id>/toggle` | POST | `toggle_subnet()` | Toggle subnet |
| `/settings/subnets/<id>/delete` | POST | `delete_subnet()` | Delete a subnet |
| `/settings/subnets/suppress` | POST | `suppress_subnet()` | Suppress auto subnet |
| `/settings/subnets/rescan` | POST | `rescan_subnet()` | Re-scan a subnet |
| `/settings/subnets/rescan-all` | POST | `rescan_all_subnets()` | Rescan all auto subnets |
| `/settings` | POST | `save_settings()` | Save global settings |
| `/diagnostic` | GET | `diagnostic_page()` | Diagnostic page |
| `/api/diagnostic/scan` | POST | `diagnostic_scan()` | Run a diagnostic scan |
| `/api/diagnostic/logs` | GET | `diagnostic_logs()` | Get scan log files |
| `/api/diagnostic/debug` | GET | `diagnostic_debug()` | NPM integration debug |
| `/api/health` | GET | `health()` | Health check endpoint |

#### Helper Functions (module-level)
- `_first_domain(domain_names)` — Extract first domain from comma-separated list
- `_subnet_for_ip(host, subnets)` — Find subnet for a host by IP
- `_npm_forward_for(npm_id)` — Get NPM forward address for a proxy host
- `_resolve_selected_subnet(subnets, host)` — Resolve selected subnet for host form
- `_parse_subnet_form(subnet_id)` — Parse subnet ID from form
- `_render_host_form(...)` — Render host add/edit form (reusable)
- `_render_host_form_conflict(...)` — Render conflict detection form

#### App Lifecycle
```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()           # Create tables, run migrations
    await monitor.start()     # Start the monitoring loop
    yield
    await monitor.stop()      # Graceful shutdown
```

---

### 3.2 `app/services/scanner.py` (2008 lines) — Network Scanner

**Purpose**: Discover devices on the LAN using ARP scanning, scapy, nmap, and mDNS.

#### Functions

| Function | Type | Description |
|----------|------|-------------|
| `normalize_mac(mac)` | sync | Normalize MAC to lowercase colon-separated |
| `find_ip_by_mac(target_mac, interface, subnets)` | async | Find IP for a MAC address (tries arp-scan → scapy) |
| `run_scan(target_mac, method, interface, subnets, scan_ports)` | async | Run one scanner, return JSON result |
| `_parse_scan_output(output, subnets)` | sync | Parse arp-scan/scapy output into host dicts |
| `resolve_hostnames(hosts, limit)` | async | Resolve hostnames via mDNS and reverse DNS |
| `load_known_hostnames(db)` | async | Load MAC→hostname from mdns_names cache |
| `load_known_hostnames_by_ip(db)` | async | Load IP→hostname from mdns_names cache |
| `remember_mdns_names(db, mac_map)` | async | Save mDNS-discovered names to DB |
| `load_mdns_names(db)` | async | Load cached mDNS names |
| `apply_hostnames(hosts, ip_map, mac_map, known_by_ip, known_by_mac)` | sync | Merge hostname maps onto host list |
| `_match_mac_in_output(target_mac, output, subnets)` | sync | Match target MAC in scan output |
| `run_arp_scan(subnets)` | sync | Execute `arp-scan` command, return (ip, output, error) |
| `_run_sweeps(sweep_cidrs, egress)` | sync | Run sweep scans on multiple CIDRs |
| `_plan_sweeps(subnets)` | sync | Plan sweep CIDRs from configured subnets |
| `_filter_and_dedupe(output, cidrs)` | sync | Filter/deduplicate scan output |
| `run_scapy_scan(target_mac, interface, subnets)` | sync | Scapy-based scan |
| `_scan_with_arp_scan(target_mac, subnets)` | async | Async wrapper for arp-scan |
| `_scan_with_scapy(target_mac, interface, subnets)` | async | Async wrapper for scapy |
| `_get_primary_ip()` | sync | Get primary interface IP |
| `ip_in_subnets(ip, subnets)` | sync | Check if IP is in any subnet |
| `get_local_ip_for_network(cidr)` | sync | Get local IP for a network |
| `get_default_subnets()` | sync | Discover auto-detected /24 subnets from `ip addr` |
| `get_local_interfaces()` | sync | List local IPv4 interfaces |
| `get_interface_flags(iface)` | sync | Get interface flags via `ip link show` |
| `is_tunnel_interface(iface, flags)` | sync | Check if interface is a tunnel |
| `interface_has_address_in(iface, cidr)` | sync | Check if interface has address in CIDR |
| `classify_subnet(cidr, explicit_iface)` | sync | Classify as L2 or L3 subnet |
| `subnet_is_l3_only(cidr, explicit_iface)` | sync | Check if subnet is L3-only (tunnel) |
| `_usable_hosts(cidr)` | sync | Generate usable hosts in a CIDR |
| `_l3_probe_egress(cidr, iface)` | sync | Find egress interface for L3 probe |
| `_l3_alive_scapy(hosts, egress, timeout)` | sync | Scapy-based L3 alive check |
| `_l3_alive_nmap(hosts, egress, timeout)` | sync | Nmap-based L3 alive check |
| `_l3_alive_ping(hosts, egress, concurrency)` | sync | Ping-based L3 alive check |
| `_host_line(ip, mac, routed, egress, via, hostname)` | sync | Format a host line for output |
| `run_l3_probe(cidrs, egress)` | sync | Run L3 probe on CIDRs |
| `run_nmap_scan(target_mac, subnets)` | sync | Nmap-based scan |
| `run_port_scan_incremental(hosts, method, max_ports, scan_ports)` | sync | Incremental port scan |
| `check_host_reachable(ip, port, timeout)` | sync | TCP connectivity check |
| `validate_host_record(host, db)` | sync | Validate a host record |

#### Scan Methods

1. **arp-scan** (default, fastest on Linux): Runs `arp-scan --localnet`, parses XML output
2. **scapy**: Uses Python scapy library for ARP requests
3. **nmap**: Uses `nmap -sn` for L3 discovery
4. **L3 probe**: For routed/tunneled subnets — uses ping, nmap, or scapy to check host liveness

#### Subnet Classification

```python
classify_subnet(cidr, explicit_iface) → dict:
    Returns:
    {
        "type": "L2" | "L3" | "auto" | "manual",
        "uses_arp": True | False,
        "uses_l3": True | False,
        "interface": str | None,
        "source": "auto" | "manual" | "suppressed",
    }
```

---

### 3.3 `app/services/monitor.py` (450 lines) — Monitoring Loop

**Purpose**: Periodic host health checking with auto-healing via NPM.

#### Class: `Monitor`

| Attribute | Type | Description |
|-----------|------|-------------|
| `running` | bool | Loop running flag |
| `_task` | asyncio.Task | Background task handle |
| `npm` | NPMClient | NPM integration client |
| `_last_event_cleanup_date` | date | Dedup for event cleanup |

| Method | Type | Description |
|--------|------|-------------|
| `start()` | async | Start the monitoring loop |
| `stop()` | async | Stop the monitoring loop |
| `_loop()` | async | Main monitoring loop |
| `_cleanup_old_events(db)` | async | Remove events older than retention |
| `_check_all_hosts(db)` | async | Check all enabled hosts |
| `_process_host(db, host)` | async | Process a single host |
| `_quiet_state(host)` | static | Check if host is in quiet period |

#### Monitoring Flow

```python
while self.running:
    check_interval = read from DB settings
    _cleanup_old_events()  # Once per day
    _check_all_hosts()     # Check every enabled host
    await asyncio.sleep(check_interval)
```

#### `_process_host` Decision Tree

```
1. Read host settings (grace_minutes, quiet_enabled, etc.)
2. Check quiet period → if active and mode='suppress': skip
3. check_host_reachable(ip, port) → is it alive?
4. If alive:
   - Update host_state to 'healthy'
   - Check if IP changed → NPM healing
   - If IP changed:
     a. find_ip_by_mac(new_mac) → find new IP
     b. npm.update_forward_host(npm_id, new_ip)
     c. npm.reload_nginx()
     d. Send 'updated' event
     e. Send 'recovered' event
   - Send notification if needed
5. If dead:
   - Track grace period
   - After grace expires: mark 'unreachable'
   - Try recovery:
     a. find_ip_by_mac(mac) → find new IP
     b. If found: try NPM update + recovery
     c. If not found: send 'unreachable' notification
```

---

### 3.4 `app/services/npm.py` (275 lines) — Nginx Proxy Manager Integration

**Purpose**: Connect to NPM's MariaDB database via Docker exec to auto-update proxy hosts.

#### Class: `NPMClient`

| Attribute | Type | Description |
|-----------|------|-------------|
| `_client` | docker.DockerClient | Docker client (lazy init) |
| `container_name` | str | NPM app container name |
| `_docker_available` | bool | Docker availability cache |
| `_db_creds` | dict | Cached DB credentials |

| Method | Type | Description |
|--------|------|-------------|
| `client` (property) | lazy | Initialize Docker client |
| `available` (property) | lazy | Check Docker availability |
| `_get_container()` | sync | Get NPM container reference |
| `exec(cmd)` | sync | Run command in NPM container |
| `_get_db_credentials()` | sync | Read DB_MYSQL_* from container env |
| `_get_connection()` | context | Get MariaDB connection |
| `get_proxy_host(npm_id)` | sync | Get a specific proxy host |
| `update_forward_host(npm_id, new_ip)` | sync | Update proxy host forward address |
| `list_proxy_hosts()` | sync | List all proxy hosts |
| `reload_nginx()` | sync | Graceful nginx reload |
| `get_all_hosts()` | sync | Get all NPM proxy hosts |
| `scan_types()` | static | Return available scanner types |

#### Credential Discovery

1. Primary: Read `DB_MYSQL_*` env vars from NPM container via `docker exec`
2. Fallback: Use `NPM_DB_*` settings from healer config
3. Never stored permanently — read on each connection

---

### 3.5 `app/services/notifications.py` (147 lines) — Notification System

**Purpose**: Send event notifications via Telegram and Email.

#### Constants
- `EVENT_TYPES`: `unreachable`, `scan_started`, `ip_found`, `updated`, `recovered`, `failed`, `manual`
- `IP_ADDRESS` regex: Matches IPv4 addresses
- `MAC_ADDRESS` regex: Matches colon/hyphen-separated and dot-separated MACs

#### Functions

| Function | Description |
|----------|-------------|
| `send_event(db, event_type, message, details, host_id, notify)` | Log event + send to enabled channels |
| `_send_telegram(config, message, details)` | Send Telegram notification (strips IPs/MACs for privacy) |
| `_send_email(config, message, details)` | Send SMTP email |

#### Privacy Note
Both Telegram and Email notifications strip IP addresses and MAC addresses from messages before sending (to avoid leaking network topology to external services).

---

### 3.6 `app/services/mdns.py` (160 lines) — mDNS Hostname Discovery

**Purpose**: Discover hostnames via mDNS/Zeroconf browsing.

#### Functions

| Function | Description |
|----------|-------------|
| `instance_display_name(fqdn)` | Extract human name from mDNS instance FQDN |
| `instance_mac(fqdn)` | Extract MAC from mDNS instance name |
| `_discover_sync(timeout)` | Blocking mDNS browse (runs in thread) |
| `discover_hostnames(timeout)` | Async wrapper for mDNS discovery |

#### Service Types Browsed
`_http`, `_https`, `_airplay`, `_raop`, `_ipp`, `_ipps`, `_ippPrint`, `_print`, `_smb`, `_ssh`, `_workstation`, `_raspberryPi`, `_raspberry-pi`, `_plex`, `_discord`, `_googlecast`, `_pulseaudio`

---

### 3.7 `app/services/diag_log.py` (174 lines) — Diagnostic Logging

**Purpose**: Log scan results to files for diagnostic review.

#### Functions

| Function | Description |
|----------|-------------|
| `emit(event, *fields)` | Log a diagnostic event |
| `recent_scans(limit)` | List recent scan log files |
| `clear_scans()` | Clear old scan logs |

---

### 3.8 `app/database.py` (204 lines) — Database Initialization

**Purpose**: Create tables, run migrations, seed defaults.

#### Key Functions

| Function | Description |
|----------|-------------|
| `init_db()` | Create tables, run migrations, seed settings |
| `_migrate_host_identity(db)` | Migrate from MAC-only to MAC+port uniqueness |
| `get_db()` | Async database connection generator |

#### Migration Strategy
- Uses `PRAGMA table_info()` to detect missing columns
- Adds missing columns via `ALTER TABLE ADD COLUMN`
- Complex migrations (like the uniqueness constraint change) use CREATE TABLE AS pattern

---

### 3.9 `app/config.py` (68 lines) — Configuration

**Purpose**: Application settings via pydantic-settings.

#### Settings Class
| Setting | Default | Description |
|---------|---------|-------------|
| `data_dir` | `/data` | Data directory |
| `db_path` | `/data/healer.db` | SQLite database path |
| `npm_container` | `nginx-app-1` | NPM app container name |
| `npm_db_path_in_container` | `/data/database.sqlite` | NPM SQLite path (fallback) |
| `npm_db_host` | `nginx-db-1` | NPM MariaDB host |
| `npm_db_port` | `3306` | NPM MariaDB port |
| `npm_db_user` | `` | NPM DB user |
| `npm_db_password` | `` | NPM DB password |
| `npm_db_name` | `proxy_manager` | NPM DB name |
| `default_grace_minutes` | `10` | Default grace period |
| `check_interval_seconds` | `600` | Default check interval |
| `scan_timeout_seconds` | `30` | Default scan timeout |
| `timezone` | `America/New_York` | UI timezone |
| `host` | `0.0.0.0` | Bind address |
| `port` | `8787` | Bind port |

---

## 4. API Endpoints Inventory

### HTML Pages (Jinja2 Templates)

| URL | Template | Data Passed |
|-----|----------|-------------|
| `/` | `dashboard.html` | hosts, npm_hosts, time_ago |
| `/hosts/add` | `host_form.html` (add mode) | subnets, npm_hosts |
| `/hosts/<id>/edit` | `host_form.html` (edit mode) | host, subnets, npm_hosts |
| `/hosts/<id>/events` | `host_events.html` | host, events, time_ago |
| `/notifications` | `notifications.html` | channels, rules, EVENT_TYPES |
| `/settings` | `settings.html` | settings, subnets, auto_subnets, local_interfaces, suppressed_cidrs |
| `/diagnostic` | `diagnostic.html` | npm_hosts, db_hosts, npm, scan_types |

### JSON API Endpoints

| URL | Method | Description |
|-----|--------|-------------|
| `/api/events/<id>/clear` | POST | Clear events for a host |
| `/api/hosts/validate` | POST | Validate existing host |
| `/api/hosts/validate-new` | POST | Validate new host data |
| `/api/diagnostic/scan` | POST | Run diagnostic scan |
| `/api/diagnostic/logs` | GET | Get scan log files |
| `/api/diagnostic/debug` | GET | NPM debug info |
| `/api/health` | GET | Health check |

### POST Form Endpoints (Redirect-After-Post)

All POST endpoints use RedirectResponse with status 303 to implement the Post/Redirect/Get pattern.

---

## 5. Key Workflows

### 5.1 Host Monitoring Cycle

```
┌─────────────────────────────────────────────────────────────────┐
│                    Monitor._loop()                              │
│                                                                 │
│  every check_interval_seconds (default 600s):                   │
│    1. Read check_interval from DB                               │
│    2. _cleanup_old_events() — once per day                      │
│    3. _check_all_hosts():                                       │
│       For each enabled host:                                    │
│         a. Check quiet period                                   │
│         b. check_host_reachable(ip, port)                       │
│         c. If alive → update state, check IP changes            │
│         d. If dead → track grace, try recovery                  │
│         e. Send notifications as needed                         │
│    4. await asyncio.sleep(check_interval)                       │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 MAC-Based Healing Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│              MAC-Based Healing (Automatic)                      │
│                                                                 │
│  1. Host unreachable → grace period expires                    │
│  2. find_ip_by_mac(mac_address) → scan LAN for MAC             │
│  3. If IP found (new_ip):                                      │
│     a. check_host_reachable(new_ip, port) → is it alive?       │
│     b. If alive:                                               │
│        - hosts.current_ip = new_ip                             │
│        - host_state.status = 'healthy'                          │
│        - host_state.last_check_at = now                         │
│        - host_state.last_ip = new_ip                            │
│        - If npm_proxy_host_id set:                             │
│          - NPMClient.update_forward_host(npm_id, new_ip)       │
│          - NPMClient.reload_nginx()                             │
│        - send_event('recovered', ...)                           │
│        - send_event('updated', ...)                             │
│        - Send notification                                      │
│     c. If not alive:                                           │
│        - host_state.last_ip = new_ip                            │
│        - host_state.status = 'unreachable'                      │
│        - send_event('failed', ...)                              │
│  4. If MAC not found:                                          │
│     - host_state.status = 'unreachable'                         │
│     - send_event('unreachable', ...)                            │n
│     - Send notification                                         │
└─────────────────────────────────────────────────────────────────┘
```

### 5.3 Host Add/Edit Flow

```
1. User submits form (name, mac, port, subnet, npm_id, etc.)
2. _parse_subnet_form() → (subnet_id, subnet_cidr)
3. validate_host_record() → checks MAC uniqueness, format
4. Check for existing host with same MAC+port → conflict?
5. INSERT or UPDATE hosts table
6. Redirect to dashboard or host edit form
```

### 5.4 Diagnostic Scan Flow

```
1. User selects method (arp-scan/scapy/nmap), target MAC, subnet
2. POST /api/diagnostic/scan
3. run_scan() → dispatches to appropriate scanner
4. resolve_hostnames() → mDNS + reverse DNS
5. Return JSON: {method, found_ip, output, error, hosts}
6. Optional: diag_log.emit() → saves to /tmp/healer_diag_logs/
```

### 5.5 Subnet Management Flow

```
Auto-detection:
  get_default_subnets() → reads `ip -4 -o addr` → finds /24 networks

Manual management:
  add_subnet() → INSERT into subnets table
  toggle_subnet() → UPDATE enabled flag
  delete_subnet() → DELETE from subnets
  suppress_subnet() → Add to suppressed CIDRs list
  rescan_subnet() → Remove from suppressed CIDRs
  rescan_all_subnets() → Clear all suppressed CIDRs
```

---

## 6. Integration Points

### 6.1 External Tools

| Tool | Purpose | Dependency |
|------|---------|------------|
| `arp-scan` | Fast ARP discovery on Linux | System package |
| `scapy` | Python-based ARP scanning | Python package |
| `nmap` | L3 host discovery | System package |
| `ping` | L3 host liveness check | System package |
| `ip` (iproute2) | Interface/subnet discovery | System package |
| `zeroconf` | mDNS hostname discovery | Python package |
| `docker` (Python SDK) | NPM container interaction | Python package |
| `pymysql` | NPM MariaDB connection | Python package |

### 6.2 Nginx Proxy Manager Integration

```
Healer ← Docker Exec → NPM Container ← pymysql → NPM MariaDB
                                    ↓
                              Nginx (reloaded)
```

**Data flow**:
1. Monitor detects IP change via MAC scan
2. NPMClient connects to NPM's MariaDB
3. Updates `proxy_host.forward_host` for matching proxy host
4. Runs `nginx -t && nginx -s reload`
5. Records event and notifies

### 6.3 Notification Channels

```
Monitor.send_event() →
  ├─ Telegram (httpx.AsyncClient → api.telegram.org)
  └─ Email (aiosmtplib → SMTP server)
```

**Privacy**: All notifications strip IP addresses and MAC addresses before sending.

---

## 7. Testing Strategy

### Current Tests (14+ test files)

| Test File | Coverage Area |
|-----------|---------------|
| `test_scanner.py` | Scanner functions |
| `test_main.py` | Main app routes |
| `test_seed_dev.py` | Development seeding |
| `test_cli.py` | CLI tools |
| `test_diag_log.py` | Diagnostic logging |
| `test_e2e_host_management.py` | E2E host CRUD |
| `test_e2e_notifications.py` | E2E notifications |
| `test_e2e_subnet_management.py` | E2E subnet mgmt |
| `test_npm.py` | NPM integration |
| `test_monitor_recovery.py` | Monitor recovery |
| `test_mdns.py` | mDNS discovery |
| `test_notifications.py` | Notification system |
| `test_api_endpoints.py` | API endpoints |
| `test_config.py` | Configuration |
| `test_database.py` | Database operations |
| `test_e2e_cross_component_integration.py` | Cross-component |
| `test_e2e_error_conditions.py` | Error handling |

### Test Infrastructure

- **Framework**: pytest with async support
- **Database**: aiosqlite in-memory for unit tests
- **HTTP Client**: httpx.AsyncClient for route testing
- **Fixtures**: `conftest.py` provides app, db, and client fixtures
- **E2E Tests**: Full integration tests against running FastAPI app

### Test Commands

```bash
# Run all tests
python3 -m pytest tests/ -q

# Run with coverage
python3 -m pytest tests/ --cov=app --cov-report=term-missing

# Run specific test file
python3 -m pytest tests/test_scanner.py -v
```

---

## 8. Deployment & CI/CD

### Docker Deployment

```dockerfile
FROM python:3.12-slim-bookworm
# Installs: gcc, arp-scan, scapy dependencies, nmap, ping, iproute2
# Copies: app/, requirements.txt
# Runs: pip install -r requirements.txt
# Exposes: 8787
# Command: uvicorn app.main:app --host 0.0.0.0 --port 8787
```

### Docker Compose

```yaml
services:
  upstream-healer:
    build: .
    network_mode: host  # Required for ARP scanning
    volumes:
      - /data:/data
    environment:
      - NPM_DB_HOST=nginx-db-1
      - NPM_DB_USER=...
      - NPM_DB_PASSWORD=...
```

### GitLab CI/CD Pipeline

```yaml
stages:
  - lint           # ruff check (~17s)
  - test           # pytest (~150s)
  - build_image    # Docker build (~37s)
  - deploy         # Manual trigger
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `NPM_CONTAINER` | NPM app container name |
| `NPM_DB_HOST` | NPM MariaDB host |
| `NPM_DB_PORT` | NPM MariaDB port |
| `NPM_DB_USER` | NPM DB user |
| `NPM_DB_PASSWORD` | NPM DB password |
| `NPM_DB_NAME` | NPM DB name |
| `TZ` | Timezone for UI |
| `UPSTREAM_HEALER_DEBUG_LOG_DIR` | Debug log directory (dev only) |

---

## 9. Known Limitations & Technical Debt

### 9.1 Architecture

1. **Single monolithic main.py** (1670 lines): All routes in one file. Should be split into routers.
2. **No Alembic migrations**: Custom migration logic in `database.py` using `PRAGMA table_info`. Alembic directory exists but is not used.
3. **No API versioning**: All endpoints are at root level.
4. **No authentication**: The app has no auth — it's designed for trusted networks.

### 9.2 Scanner

1. **arp-scan dependency**: Not available on Windows; fallback is scapy (slower).
2. **mDNS timeout**: Fixed 8-second timeout; may miss slow devices.
3. **No DNS resolution**: Only mDNS and reverse DNS; no forward DNS lookup.
4. **L3 probe**: Tunnel interface detection uses heuristic (interface name prefixes).

### 9.3 NPM Integration

1. **Docker dependency**: Requires Docker socket access to exec into NPM container.
2. **Single NPM instance**: No support for multiple NPM deployments.
3. **No API usage**: Connects directly to MariaDB instead of using NPM's REST API.
4. **No rollback**: If nginx reload fails, no automatic rollback.

### 9.4 Monitoring

1. **No rate limiting**: All hosts checked simultaneously.
2. **No backoff**: Fixed check interval; no adaptive interval based on host behavior.
3. **Single monitor instance**: No distributed monitoring.
4. **No alerting escalation**: Single notification level.

### 9.5 Database

1. **SQLite**: Not suitable for high-concurrency or multi-instance deployments.
2. **No connection pooling**: Each request opens a new connection.
3. **No data export**: No backup/export functionality.

---

## 10. Future Enhancements

### 10.1 Short-Term (High Impact)

1. **Route splitting**: Move route handlers from `main.py` into `app/routers/` submodules.
2. **API authentication**: Add JWT or API key auth.
3. **REST API**: Add proper JSON API endpoints (currently mostly HTML).
4. **Health check improvements**: Add SQLite connectivity check.
5. **Config validation**: Add runtime validation for NPM credentials.

### 10.2 Medium-Term

1. **Alembic migrations**: Replace custom migration logic.
2. **Redis caching**: Cache mDNS names, ARP results.
3. **Webhook notifications**: Add generic webhook support.
4. **Dashboard improvements**: Real-time status updates via WebSocket.
5. **Multi-NPM support**: Support multiple NPM deployments.

### 10.3 Long-Term

1. **PostgreSQL/MySQL**: Replace SQLite for production use.
2. **Distributed monitoring**: Support multiple healer instances.
3. **Machine learning**: Predictive failure detection.
4. **Plugin system**: Extensible scanner methods.
5. **REST API v2**: Versioned API with OpenAPI docs.

---

## Appendix A: File Sizes

| File | Lines | Size |
|------|-------|------|
| `app/main.py` | 1,670 | ~70KB |
| `app/services/scanner.py` | 2,008 | ~85KB |
| `app/services/monitor.py` | 450 | ~18KB |
| `app/services/npm.py` | 275 | ~11KB |
| `app/services/notifications.py` | 147 | ~6KB |
| `app/services/mdns.py` | 160 | ~6KB |
| `app/services/diag_log.py` | — | ~17KB |
| `app/database.py` | 204 | ~8KB |
| `app/config.py` | 68 | ~3KB |
| **Total source** | **4,982** | **~224KB** |

## Appendix B: Template Files

| Template | Purpose | Last Modified |
|----------|---------|---------------|
| `base.html` | Base template | Sep 14 |
| `dashboard.html` | Main dashboard | Sep 23 |
| `host_form.html` | Add/edit host form | Sep 23 |
| `host_events.html` | Host event log | Aug 23 |
| `diagnostic.html` | Diagnostic page | Sep 28 |
| `notifications.html` | Notification config | Aug 23 |
| `settings.html` | Settings page | Sep 19 |
| `channel_email.html` | Email config partial | Aug 23 |
| `channel_telegram.html` | Telegram config partial | Aug 23 |

## Appendix C: Dependency Tree

```
upstream-healer
├── fastapi
├── uvicorn[standard]
├── jinja2
├── python-multipart
├── aiosqlite
├── httpx
├── aiosmtplib
├── docker (Python SDK)
├── pymysql
├── pydantic-settings
├── scapy
├── zeroconf
└── nmap (optional, system)
```

---

*This plan is a living document. Update it as the codebase evolves.*
