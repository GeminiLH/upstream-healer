# Upstream Healer — Comprehensive Implementation Plan

> Generated: 2026-10-05  
> Codebase: 4982 lines across 7 Python files + 8 templates  
> Stack: FastAPI + aiosqlite + Jinja2 + arp-scan/scapy + Nginx Proxy Manager (MariaDB)

---

## Table of Contents

0. [User Goals & Audiences](#0-user-goals--audiences)
1. [Current Architecture Overview](#1-current-architecture-overview)
2. [Data Models & Database Schema](#2-data-models--database-schema)
3. [Module Breakdown](#3-module-breakdown)
4. [API Endpoints Inventory](#4-api-endpoints-inventory)
5. [Key Workflows](#5-key-workflows)
  - 5.6 [First-Run Setup Experience](#56-first-run-setup-experience)
  - 5.7 [Validation & Assistance Contract](#57-validation--assistance-contract)
  - 5.8 [Notification Design](#58-notification-design)
  - 5.9 [Dashboard Specification](#59-dashboard-specification)
  - 5.10 [Language & Copy Guidelines](#510-language--copy-guidelines)
6. [Integration Points](#6-integration-points)
7. [Testing Strategy](#7-testing-strategy)
8. [Deployment & CI/CD](#8-deployment--cicd)
9. [Known Limitations & Technical Debt](#9-known-limitations--technical-debt)
10. [Future Enhancements](#10-future-enhancements)

---

## 0. User Goals & Audiences

> *Why we build this, who it's for, and what "good" looks like.*

### 0.1 Purpose

Upstream Healer keeps a home's **Nginx Proxy Manager (NPM) reverse proxy** running when backend devices (media servers, Home Assistant, NAS, etc.) lose their IP address — after a reboot, DHCP lease expiry, router reset, or power outage. It:

1. **Monitors** every important device on the LAN.
2. **Self-heals** by finding the device's new IP and updating NPM automatically.
3. **Notifies** the user when something needs attention — with privacy-preserving messages that never leak MAC or IP addresses to Telegram or Email.

### 0.2 Personas & Page Audiences

| Page | Who uses it | How often | What they need to know |
|------|-------------|-----------|----------------------|
| **Dashboard** (`/`) | **Everyone** (primary user) | Daily / glance | "Is my reverse proxy working?" |
| **Add Host** (`/hosts/add`) | **Primary user** | When adding a device | "What's my device name, MAC, and port?" |
| **Notifications** (`/notifications`) | **Primary user** (rare) | When configuring | "How do I get alerts? How do I stop them?" |
| **Settings** (`/settings`) | **Primary user** (rare) | Initial setup only | "What do these settings mean?" |
| **Diagnostics** (`/diagnostic`) | **Technical support** | When investigating | "Show me what the scanner found." |

**Design implications:**
- Dashboard and Add Host must be **intuitive, guided, and self-explanatory** — every field needs a plain-English helper text.
- Notifications and Settings are **rare but critical** — they need clear labels, sane defaults, and inline explanations.
- Diagnostics is a **technical tool** — raw output is fine here, but it must be clearly marked as diagnostic-only.

### 0.3 User-Facing Language Principles

| Technical term | User-facing term |
|----------------|-----------------|
| Subnet / CIDR | "Network segment" (e.g. "Home Network — 192.168.86.0/24") |
| NPM proxy host | "The NPM page for example.com" (name + domain) |
| Grace period | "Waiting period before alerting (default 10 minutes)" |
| MAC address | "Device identifier" — shown only in technical details, not in alerts |
| ARP scan | "Network scan for the device" |
| L2 / L3 probe | "Network scan method" (no need to expose this to users) |
| Quiet period | "Do-not-disturb window" (the UI says "Quiet time", but explanations use DND) |
| Suppressed CIDRs | "Networks to skip during scans" |

**Golden rule:** Never expose raw IP addresses or MAC addresses in outbound notifications (Telegram, Email). The local dashboard is safe — it's a trusted local interface. Outbound channels are not.

### 0.4 Notification Privacy Boundary

- **Dashboard / local API:** Full details (MAC, IP, subnet) are displayed — this is a trusted internal interface.
- **Telegram / Email:** Only the device **name** and the **event outcome** are sent. Any raw network identifiers in the message body are stripped.
- **Email parity:** Both Telegram and Email must apply the same sanitization. (See §3.5 for current implementation status — email is currently unsanitized and must be fixed.)

### 0.5 Privacy-First Notification Design

All outbound notifications must:
1. Contain **only** the device name and event outcome (e.g. "vault is reachable again", "media-server is unreachable").
2. Never contain raw IP addresses, MAC addresses, subnet CIDRs, or any network topology information.
3. Use plain language that any household member can understand.
4. Include a clear call-to-action if manual intervention is needed.

Example good notification:
> 🔔 **Upstream Healer**
> 
> ✅ **vault** is reachable again.

Example bad notification:
> ✅ vault is reachable again at 192.168.86.249

### 0.6 Page-Audience Matrix (Summary)

| Page | Primary user | Frequency | Knowledge level | Required in-page help |
|------|-------------|-----------|----------------|----------------------|
| Dashboard | Everyone | Daily / glance | None | Status legend, banner |
| Add Host | Primary | When needed | Basic (name, MAC, port) | Helper text on every field, validate button |
| Notifications | Primary | Rare | Basic | What each event type means, test button |
| Settings | Primary | Rare | Intermediate | Per-setting explanation, safe defaults |
| Diagnostics | Support | When investigating | Advanced | Scan method explanations |

### 0.7 Authentication as a User-Facing Requirement

Authentication is **not** tech debt — it is a user-facing security requirement. The application currently has no access control, which means anyone on the local network can:
- View all device names, MAC addresses, and IP addresses
- Add, edit, or delete monitored hosts
- Modify notification channels (add/remove/change)
- Trigger arbitrary network scans

**Required behavior:**
1. **Login page:** Simple username/password login on first visit (or redirect to `/login` if no user exists).
2. **Default credentials:** First-run creates an admin account; subsequent visits require authentication.
3. **Session management:** Persistent sessions with configurable timeout (default 24 hours).
4. **No public access:** All HTML pages and API endpoints require authentication unless explicitly marked public (e.g., health check).
5. **No hardcoded passwords:** Passwords must be hashed (bcrypt or argon2) and never stored in plaintext.
6. **Admin-only actions:** Adding/removing hosts, changing notification settings, and modifying NPM credentials require admin privileges.
7. **Audit trail:** All admin actions are logged in the event history.

**Migration from "tech debt":**
- This requirement was previously listed in §9.1 (Known Limitations) and §10.1 (Short-Term Enhancements) as "no authentication" and "API authentication."
- It is now promoted to a **core user-facing requirement** in §0.7.
- Remove from §9.1 (no longer tech debt — it's a requirement).
- Remove from §10.1 (no longer short-term enhancement — it's a requirement).

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
| `quiet_mode` | TEXT DEFAULT 'suppress' | 'suppress' (monitor but silence notifications) or 'delete' (skip checks entirely) |
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

- **Telegram:** Both message and details strip IP addresses and MAC addresses before sending (via regex substitution).
- **Email:** ⚠️ **Current implementation does NOT strip network identifiers.** The email handler (`_send_email`) sends the raw `message` and `details` unchanged. This must be fixed to match Telegram's behavior. Until then, email recipients receive full MAC and IP addresses.
- **Dashboard / local API:** No stripping — full details are appropriate for the trusted local interface.

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

### 5.6 First-Run Setup Experience

> *The make-or-break moment for average users. Every step must be guided and verifiable.*

#### 5.6.1 Setup Checklist / Wizard Flow

```
Step 1: NPM Connection Check
  → GET /api/setup/npm-check
  → Result: PASS (can reach NPM) or FAIL (with plain-English explanation)
  → If FAIL: Show where to find NPM MariaDB credentials
  → User action: Enter NPM DB credentials if auto-discovery fails

Step 2: Pick Proxy Hosts to Watch
  → GET /api/setup/npm-hosts (list all NPM proxy hosts)
  → User selects which proxy hosts to monitor
  → For each selected host:
    - System pre-fills: name, domain, forward_host, forward_port
    - System runs a background scan to find the device's MAC
    - User confirms: "This is the [device name] at [MAC]"
    - If scan fails: "Device not found — is it powered on?"

Step 3: Notification Channel Setup
  → GET /notifications/add/telegram or /notifications/add/email
  → Telegram: "Create a bot with @BotFather → Message it → Paste the chat ID"
  → Email: "Select provider (Gmail, Outlook, custom) → SMTP prefilled → Enter credentials"
  → TEST BUTTON: POST /notifications/channel/<id>/test
    - Sends a test notification to verify the channel works
    - Result: "Test notification sent — did you receive it?"

Step 4: Confirmation
  → "Setup complete: X devices being monitored, Y notification channels active"
  → "First test alert sent — if you see '[Upstream Healer] Setup complete' you're good"
  → Link to dashboard
```

#### 5.6.2 Provider Presets for Notification Channels

**Email presets:**
| Provider | SMTP host | Port |
|----------|-----------|------|
| Gmail | smtp.gmail.com | 587 |
| Outlook | smtp-mail.outlook.com | 587 |
| Yahoo | smtp.mail.yahoo.com | 587 |

**Telegram:**
- Step-by-step instructions inline (no presets needed — just @BotFather)

---

### 5.7 Validation & Assistance Contract

> *Every validation outcome must be actionable, not just an error string.*

#### 5.7.1 Validation Flow (Add/Edit Host)

```
User enters: name, MAC, port, (optionally) IP
  → POST /api/hosts/validate-new (for new hosts) or POST /hosts/<id>/validate (for edits)
  → System runs:
    1. MAC format check (normalize: aa:bb:cc:dd:ee:ff)
    2. Port range check (1–65535)
    3. If IP provided: check if IP is in a known subnet
    4. If MAC provided: run ARP scan to find current IP
    5. If scan finds device: show "Device found at [IP], MAC [MAC]"
    6. If scan finds wrong MAC: "IP [IP] belongs to a different device (MAC [found_MAC])"
    7. If port scan enabled: probe common ports and show "Open ports found: 80, 443, 8080, ..."
```

#### 5.7.2 Validation Outcome Messages (User-Facing)

| Scenario | User-facing message | Action |
|----------|-------------------|--------|
| MAC format invalid | "MAC address should look like aa:bb:cc:dd:ee:ff. We'll fix it automatically." | Auto-normalize |
| MAC not found on network | "We couldn't find this MAC on your network. Is the device powered on?" | Check device power |
| IP not in any known subnet | "This IP isn't on any configured network. Add the network in Settings first." | Go to Settings |
| IP found but wrong MAC | "That IP belongs to a different device. Double-check the MAC address." | Verify MAC |
| Port not responding | "Port X isn't answering. Did you mean Y? (Open ports: …)" | Suggest alternative |
| NPM mismatch | "NPM expects [old IP] but you entered [new IP]" | Three choices: Update to match / Link anyway / Don't link |
| Duplicate MAC+port | "A host with this MAC on this port already exists. Add as a second service?" | Merge or keep separate |

#### 5.7.3 Multi-Service Grouping (Dashboard)

On the dashboard, hosts sharing the same MAC address should be visually grouped:
```
┌─────────────────────────────────────────────┐
│ 🟢 vault (2 services)                       │
│   ├─ Port 8200 (Plex Metadata) — Healthy    │
│   └─ Port 8096 (Plex Web) — Healthy         │
└─────────────────────────────────────────────┘
```

Each service port is independently monitored but grouped under the device name so users understand they're watching one physical device with multiple services.

---

### 5.8 Notification Design

> *Users must have granular control to avoid notification fatigue and sleep disruption.*

#### 5.8.1 Event Types (User-Friendly Labels)

| Event Type | User-Facing Label | Plain-English Description | Default ON/OFF |
|------------|------------------|--------------------------|----------------|
| `unreachable` | ⚠️ Device Down | "The device isn't responding after the waiting period" | ON |
| `recovered` | ✅ Device Recovered | "The device is back up and working" | ON |
| `failed` | ❌ Recovery Failed | "We couldn't fix the device automatically" | ON |
| `scan_started` | 🔍 Scanning… | "We're looking for the device on the network" | OFF (noise) |
| `ip_found` | 📍 IP Found | "We found a new IP for the device" | OFF (noise) |
| `updated` | 🔄 NPM Updated | "We updated the proxy configuration" | OFF (noise) |
| `manual` | 👆 Manual Action | "An action was triggered manually" | ON |
| `quiet_time` | ⏱️ Quiet Time | "Do-not-disturb window started/ended" | OFF (noise) |

#### 5.8.2 Global Do-Not-Disturb (DND)

- **Settings toggle:** A global "Mute all notifications" switch (in Settings page).
- **Effect:** All event types are suppressed regardless of per-event toggles.
- **Use case:** "I'm sleeping, don't page me tonight" — without disabling monitoring entirely.
- **Duration options:** "Until 7:00 AM", "Custom (HH:MM to HH:MM)", or "Permanent until toggled off".
- **Recovery:** When DND ends, no backlog of missed notifications is sent — the system simply resumes normal operation.

#### 5.8.3 Per-Host Quiet Period (Existing, Clarified)

The current quiet period feature is per-host. The plan clarifies its behavior:
- **Quiet mode "suppress":** Continue monitoring the device, but do NOT send notifications. The device is still checked every check_interval.
- **Quiet mode "delete":** Skip monitoring checks entirely. No reachability check, no IP change detection. Useful for devices that are off during certain hours (e.g., a guest PC at night).

#### 5.8.4 De-duplication & Escalation (Requirement, not Tech Debt)

Current behavior: A persistently unreachable device can trigger notifications on every check cycle (every 600 seconds by default). This is unacceptable for sleep disruption.

Required behavior:
1. **Initial alert:** When grace period expires → send `unreachable` notification.
2. **De-duplication:** Do NOT re-notify on subsequent checks while the device stays unreachable.
3. **Escalation (optional, future):** If the device is still unreachable after X hours (configurable in Settings), send a reminder: "[Device] has been down for X hours — manual intervention may be needed."
4. **Recovery always notifies:** When a device recovers, always send a `recovered` notification (no de-duplication — this is the resolution).
5. **State-change only:** Only send notifications on state transitions (healthy → unreachable, unreachable → healthy), not on every check.

#### 5.8.5 Test Notification Endpoint

- **Endpoint:** `POST /notifications/channel/<id>/test`
- **Behavior:** Sends a test notification through the channel with a message like "This is a test notification from Upstream Healer."
- **UI:** A "Test" button on each channel card in the Notifications page.
- **Purpose:** Verify the channel works immediately after setup, without waiting for a real event.

#### 5.8.6 Notification Message Templates (Sanitized)

All outbound messages must use these sanitized templates:

**Event: unreachable**
```
⚠️ [Device Name] is unreachable. We're looking for it on your network.
```

**Event: recovered**
```
✅ [Device Name] is reachable again.
```

**Event: failed**
```
❌ We couldn't find [Device Name] on your network. Manual intervention may be needed.
```

**Event: manual**
```
👆 [Device Name] was checked manually.
```

**Event: quiet_time (log-only, never notified)**
```
Quiet time for [Device Name]: started/ended.
```

#### 5.8.7 Notification Channel Toggle Flow

```
User visits /notifications:
  1. Sees all configured channels (Telegram, Email)
  2. Each channel card shows:
     - Channel name + type badge
     - Enabled/Disabled status
     - Toggle button (Enable/Disable)
     - Per-event toggle buttons (with plain-English labels)
     - Test button
     - Edit/Delete buttons
  3. Toggling a channel off: stops all notifications through that channel
  4. Toggling an event type off: stops only that event type through that channel
  5. Global DND (if implemented): overrides all toggles temporarily
```

### 5.9 Dashboard Specification

> *The dashboard is the single source of truth for "is my reverse proxy working?"*

#### 5.9.1 Overall Banner

```
┌─────────────────────────────────────────────────────────┐
│ 🟢 All systems healthy — X devices monitored, Y active  │
│                                                         │
│ 🔴 1 device needs attention: [device name]              │
│    (Tap to see details)                                 │
└─────────────────────────────────────────────────────────┘
```

- **Green banner:** All monitored devices are healthy (or in quiet mode).
- **Amber banner:** One or more devices are in grace period (not yet at alert threshold).
- **Red banner:** One or more devices are unreachable (past grace period).

#### 5.9.2 Device Card (Per-Host)

```
┌─────────────────────────────────────────────────┐
│ 🟢 vault                                        │
│    Port 8200 — Healthy                          │
│    Last checked: 2 minutes ago                  │
│                                                 │
│ [Force Check] [Events] [Edit]                   │
└─────────────────────────────────────────────────┘
```

**Status indicators:**
| Status | Icon | Color | Meaning |
|--------|------|-------|---------|
| `healthy` | 🟢 | Green | Device is responding on its monitored port |
| `unreachable` | 🔴 | Red | Device is not responding (past grace period) |
| `recovering` | 🟡 | Amber | We're actively scanning for the device |
| `unknown` | ⚪ | Gray | Device was just added, not yet checked |
| `maintenance` | 🔵 | Blue | Device is being edited or in quiet mode |

**Grace period countdown:** When a device first becomes unreachable, show:
```
⏱️ Down 4 minutes — alerting in 6 minutes
```
This gives the user time to react before being paged.

#### 5.9.3 Multi-Service Grouping

Devices with multiple monitored ports (same MAC, different ports) are grouped:
```
┌─────────────────────────────────────────────────┐
│ 🟢 vault (2 services)                           │
│    ├─ Port 8200 — Healthy (checked 2m ago)      │
│    └─ Port 8096 — Healthy (checked 2m ago)      │
│                                                 │
│ [Force Check] [Events] [Edit]                   │
└─────────────────────────────────────────────────┘
```

If one service is unhealthy:
```
┌─────────────────────────────────────────────────┐
│ 🔴 vault (2 services)                           │
│    ├─ Port 8200 — Healthy                       │
│    └─ Port 8096 — Unreachable (in 8 min)        │
│                                                 │
│ [Force Check] [Events] [Edit]                   │
└─────────────────────────────────────────────────┘
```

#### 5.9.4 Actions

| Action | What it does | User-facing text |
|--------|-------------|-----------------|
| Force Check | Immediately scans one device | "Force Check" |
| Events | Opens the event log for this device | "Events" |
| Edit | Opens the edit form | "Edit" |
| Delete | Removes the device from monitoring | "Delete" (with confirmation) |
                                    ↓
                              Nginx (reloaded)
```

---

### 5.10 Language & Copy Guidelines

> *Consistent language across the UI reduces confusion and makes the tool feel polished.*

#### 5.10.1 Tone

- **Calm and helpful:** Never alarmist. "Device is unreachable" not "CRITICAL: DEVICE DOWN".
- **Actionable:** Every message should suggest what to do (or nothing if no action is needed).
- **Technical terms only where necessary:** Use "port" and "device name" freely; avoid "CIDR", "proxy host", "ARP" in user-facing text.

#### 5.10.2 Terminology Reference

| UI Label | Technical Meaning |
|----------|------------------|
| Device | A monitored host (identified by MAC + port) |
| Device name | The `name` field (e.g. "vault", "jellyfin") |
| Network segment | A subnet (e.g. "Home Network — 192.168.86.0/24") |
| Port | The TCP port to monitor on the device |
| Service | A specific port on a device (a device can have multiple services) |
| Waiting period | The grace period before alerting (default 10 minutes) |
| Do-not-disturb | Quiet time (suppress notifications) |
| Quiet time | Can be "suppress" (silence alerts) or "skip" (skip checks) |
| NPM page | An Nginx Proxy Manager proxy host (identified by domain name) |
| Network scan | ARP scan, scapy scan, or nmap scan (user doesn't need to choose) |
| Validate | Check if the entered device info is correct (runs a scan) |
| Event | A state change (device down, device recovered, etc.) |
| Alert | A notification sent to Telegram or Email |
| Health | Whether the device is responding on its monitored port |

#### 5.10.3 Error Messages

All error messages must:
1. Explain **what went wrong** in plain English.
2. Suggest **what to do** about it.
3. Never expose raw technical details (SQL errors, stack traces, etc.) to the user.

| Scenario | Bad | Good |
|----------|-----|------|
| NPM connection fails | "Connection refused to 192.168.86.40:3306" | "We can't reach Nginx Proxy Manager. Make sure it's running and the database credentials are correct." |
| MAC format invalid | "Invalid MAC" | "MAC address should look like aa:bb:cc:dd:ee:ff. We'll fix it automatically." |
| Port scan fails | "Connection timeout" | "Port X isn't answering. The device might not be running this service, or the port number might be wrong." |
| Device not found | "No hosts found" | "We couldn't find this MAC address on your network. Is the device powered on?" |

#### 5.10.4 Settings Explanations

Every setting in the Settings page should have a one-line explanation:

| Setting | Explanation |
|---------|-------------|
| Check interval | "How often we check if devices are responding (default: every 10 minutes)" |
| Grace period | "How long to wait before alerting (gives devices time to reboot — default: 10 minutes)" |
| Event retention | "How long to keep event history (default: 10 days)" |
| Check interval per subnet | "Custom check interval for this network (leave blank to use global default)" |

#### 5.10.5 Inline Help Pattern

Every form field should follow this pattern:
```
[Label]
[Input field]
<p class="text-xs text-slate-500">Explanation of what this field means and how to fill it</p>
```

Example:
```
Device name *
[vault                  ]
<p class="text-xs text-slate-500">A friendly name for this device, shown in alerts and on the dashboard</p>
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

The scanner uses the Nginx Proxy Manager's MariaDB to discover and update proxy hosts.

**Data flow**:
```
Healer ← Docker Exec → NPM Container ← pymysql → NPM MariaDB
```

1. **Connect to NPM**: Use Docker SDK to exec `pymysql` into the NPM container.
2. **Query proxy hosts**: `SELECT * FROM proxy_hosts WHERE scheme_http = 1 AND domain_names LIKE ?`
3. **Match by domain**: Find the proxy host whose domain matches the scanner's mDNS/ARP result.
4. **Update forward_host**: `UPDATE proxy_hosts SET forward_host = ? WHERE id = ?`
5. **Reload nginx**: `docker exec npm_nginx_1 nginx -s reload`

**Privacy**: All notifications strip IP addresses and MAC addresses before sending.
⚠️ **Current status:** Telegram applies stripping; Email does NOT. Email sanitization must be added to match Telegram's behavior.

### 6.3 Notification Channels

```
Monitor.send_event() →
  ├─ Telegram (httpx.AsyncClient → api.telegram.org)
  └─ Email (aiosmtplib → SMTP server)
```

**Privacy**: All notifications strip IP addresses and MAC addresses before sending.
⚠️ **Current status:** Telegram applies stripping; Email does NOT. Email sanitization must be added to match Telegram's behavior.

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
2. **REST API**: Add proper JSON API endpoints (currently mostly HTML).
3. **Health check improvements**: Add SQLite connectivity check.
4. **Config validation**: Add runtime validation for NPM credentials.

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
