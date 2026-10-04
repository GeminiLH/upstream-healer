# Upstream Healer — Project Plan & Priorities

> Last updated: 2026-10-04

## 1. API Documentation Template & Guidelines *(Priority 1)*

### Current State
The application is a **FastAPI** app with **two distinct API surfaces**:
- **Server-rendered HTML routes** (dashboard, settings, hosts, notifications, diagnostic UI) — all decorated with `response_class=HTMLResponse`
- **JSON API endpoints** under `/api/` — scan progress, scan results, network info, etc.

There is **no formal API documentation**. FastAPI's auto-generated Swagger UI (`/docs`) exists but is undocumented, unstyled, and lacks business-context descriptions.

### Plan

#### A. Route Documentation Audit
Document every route with these fields in a central `docs/api-reference.md`:

| Route | Method | Auth | Description | Request | Response |
|-------|--------|------|-------------|---------|----------|
| `GET /api/diagnostic/scan-progress/{scan_id}` | GET | None | Poll scan progress | — | `{status, progress_pct, stage, elapsed_time, ...}` |
| `POST /api/diagnostic/scan` | POST | None | Trigger network scan | `{scan_type, subnets, ports}` | `{scan_id}` |
| `GET /api/hosts` | GET | None | List monitored hosts | `?enabled=true` | `[Host]` |
| `POST /api/hosts` | POST | None | Add a host | `{name, mac, ip, port}` | `{id, ...}` |

#### B. FastAPI Enhancement
- Add `summary` + `description` to every route decorator (especially `/api/*` endpoints)
- Create Pydantic response models for `/api/*` endpoints (currently returning raw dicts)
- Add `tags=["Diagnostic"]` / `tags=["Hosts"]` etc. for Swagger grouping
- Add OpenAPI schema customization to hide `/docs` in production

#### C. API Documentation Template
Create `docs/api-template.md` as a reusable template:

```markdown
## {Endpoint Name}
- **Method:** GET|POST|PUT|DELETE
- **Path:** `/api/...`
- **Authentication:** None|API Key|Session
- **Rate Limit:** N/A|X req/min
- **Description:** One-liner of purpose
- **Request Body:** JSON schema
- **Response:** Success schema + error codes
- **Example:** curl snippet
- **Notes:** Edge cases, quirks
```

#### D. API Changelog
Maintain `docs/api-changelog.md` tracking:
- Added/removed endpoints
- Breaking changes (request/response schema)
- Deprecation timeline

---

### Files to Create
- `docs/api-template.md` — reusable endpoint template
- `docs/api-changelog.md` — version history
- `docs/api-reference.md` — comprehensive route documentation

### Files to Modify
- `app/main.py` — add Pydantic models + OpenAPI descriptions to routes

---

## 2. Test Coverage Requirements *(Priority 2)*

### Current State
- **383 tests** (382 passed + 1 skipped)
- **pytest-asyncio** auto mode
- **No coverage threshold** enforced in CI
- Ruff linting passes (E+F, long lines allowed)
- Tests exist for: scanner, database, config, main routes, notifications

### Plan

#### A. Coverage Baseline Measurement
Run `pytest --cov=app --cov-report=term-missing` to measure current coverage.

#### B. CI Coverage Gate
Add to `.gitlab-ci.yml`:

```yaml
unit_tests:
  script:
    - python3 -m pytest tests/ -q --cov=app --cov-report=xml --cov-fail-under=70
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
  coverage: '/TOTAL.*\s+(\d+%)/'
```

#### C. Coverage Targets (Phased)

| Phase | Target | Timeline |
|-------|--------|----------|
| Current | Measure baseline | Sprint 1 |
| Short-term | 60% minimum | Sprint 2-3 |
| Medium-term | 75% minimum | Sprint 4-6 |
| Long-term | 85%+ minimum | Ongoing |

#### D. Gap Analysis — Areas Needing Tests
Based on code review, these areas likely have low/no coverage:
- **`app/services/scanner.py`** — tunnel discovery, routed networks, suppressed subnets
- **`app/main.py`** — error paths, edge cases in form handlers, settings page logic
- **`app/services/npm.py`** — Nginx Proxy Manager integration, DB fallback paths
- **`app/services/mdns.py`** — mDNS discovery edge cases
- **`app/cli.py`** — CLI subcommand error handling
- **`app/database.py`** — migration edge cases

#### E. Testing Conventions to Document
```python
# In tests/conftest.py or project README
# - Use pytest fixtures for DB (aiosqlite in-memory)
# - Mock subprocess calls (arp-scan, nmap, ip command)
# - Async tests: use pytest-asyncio auto mode
# - No real network calls in unit tests
# - Use test client for route tests
```

---

### Files to Create
- `tests/test_coverage_baseline.py` — script to measure and report coverage
- `docs/testing-guide.md` — testing conventions and patterns

### Files to Modify
- `.gitlab-ci.yml` — add coverage gate
- `pyproject.toml` or `setup.cfg` — add `[tool.pytest.ini_options]` coverage config
- Add new tests in `tests/` for uncovered modules

---

## 3. Database Schema Analysis *(Priority 3)*

### Current State
SQLite database with **7 tables**, all defined inline in `app/database.py::SCHEMA`. No migration framework (e.g., Alembic) — uses ad-hoc `ALTER TABLE` + migration logic in `init_db()`.
## 3. Database Schema Analysis *(Priority 3)*

### Current State
SQLite database with **7 tables**, all defined inline in `app/database.py::SCHEMA`. No migration framework (e.g., Alembic) — uses ad-hoc `ALTER TABLE` + migration logic in `init_db()`.

### Schema Diagram

```
┌──────────────┐       ┌───────────────┐
│   hosts      │       │   subnets     │
├──────────────┤       ├───────────────┤
│ id (PK)      │       │ id (PK)       │
│ name         │ ──FK  │ name          │
│ local_device_name │  │ cidr (UNIQUE) │
│ quiet_enabled    │   │ interface     │
│ quiet_start      │   │ enabled       │
│ quiet_end        │   │ check_interval│
│ quiet_mode       │   └───────────────┘
│ domain           │
│ mac_address      │       ┌───────────────────┐
│ current_ip       │       │ mdns_names        │
│ npm_proxy_host_id│       ├───────────────────┤
│ port             │       │ mac (PK)          │
│ grace_minutes    │       │ hostname          │
│ enabled          │       │ updated_at        │
│ subnet_id (FK)   │       └───────────────────┘
│ subnet_cidr      │
│ notes            │       ┌───────────────────┐
│ created_at       │       │   settings        │
│ updated_at       │       ├───────────────────┤
│ UNIQUE(mac,port) │       │ key (PK)          │
└──────────────┘       │ value             │
                       └───────────────────┘

┌───────────────────┐       ┌───────────────────┐
│ notification_     │       │ notification_     │
│ channels          │       │ rules             │
├───────────────────┤       ├───────────────────┤
│ id (PK)           │       │ id (PK)           │
│ type              │       │ event_type        │
│ name              │       │ channel_id (FK)   │
│ enabled           │       │ enabled           │
│ config (JSON)     │       └───────────────────┘
│ created_at        │

┌──────────────┐
│    events    │
├──────────────┤
│ id (PK)      │
│ host_id (FK) │
│ event_type   │
│ message      │
│ details (JSON)│
│ created_at   │
└──────────────┘

┌──────────────┐
│ host_state   │
├──────────────┤
│ host_id (PK,FK)│
│ status         │
│ last_seen_at   │
│ unreachable_since│
│ last_check_at  │
│ last_ip        │
│ quiet_active   │
│ quiet_mode     │
└──────────────┘
```

### Analysis & Recommendations

#### Strengths
- Simple, flat schema — no unnecessary joins
- Soft-delete via `enabled` flags
- JSON config storage for extensibility (`notification_channels.config`)
- Row-level state tracking (`host_state`)

#### Issues & Recommendations

| Issue | Severity | Recommendation |
|-------|----------|----------------|
| **No migration framework** | High | Introduce Alembic or similar for schema versioning |
| **Inline SCHEMA string** | Medium | Move schema to `app/database/schema.sql` for version control clarity |
| **No indexes** | Medium | Add indexes on `events.host_id`, `events.created_at`, `hosts.mac_address`, `hosts.enabled` |
| **events retention not enforced** | Medium | Implement cleanup cron job (configurable via `event_retention_days`) |
| **No audit trail** | Low | Consider adding `audit_log` table for config changes |
| **hardcoded DEFAULT_SETTINGS** | Low | Move to seed script for reproducibility |

#### Query Optimization
The dashboard query (`GET /`) does a three-table JOIN on every load. For large host counts:
```sql
-- Recommended indexes
CREATE INDEX IF NOT EXISTS idx_events_host_id ON events(host_id);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac_address);
CREATE INDEX IF NOT EXISTS idx_hosts_enabled ON hosts(enabled);
CREATE INDEX IF NOT EXISTS idx_host_state_status ON host_state(status);
```

#### Schema Evolution History (from `init_db()` migrations)
- Added: `local_device_name`, `quiet_enabled/start/end/mode`, `port`, `subnet_cidr` to `hosts`
- Added: `quiet_active`, `quiet_mode` to `host_state`
- Added: `subnet_id` to `hosts`
- Changed: `hosts` uniqueness from `(mac)` to `(mac, port)`

---

### Files to Create
- `app/database/schema.sql` — canonical schema definition
- `app/database/indexes.sql` — recommended indexes
- `app/database/migrations/` — future migration directory

### Files to Modify
- `app/database.py` — reference external schema, add index creation
- `app/main.py` — add events cleanup route/endpoint

---



