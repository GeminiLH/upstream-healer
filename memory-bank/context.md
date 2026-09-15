# Context — Upstream Healer

> Last updated: 2026-07-09. Re-verify with `git status` and `progress.md` before relying on this.

## What it is

Automatic recovery for **Nginx Proxy Manager (NPM)** upstreams when backend IPs
change. Designed for a Raspberry Pi (Debian 12) running NPM in Docker in the
"Hylla" home lab.

Workflow when a monitored backend drops:
1. Alert (Telegram + Email) after a configurable **grace period** (default 10 min)
2. Scan the LAN (ARP/scapy) for the device's MAC to find its new IP
3. Update the matching NPM `proxy_host` row
4. Graceful `nginx -s reload` (never restarts the NPM container)

## Purpose / motivation

Backends on the home LAN (vault, jellyfin, etc.) get new IPs after reboots/DHCP
expiry; NPM upstreams break. The healer detects this by MAC address, finds the
new IP, and self-heals NPM config. See `upstream healer notes.txt` for ad-hoc
LAN notes (IP/MAC tables, one-off docker exec commands) — it is scratch paper,
not documentation, and **contains secrets** (bot token, gitlab tokens) that
must never be copied into code, tests, or the memory bank.

## Tech stack

- Python 3, **FastAPI** (web UI + JSON API on port **8787**), Jinja2 templates
- **aiosqlite** — app state in `healer.db` (SQLite, in `healer-data` volume)
- **pymysql** — read/write of NPM's MariaDB (`proxy_manager` schema)
- **scapy** — LAN ARP scan for MAC → IP discovery
- **docker** python SDK — reaches into the `nginx-app-1` container
- apscheduler, aiosmtplib (email), httpx (telegram), pydantic-settings
- Dev: pytest (asyncio_mode=auto), ruff (lint: E,F; E501 ignored)

## Environment gotchas

- The checkout at `/mnt/Aquaman/upstream-healer` is on an **NFS share**. The
  `.venv/` present in the repo is a **Windows-style venv** (`Lib/`, `Scripts/`)
  from a Windows machine and **does not work on this Linux host**.
- Use the system interpreter instead: `python3` (3.13, with all deps installed
  globally). Verified working: `python3 -m pytest tests/ -q` → 105 passed.
- **Remotes**: `gitlab` = `ssh://git@192.168.86.38:32768/monster/upstream_healer.git`
  — **primary source of truth** (see decisions.md). `origin` = GitHub
  `GeminiLH/upstream-healer` — **legacy, ignore but never delete**.
- CI: GitLab CI (`.gitlab-ci.yml`) with unit tests, lint, build, dev/deploy
  jobs; deploy jobs use `needs:optional` for `unit_tests`.
- `upstream healer notes.txt` contains live secrets and is in `.gitignore` —
  **never commit it** (hard rule, see decisions.md).

## Ports (host networking — no published ports shown by `docker ps`)

| Port | Service | Where |
|---|---|---|
| **8787** | Healer web UI + JSON API | dev + prod |
| **8181** | NPM web UI (HTTP) | dev (`WEB_HTTP_PORT`, override `DEV_WEB_HTTP_PORT`) |
| **8182** | NPM edge + web HTTPS | dev (`WEB_HTTPS_PORT` / `EDGE_PORT`, overrides `DEV_WEB_*_PORT`) |
| **3306** | Dev MariaDB (`proxy_manager` schema, container `nginx-db-1`) | dev |
| 80 / 443 | NPM edge | prod (dev deliberately moves off these) |

GitLab instance: SSH `192.168.86.38:32768`; Web/API **`http://192.168.86.38:32769`**
(port map 32768→ssh, 32769→80, 32770→443). Project id 4. Pipeline tokens live
in the git-ignored `.env.local` at repo root (see decisions.md — do not name it
`.env`, the app loads that file via pydantic-settings).
Dev NPM UI login: `dev@hylla.local` / `devhealer123` (sandbox defaults).

## Key commands

```bash
# Tests & lint (on this Linux host — use system python3, NOT .venv)
cd /mnt/Aquaman/upstream-healer
python3 -m pytest tests/ -q
python3 -m ruff check app/ scripts/ tests/

# Full dev stack (Pi / any Docker host)
docker compose -f docker-compose.dev.yml up -d --build   # healer + NPM + MariaDB + seed
docker compose -f docker-compose.dev.yml down            # teardown (add -v to wipe)

# CLI administration (inside the running app container)
docker exec upstream-healer python -m app.cli <cmd>       # see README "Docker exec administration"

# Dev seeder (creates vault/jellyfin/failtest hosts + NPM proxy_host rows + links)
scripts/seed_dev.py
```

## Seeded dev hosts

`scripts/seed_dev.py` seeds **6 hosts** (tests expect 6 / 5 linked — see recent
commit `cb09b16`), including `plex`, `homeassistant`, `portainer`. `failtest`
is a deliberately dead device to exercise the full recovery flow
(unreachable → scan → NPM update → nginx reload).
