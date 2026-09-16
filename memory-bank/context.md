# Context — Upstream Healer

> Last updated: 2026-09-16. Re-verify with `git status` and `progress.md` before relying on this.

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
- **aiosqlite** — app state in `healer.db` (SQLite, in `healer-data` volume).
  Tables: `hosts` (incl. `subnet_id` FK), `subnets`, `settings`,
  `notification_channels`, `notification_rules`, `events`, `host_state`.
- **pymysql** — read/write of NPM's MariaDB (`proxy_manager` schema)
- **bcrypt** — hashes the seeded NPM owner's wizard password (seed image only;
  the app container also builds with it but doesn't use it)
- **scapy** — LAN ARP scan for MAC → IP discovery; `arp-scan` (Dockerfile
  `iproute2`-adjacent) is the fast first choice. The Diagnostic page can run
  either on demand via `POST /api/diagnostic/scan` → `run_scan`.
- **Multi-subnet discovery:** `app.services.scanner.get_default_subnets()`
  shells out to `ip -4 -o addr` (from `iproute2`, in the Dockerfile) to
  enumerate locally-attached /24s. Manual overrides live in the `subnets`
  table; per-host pinning via `hosts.subnet_id`.
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

## Ports (host networking on the batcave box — no published ports in `docker ps`)

| Port | Service | Reachable from this workstation (192.168.86.24)? |
|---|---|---|
| **8787** | Healer web UI + JSON API (dev+prod) | yes |
| **8181 / 8182** | NPM web UI + edge (dev; `DEV_WEB_*_PORT` overrides) | **NO — connection refused** (on-box only) |
| **3306** | Dev MariaDB, `proxy_manager` schema (container `nginx-db-1`) | **yes — open on 0.0.0.0** (use direct SQL from here) |
| 80 / 443 | NPM edge in prod | dev deliberately moves NPM off these; on batcave `:80` answers with HTTP 200 for some **other** service (not NPM), `:443` socket open but TLS fails |

GitLab instance: SSH `192.168.86.38:32768`; Web/API **`http://192.168.86.38:32769`**
(port map 32768→git-ssh, 32769→web-80, 32770→web-443 — 443 not reachable from
here, use 32769). Project id 4. Pipeline tokens live in the git-ignored
`.env.local` at repo root (see decisions.md — do not name it `.env`, the app
loads that file via pydantic-settings).
Dev NPM UI login: `dev@hylla.local` / `devhealer123` (sandbox defaults).

## Dev stack on the batcave box (192.168.86.38)

Verified via the manual `dev_debug` CI job (2026-09-15): containers
`nginx-app-1` (NPM, `jc21/nginx-proxy-manager:latest`), `nginx-db-1`
(MariaDB 10.11, `jc21/mariadb-aria`), `upstream-healer`, plus one-shot
`upstream-healer-seed-1` (exits 0). All on host networking; named volumes
(`healer-data`, `npm-*`) persist across deploys.

**Interact with NPM via `docker exec` — never via the web UI** (user
directive). There is no docker CLI or SSH from this workstation, so from here
the equivalent is: direct MariaDB over `:3306`, or triggering the manual
`dev_debug` CI job (job dumps container states + log tails; see decisions.md
for the trigger recipe).

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

Seeder history is complete: the "Cursor closed" bug (`72dd82b`) and the
NOT-NULL 1364 introspection fix are both live. The current live state is
recorded in `progress.md` / `decisions.md`; no further seeder work expected.
