# Context — Upstream Healer

> Last updated: 2026-09-27 (scan-progress UI `d2b62f0` — diagnostic page polls
> `GET /api/diagnostic/scan-progress/{scan_id}` for status/progress/ETA; seeder
> now 8 hosts / 6 NPM-linked; `fash` → `flash` rename leftovers fixed).
> Re-verify with `git status` and `progress.md` before relying on this.

## Repository (read this first)

**GitLab is the primary repository** — the only active remote. All commits,
pushes, and CI/pipeline work target the `gitlab` remote:
`ssh://git@192.168.86.38:32768/monster/upstream_healer.git`
(project `monster/upstream_healer`; CI = GitLab CI; Web/API
`http://192.168.86.38:32769`).

- Push **explicitly**: `git push gitlab main`. Never use a bare `git push` —
  the local branch's upstream may silently point at the legacy `origin` remote.
- `origin` = GitHub `GeminiLH/upstream-healer` is a **legacy mirror**: never a
  push target, but never delete the remote or the GitHub repo either (hard rule,
  see decisions.md).

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
  either on demand via `POST /api/diagnostic/scan` → `run_scan`. **Tunnel/routed**
  subnets (WireGuard, gateway) can't be ARP-*broadcast* swept, so they're probed at
  Layer 3 (scapy ICMP → `nmap -sn` → `ping`); `nmap` is a selectable diagnostic
  method (in the Dockerfile) and shows `--` for the (unresolvable) source MAC.
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
  globally). Verified working: `python3 -m pytest tests/ -q` → 255 passed.
- **Remotes**: `gitlab` = `ssh://git@192.168.86.38:32768/monster/upstream_healer.git`
  — **the primary repository** (see the "Repository" section above and the hard
  rule in decisions.md). `origin` = GitHub `GeminiLH/upstream-healer` —
  **legacy mirror; never push there, but never delete either**.
- CI: GitLab CI (`.gitlab-ci.yml`) with unit tests, lint, build, dev/deploy
  jobs; deploy jobs use `needs:optional` for `unit_tests`.
- `upstream healer notes.txt` contains live secrets and is in `.gitignore` —
  **never commit it** (hard rule, see decisions.md).
- **MCP servers: `command` must be the node binary, not the package bin shim.**
  The IDE is **VSCodium Insiders running as a Flatpak** and its extension host
  PATH does **not** include the nvm node dir (`~/.nvm/versions/node/v20.20.2/bin`
  comes from `.bashrc` nvm init, which GUI-launched apps never source). The npm
  bin shims (`mcp-gitlab`, `ssh-mcp-server`) are `#!/usr/bin/env node` scripts,
  so `env node` fails in that PATH → server dies at spawn →
  **`MCP error -32000: Connection closed`** (all 3 servers). Fix (2026-09-27):
  in `cline_mcp_settings.json` use `"command": "/home/lhoward/.nvm/versions/node/v20.20.2/bin/node"`
  with the package `build/index.js` as the first `args` entry. Keep **both**
  copies in sync: `~/.cline/data/settings/cline_mcp_settings.json` (primary,
  post-4.x migration) and the legacy
  `~/.var/app/com.vscodium.codium-insiders/config/VSCodium - Insiders/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`.
  Config changes hot-reload (Cline watches the file); restart the IDE if not.
  Diagnostic: `tr '\0' '\n' < /proc/<extHostPID>/environ | grep ^PATH` and spawn
  the server with `env -i PATH=<that PATH>` to reproduce.

## Ports (host networking on the batcave box — no published ports in `docker ps`)

| Port | Service | Reachable from this workstation (192.168.86.24)? |
|---|---|---|
| **8787** | Healer web UI + JSON API (dev+prod) | yes |
| **8181 / 8182** | NPM web UI + edge (dev; `DEV_WEB_*_PORT` overrides) | **NO — connection refused** (on-box only) |
| **3306** | Dev MariaDB, `proxy_manager` schema (container `nginx-db-1`) | **yes — open on 0.0.0.0** (use direct SQL from here) |
| 80 / 443 | NPM edge in prod | dev deliberately moves NPM off these; on batcave `:80` answers with HTTP 200 for some **other** service (not NPM), `:443` socket open but TLS fails |

GitLab instance: SSH `192.168.86.38:32768`; Web/API **`http://192.168.86.38:32769`**
(port map 32768→git-ssh, 32769→web-80, 32770→web-443 — 443 not reachable from
here, use 32769). Project id 4. Use the **`gitlab-read`** and **`gitlab-pipelines`**
MCP tools for all GitLab API interactions — they are pre-configured with the
necessary tokens. Do not source `.env.local` or hand-roll curl calls to GitLab.
Dev NPM UI login: `dev@hylla.local` / `devhealer123` (sandbox defaults).

## Dev stack on the batcave box (192.168.86.38)

Verified via the manual `dev_debug` CI job (2026-09-15): containers
`nginx-app-1` (NPM, `jc21/nginx-proxy-manager:latest`), `nginx-db-1`
(MariaDB 10.11, `jc21/mariadb-aria`), `upstream-healer`, plus one-shot
`upstream-healer-seed-1` (exits 0). All on host networking; named volumes
(`healer-data`, `npm-*`) persist across deploys.

**Interact with NPM via `docker exec` — never via the web UI** (user
directive). There is no docker CLI or *general* (key) SSH from this workstation,
so the usual equivalent is direct MariaDB over `:3306` or the manual `dev_debug`
CI job (dumps container states + log tails; see decisions.md for the trigger
recipe). The one SSH exception: the read-only **`cline-logs`** account for
**scan logs** (below).

## Accessing the batcave scan logs (read-only `cline-logs`)

The per-scan `diag_*.log` files live in the app's mounted `/logs` dir
(`= /mnt/data/upstream-healer/logs` on batcave). Use the **`log-servers`** MCP
tool — it is pre-configured with the `cline-logs` account credentials and lets
you run shell commands remotely on batcave. The `log-server` MCP enforces a
command whitelist regex **locally** (before SSH):
`^ls.*|^cat.*|^tail.*|^grep.*|^head.*|^wc.*|^file.*|^stat.*` — the *whole*
command must match one of these anchored patterns, so flags and arguments are
fine (`ls -lat`, `tail -n 50 <file>`, `grep -i pat <file>`) but any other
command is rejected with `Command not in whitelist`. Shell control syntax
(`;` `&` `|` backtick `<` `>` `$(`) is explicitly forbidden too. The account
**auto-cd's into the log directory**, so no path is needed. Verified 2026-09-27:
the old pattern (`^ls|^cat|…`, no `.*`) only matched bare command names and
silently broke `cat <file>` — if log reads start failing with a whitelist
error, check the `--whitelist` arg in
`~/.cline/data/settings/cline_mcp_settings.json` (Cline restarts the MCP
server on config change; no manual reload needed).

Filenames contain `:` (MAC addresses) — pass them **unquoted** in the remote
command: `cat diag_20260921_070637_nmap_dc:a6:32:02:59:63_7.log`.

Legacy: `scripts/batcave_logs.sh '<cmd>'` is still available but requires
sourcing credentials manually. Prefer the `log-servers` MCP tool.

## Triggering a scan to test a scanner change (no `docker exec` needed)

The dev stack on batcave serves the FastAPI app on `:8787` and the app API is
**unauthenticated** (no bearer/JWT/token in `main.py`/`config.py`). So from this
box you can fire a scan directly and then read back the fresh `diag_*.log`:

```bash
curl -s -m 105 -X POST http://192.168.86.38:8787/api/diagnostic/scan \
  -H 'Content-Type: application/json' \
  -d '{"target_mac":"dc:a6:32:02:59:63","method":"arp-scan","subnet_cidr":"192.168.86.0/24"}'
# → {found_ip, found_via, output, error, hosts[], subnets}

# No-MAC sweep (L3; hosts labeled by curated/mDNS/reverse-DNS — 2026-09-24+):
curl -s -m 240 -X POST http://192.168.86.38:8787/api/diagnostic/scan \
  -H 'Content-Type: application/json' \
  -d '{"method":"nmap","scan_ports":false}'
# a run takes 60–120 s → use -m 240 and run it backgrounded (gotcha below)
```

`method` ∈ `arp-scan|scapy|nmap`; `subnet_cidr` scopes the sweep (leave `""` +
`subnet_id:0` for all effective subnets). Use a known-up target so `found_ip`
populates. Verified the arp-scan `--interface=` fix this way on 2026-09-21
(17 hosts, `rc=0`, `error=None`, `--interface=enp6s0` in the diag log).

**Scan debug log (dev-only, added 2026-09-24):** `GET
http://192.168.86.38:8787/api/diagnostic/scan-log` returns the newest per-scan
log (`diag_*.log`) content (200 KB truncated) plus a `files` metadata list —
exact nmap command, full raw output, hostname maps, `reverse-dns
attempted=/resolved=` summary. The diagnostic page has a "Scan debug log"
button for the same. 404 on test/prod (`UPSTREAM_HEALER_DEBUG_LOG_DIR` unset
there; also 404 when `ENV == "production"`). The logs also live at
`/mnt/data/upstream-healer/logs` on batcave (dev compose mounts them to
`/logs` in the app container).

**Agent-tool gotcha (this sandbox, learned 2026-09-21):** a `run_commands` shell
is reaped at ~30 s and takes anything backgrounded behind `&`/`nohup` down with
it — so a long scan trigger (or `ship.sh`'s background `deploy_dev` wait) is
killed before it finishes. Launch it detached with `setsid … &`, `touch` a
sentinel file on exit, and **poll that file** in a short separate command; the
work keeps running in its own session even after the launching shell is reaped
(this is how the Fix C `deploy_dev` and the live nmap sweep were driven here).

**MCP timeout gotcha (verified 2026-09-28):** `gitlab-pipelines` MCP calls have
a hard **60 s timeout** — `wait_for_pipeline` / `wait_for_job` (which block
until terminal status) always exceed it and return
`MCP error -32001 … timed out after 60s`. Don't use them; poll instead:
`sleep 25` via `run_commands` (a bare `sleep 30` command itself hits the ~30 s
foreground cap and fails), then `list_pipeline_jobs` / `get_pipeline_job`.
Typical durations: auto stage ~3–4 min (lint ~17 s, unit_tests ~150 s,
build_image ~37 s); `deploy_dev` ~20 s.

## Testing & Troubleshooting Checklist (2026-09-27 verified)

### Quick scan test (verify scanner changes without `docker exec`)

The dev API at `http://192.168.86.38:8787` is **unauthenticated**. From this
workstation you can trigger scans and read back results:

**1. Trigger a scan (detached — avoids 30 s shell timeout):**

```bash
# Quick MAC-targeted ARP sweep (~3 s):
setsid bash -c 'curl -s -m 105 -X POST http://192.168.86.38:8787/api/diagnostic/scan \
  -H "Content-Type: application/json" \
  -d "{\"target_mac\":\"dc:a6:32:02:59:63\",\"method\":\"arp-scan\",\"subnet_cidr\":\"192.168.86.0/24\"}" \
  > /tmp/scan_result.json; echo done' &

# Full L3 sweep (nmap, no ports; ~60-120 s):
setsid bash -c 'curl -s -m 240 -X POST http://192.168.86.38:8787/api/diagnostic/scan \
  -H "Content-Type: application/json" \
  -d "{\"method\":\"nmap\",\"scan_ports\":false}" \
  > /tmp/scan_result.json; echo done' &
```

**2. Read back the latest scan log:**

```bash
# List recent scan log files:
curl -s http://192.168.86.38:8787/api/diagnostic/scan-log \
  | python3 -c "import sys,json; d=json.load(sys.stdin); [print(f) for f in d['files']]"

# Read full latest log content:
curl -s http://192.168.86.38:8787/api/diagnostic/scan-log \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['latest'].get('content',''))"
```

**3. Alternative: read logs via SSH (log-servers MCP tool or `batcave_logs.sh`):**

```bash
# Via the read-only cline-logs SSH account:
curl -s http://192.168.86.38:8787/api/diagnostic/scan-log \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['files'][0]['name'])"
# → diag_20260927_125033_arp-scan_dc:a6:32:02:59:63_1.log
# Then pass filename to log-servers MCP or batcave_logs.sh 'cat <filename>'
```

**Expected results (verified 2026-09-27):**
- ARP sweep: `rc=0`, `found_ip=192.168.86.37` (flash), `error=None`, 15 hosts
- Reverse DNS: ~87% resolution (13/15 hosts named)
- mDNS: live names for flash, Apple TV, HP printer, WDMyCloud

### Common roadblocks & workarounds

| Problem | Cause | Fix |
|---------|-------|-----|
| Scan curl returns before scan finishes | API is async; curl returns immediately | Check `/api/diagnostic/scan-log` for completed result |
| Shell kills background `curl` at 30 s | `run_commands` timeout | Use `setsid bash -c '...' &` to detach |
| `scan-log` endpoint returns 404 | Dev-only; `UPSTREAM_HEALER_DEBUG_LOG_DIR` unset | Only works on dev compose; not on prod/test |
| `docker exec` fails | No SSH with docker privs to batcave | Use unauthenticated dev API at `:8787` instead |

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

`scripts/seed_dev.py` seeds **8 hosts** (6 NPM-linked: vault, jellyfin,
failtest, plex, homeassistant, portainer; plus `batcave` + `flash`, both
disabled and domain-less — `fash` was renamed `flash` in `4299a52`), so the
`hosts` table has 8 rows and 6 `host_state` rows (tests: `len(hosts) == 8`,
`len(states) == 6`). `failtest` is a deliberately dead device to exercise the
full recovery flow (unreachable → scan → NPM update → nginx reload). The live
dev DB may hold a few extra manually-added rows on top (10 as of 2026-09-27);
the seeder itself is idempotent and only ever adds the 8 canonical hosts.

Seeder history is complete: the "Cursor closed" bug (`72dd82b`) and the
NOT-NULL 1364 introspection fix are both live. The current live state is
recorded in `progress.md` / `decisions.md`; no further seeder work expected.
