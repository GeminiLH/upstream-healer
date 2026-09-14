"""Idempotent dev-data seeder for the dev stack (docker-compose.dev.yml).

Runs inside the upstream-healer image — either via the one-shot ``seed``
compose service (deploy_dev job) or manually:

    docker exec upstream-healer python /app/scripts/seed_dev.py

What it does (every step is idempotent — safe to re-run on each deploy):

1. Seeds a fixed set of monitored hosts mirroring the real lab
   (vault, jellyfin, and the deliberately-dead failtest that exercises
   the full recovery flow).
2. Best-effort: creates NPM ``proxy_host`` rows in the dev MariaDB for
   those hosts' domains and links them, so the complete recovery path
   (NPM forward-host update + graceful nginx reload) can be exercised.
   Skipped with a warning if MariaDB is not (yet) reachable.
3. If TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_IDS are set in the environment
   and no telegram channel exists yet, adds one with all event types
   enabled. Channels already present (UI-configured) are never touched.

The seeder never fails the deploy for soft issues (missing MariaDB,
missing telegram env): it logs a warning and exits 0.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from typing import Any, Dict, List

import aiosqlite

from app.config import current_time, settings
from app.database import init_db
from app.services.notifications import EVENT_TYPES
from app.services.scanner import normalize_mac

logger = logging.getLogger("healer.seed")

# Fixed dev host set — mirrors the lab's own seed commands.
# failtest is a dead MAC/IP on purpose: it drives the unreachable ->
# scan -> NPM update -> nginx reload -> notify flow.
SEED_HOSTS: List[Dict[str, Any]] = [
    {
        "name": "vault",
        "mac": "46:dc:21:61:26:93",
        "ip": "192.168.86.249",
        "domain": "vault.hylla.us",
        "port": 80,
        "grace_minutes": 10,
    },
    {
        "name": "jellyfin",
        "mac": "a0:ad:9f:85:d7:cb",
        "ip": "192.168.86.40",
        "domain": "jelly.hylla.us",
        "port": 11000,
        "grace_minutes": 10,
    },
    {
        "name": "failtest",
        "mac": "aa:bb:cc:dd:ee:ff",
        "ip": "192.168.86.250",
        "domain": "none.hylla.us",
        "port": 11000,
        "grace_minutes": 5,
    },
]

# How long to wait for the dev MariaDB (proxy_host table) to appear
# before giving up on the NPM-side seeding. First boot of the jc21 MySQL
# image takes a while to initialize the proxy_manager schema.
MYSQL_WAIT_SECONDS = 180
MYSQL_POLL_SECONDS = 3
# Schema errors meaning "the NPM app is still migrating proxy_host —
# wait a bit and retry" (1054: unknown column, 1146: table doesn't
# exist yet). NPM's migrations alter that table across several steps.
_MIGRATING_ERRNOS = {1054, 1146}
# How many times to retry the seeding attempt on a still-migrating
# schema before giving up (3s apart -> ~30s of migration headroom).
_SEED_RETRIES = 10


# ───────────────────────────── Healer SQLite ─────────────────────────────


async def seed_hosts(db: aiosqlite.Connection) -> List[str]:
    """Insert any missing dev hosts (host + host_state rows).

    Returns the names of the hosts that were added. Existing hosts
    (matched by the unique mac_address + port pair) are left untouched.
    """
    async with db.execute(
        "SELECT mac_address, port FROM hosts"
    ) as cursor:
        existing = {(row["mac_address"], row["port"]) for row in await cursor.fetchall()}

    now = current_time().isoformat()
    added: List[str] = []
    for spec in SEED_HOSTS:
        mac = normalize_mac(spec["mac"])
        if (mac, spec["port"]) in existing:
            continue
        cursor = await db.execute(
            """INSERT INTO hosts
               (name, domain, mac_address, current_ip, port,
                grace_minutes, notes, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                spec["name"],
                spec["domain"],
                mac,
                spec["ip"],
                spec["port"],
                spec["grace_minutes"],
                "seeded by deploy_dev (dev sandbox)",
                now,
                now,
            ),
        )
        await db.execute(
            "INSERT INTO host_state (host_id, status, last_ip) VALUES (?, 'unknown', ?)",
            (cursor.lastrowid, spec["ip"]),
        )
        added.append(spec["name"])
    await db.commit()
    return added


async def apply_npm_links(db: aiosqlite.Connection, links: Dict[str, int]) -> int:
    """Point seeded hosts at their NPM proxy_host ids.

    ``links`` maps domain -> proxy_host id. Only rows whose domain matches
    and whose npm_proxy_host_id is still NULL are updated — anything the
    user configured in the UI is never overwritten.
    Returns the number of hosts linked.
    """
    linked = 0
    now = current_time().isoformat()
    for domain, proxy_host_id in links.items():
        cursor = await db.execute(
            """UPDATE hosts
               SET npm_proxy_host_id = ?, updated_at = ?
               WHERE domain = ? AND npm_proxy_host_id IS NULL""",
            (proxy_host_id, now, domain),
        )
        linked += cursor.rowcount
    if linked:
        await db.commit()
    return linked


async def seed_telegram_if_requested(db: aiosqlite.Connection) -> bool:
    """Create a telegram channel from TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_IDS.

    Only acts when both env vars are set AND no telegram channel exists
    yet. Returns True when a channel was created.
    """
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_ids_raw = os.environ.get("TELEGRAM_CHAT_IDS", "").strip()
    if not token or not chat_ids_raw:
        logger.info(
            "TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_IDS not set — skipping the "
            "telegram channel (add one in the UI, or set those env vars)"
        )
        return False

    async with db.execute(
        "SELECT COUNT(*) FROM notification_channels WHERE type = 'telegram'"
    ) as cursor:
        count = (await cursor.fetchone())[0]
    if count:
        logger.info("A telegram channel already exists — leaving it untouched")
        return False

    chat_ids = [part.strip() for part in chat_ids_raw.split(",") if part.strip()]
    now = current_time().isoformat()
    cursor = await db.execute(
        """INSERT INTO notification_channels (type, name, enabled, config, created_at)
           VALUES ('telegram', ?, 1, ?, ?)""",
        ("Dev alerts", json.dumps({"bot_token": token, "chat_ids": chat_ids}), now),
    )
    channel_id = cursor.lastrowid
    for event_type in EVENT_TYPES:
        await db.execute(
            "INSERT INTO notification_rules (event_type, channel_id, enabled) VALUES (?, ?, 1)",
            (event_type, channel_id),
        )
    await db.commit()
    logger.info(
        f"Created telegram channel 'Dev alerts' (id={channel_id}, "
        f"{len(chat_ids)} chat id(s), {len(EVENT_TYPES)} event types enabled)"
    )
    return True


# ───────────────────────────── NPM MariaDB ─────────────────────────────


def _bootstrap_npm_schema() -> None:
    """Ensure the proxy_manager database and app user exist, as MariaDB
    root.

    The standard MariaDB entrypoint only applies its MYSQL_DATABASE /
    MYSQL_USER env vars when the data directory is completely empty. A
    volume that was initialized before those vars were set (e.g. by an
    earlier crashed run) therefore keeps working for root but has no app
    database/user — the NPM app can never log in. This makes that edge
    case self-healing.

    Only runs when NPM_DB_ROOT_USER / NPM_DB_ROOT_PASSWORD are provided;
    otherwise a no-op. Soft-fails: any error is logged, never raised.
    """
    root_user = os.environ.get("NPM_DB_ROOT_USER", "").strip()
    root_password = os.environ.get("NPM_DB_ROOT_PASSWORD", "")
    if not root_user or not root_password:
        return

    db_name = settings.npm_db_name
    app_user = settings.npm_db_user
    if not db_name or not app_user:
        return  # NPM integration disabled — nothing to bootstrap
    # These come from compose env vars, not user input — but a GRANT can
    # only take literal identifiers, so refuse anything that isn't a
    # plain SQL-safe identifier before it lands in a statement.
    if not re.fullmatch(r"[A-Za-z0-9_]+", db_name) or not re.fullmatch(
        r"[A-Za-z0-9_]+", app_user
    ):
        logger.warning("NPM schema bootstrap skipped (unsafe identifier in env)")
        return

    import pymysql

    try:
        conn = pymysql.connect(
            host=settings.npm_db_host,
            port=int(settings.npm_db_port),
            user=root_user,
            password=root_password,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"NPM schema bootstrap skipped (root login failed): {exc}")
        return

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
            cursor.execute(
                "CREATE USER IF NOT EXISTS %s@'%%' IDENTIFIED BY %s",
                (app_user, settings.npm_db_password),
            )
            cursor.execute(
                f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{app_user}'@'%'"
            )
            cursor.execute("FLUSH PRIVILEGES")
        conn.commit()
        logger.info(f"NPM schema bootstrap ok (database `{db_name}`, user '{app_user}')")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"NPM schema bootstrap failed (continuing): {exc}")
    finally:
        conn.close()


def _mysql_connect():
    import pymysql

    return pymysql.connect(
        host=settings.npm_db_host,
        port=int(settings.npm_db_port),
        user=settings.npm_db_user,
        password=settings.npm_db_password,
        database=settings.npm_db_name,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
    )


def _mysql_ready() -> bool:
    """True when we can query the proxy_host table."""
    conn = _mysql_connect()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM proxy_host LIMIT 1")
        return True
    finally:
        conn.close()


def _wait_for_mysql(timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if _mysql_ready():
                return True
        except Exception as exc:  # noqa: BLE001 - any connection issue = not ready
            logger.debug(f"MariaDB not ready yet: {exc}")
        time.sleep(MYSQL_POLL_SECONDS)
    return False


def ensure_proxy_hosts() -> Dict[str, int]:
    """Best-effort: make sure a proxy_host row exists for each seeded
    domain and return {domain: proxy_host_id}.

    Never raises — on any failure (MariaDB absent, schema mismatch, ...)
    it logs a warning and returns whatever it could confirm. The healer
    works fine without NPM; this only powers the recovery path.
    """
    links: Dict[str, int] = {}
    domains = [spec["domain"] for spec in SEED_HOSTS if spec.get("domain")]
    if not domains:
        return links

    _bootstrap_npm_schema()

    try:
        if not _wait_for_mysql(MYSQL_WAIT_SECONDS):
            logger.warning(
                f"Dev MariaDB ({settings.npm_db_host}:{settings.npm_db_port}) not "
                f"reachable within {MYSQL_WAIT_SECONDS}s — skipping proxy_host seeding. "
                "The healer runs fine without NPM; re-run the seeder later to link."
            )
            return links
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"proxy_host seeding skipped — could not reach MariaDB: {exc}")
        return links

    # The database can be reachable while the NPM app is still running its
    # migrations (the seeder and the app both start on `up`), so a schema
    # error on the first attempt is "not finished yet", not "broken" —
    # retry for a while instead of skipping.
    last_error = ""
    for attempt in range(1, _SEED_RETRIES + 1):
        try:
            conn = _mysql_connect()
            try:
                return _seed_proxy_host_once(conn)
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            err_no = exc.args[0] if exc.args else None
            if err_no in _MIGRATING_ERRNOS and attempt < _SEED_RETRIES:
                logger.info(
                    f"NPM schema still migrating (attempt {attempt}, err {err_no}) — "
                    "retrying proxy_host seeding in a moment"
                )
                time.sleep(MYSQL_POLL_SECONDS)
                continue
            break
    logger.warning(
        f"proxy_host seeding skipped — {last_error or 'MariaDB not ready'} "
        "(the healer runs fine without NPM; re-run the seeder later to link)"
    )
    return links


def _seed_proxy_host_once(conn: Any) -> Dict[str, int]:
    """One seeding pass: record existing rows, create the missing ones.

    Returns {domain: proxy_host_id} for every seeded host that now has a
    row. May raise a schema error (caller retries) — rows are committed
    one at a time, so a retried pass only creates what is still missing.
    """
    with conn.cursor() as cursor:
        cursor.execute("SELECT id, domain_names FROM proxy_host WHERE is_deleted = 0")
        existing = {
            str(row["domain_names"]).strip(): row["id"]
            for row in cursor.fetchall()
            if row.get("domain_names")
        }

    links: Dict[str, int] = {}
    for spec in SEED_HOSTS:
        domain = spec.get("domain")
        if not domain:
            continue
        if domain in existing:
            links[domain] = existing[domain]
            continue
        with conn.cursor() as cursor:
            cursor.execute(
                """INSERT INTO proxy_host
                   (domain_names, forward_scheme, forward_host, forward_port, is_deleted)
                   VALUES (%s, 'http', %s, %s, 0)""",
                (domain, spec.get("ip") or "127.0.0.1", str(spec.get("port") or 80)),
            )
            proxy_host_id = cursor.lastrowid
        conn.commit()
        existing[domain] = proxy_host_id
        links[domain] = proxy_host_id
        logger.info(
            f"Created NPM proxy_host #{proxy_host_id} for {domain} "
            f"-> {spec.get('ip')}:{spec.get('port') or 80}"
        )
    return links


# ───────────────────────────── Orchestration ─────────────────────────────


async def _run() -> None:
    await init_db()

    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        added_hosts = await seed_hosts(db)
        telegram_created = await seed_telegram_if_requested(db)

    logger.info(
        f"hosts: {len(added_hosts)} added "
        f"({'none new' if not added_hosts else ', '.join(added_hosts)}); "
        f"telegram channel created: {telegram_created}"
    )

    links = ensure_proxy_hosts()
    if links:
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            linked = await apply_npm_links(db, links)
        logger.info(f"linked {linked} host(s) to their NPM proxy_host ids")

    print(json.dumps({"hosts_added": added_hosts, "npm_links": links}))
    print("seed_dev: done")


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    try:
        asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001
        # Soft failures must not break the deploy.
        logger.error(f"seeder finished with errors: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())