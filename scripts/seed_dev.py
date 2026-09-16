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
    {
        "name": "plex",
        "mac": "11:22:33:44:55:66",
        "ip": "192.168.86.30",
        "domain": "plex.hylla.us",
        "port": 32400,
        "grace_minutes": 10,
    },
    {
        "name": "homeassistant",
        "mac": "77:88:99:aa:bb:cc",
        "ip": "192.168.86.20",
        "domain": "ha.hylla.us",
        "port": 8123,
        "grace_minutes": 10,
    },
    {
        "name": "portainer",
        "mac": "de:ad:be:ef:00:01",
        "ip": "192.168.86.10",
        "domain": "portainer.hylla.us",
        "port": 9443,
        "grace_minutes": 10,
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


def _npm_default_password() -> str:
    """The default (wizard) login password, read from the seeder's own
    environment. ``NPM_DEFAULT_PASSWORD`` must be set on the healer container
    (see ``docker-compose.dev.yml``) — the value ends up in the seeder logs.
    """
    return os.environ.get("NPM_DEFAULT_PASSWORD", "").strip()


def _ensure_npm_defaults(conn: Any) -> tuple[int, int]:
    """Return ``(owner_user_id, access_list_id)`` to attach to seeded
    ``proxy_host`` rows.

    ``proxy_host`` declares ``owner_user_id`` and ``access_list_id`` as
    NOT NULL with no defaults — upstream leaves them to the setup wizard,
    which a stock dev stack never completed. So:

    * owner: reuse an existing ``user`` row (the wizard must have run);
      otherwise create one with the default password *directly in the
      database* (``CREATE USER`` with the bcrypt list, i.e. the "allow
      with a password" option — no wizard completion required).
    * access list: always a fresh dev allowlist (pass_auth: no login for
      the lab's own requests) — idempotent enough for a throwaway env.
    * certificate: reuse id 0 (NPM's built-in "none" cert), else create.

    The schema itself is guaranteed: on this dev setup the container was
    started by an NPM image that ships the tables; otherwise every
    statement here errors and the caller's retry loop skips seeding (the
    healer runs fine without NPM). No DDL, no schema inspection needed.
    """
    # NOTE: every statement must run inside its ``with conn.cursor()`` block.
    # The earlier revision ran the owner INSERT (below) after the SELECT block
    # had closed the cursor, so a pristine dev NPM (``user`` table empty — the
    # exact case a stock sandbox is) hit pymysql's "Cursor closed" error.
    # pymysql raises that as a str-args OperationalError, which the seeding
    # retry loop did not recognise as transient, so it gave up immediately
    # and seeded zero proxy_host rows. Keeping statements inside the block is
    # the fix; the retry loop additionally treats closed-cursor errors as
    # transient (see ensure_proxy_hosts).
    password = _npm_default_password()

    with conn.cursor() as cursor:
        cursor.execute("SELECT id FROM user WHERE is_deleted = 0 ORDER BY id")
        rows = cursor.fetchall()
        if rows:
            owner_user_id = rows[0]["id"]
            logger.info(
                f"NPM owner: reusing existing user #{owner_user_id} — log in "
                "with the default NPM password to complete the wizard (dev only)"
            )
        else:
            if not password:
                password = "dev-healer"
                logger.warning(
                    "NPM_DEFAULT_PASSWORD not set — using 'dev-healer' for the "
                    "seeded owner (set the env var to pick your own)"
                )
            cursor.execute(
                """INSERT INTO user
                   (created_on, modified_on, is_deleted, is_disabled, email,
                    name, nickname, roles)
                   VALUES (NOW(), NOW(), 0, 0, %s, %s, %s, %s)""",
                ("healer@example.com", "Healer (seeded)", "healer", '["admin"]'),
            )
            owner_user_id = cursor.lastrowid
            try:
                import bcrypt

                hashed = bcrypt.hashpw(
                    password.encode("utf-8"), bcrypt.gensalt(12)
                ).decode("ascii")
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    f"Could not hash the NPM default password ({exc}) — the "
                    "owner user exists but has no password login"
                )
                hashed = ""
            cursor.execute(
                # CREATE USER with a password list = the wizard's "allow with a
                # password" step, done in the DB so the wizard is never needed.
                "CREATE USER (email = %s, password = %s, realm = %s)",
                ("healer@example.com", hashed, "proxyManager"),
            )
            conn.commit()
            logger.info(
                f"NPM owner: created user #{owner_user_id} "
                "(wizard login: he**@example.com / NPM_DEFAULT_PASSWORD)"
            )

    with conn.cursor() as cursor:
        cursor.execute("SELECT id FROM certificate WHERE id = 0")
        row = cursor.fetchone()
        if row:
            certificate_id = row["id"]
        else:
            cursor.execute(
                """INSERT INTO certificate
                   (created_on, modified_on, owner_user_id, is_deleted,
                    provider, nice_name, domain_names, expires_on, meta)
                   VALUES (NOW(), NOW(), %s, 0, 'manual', %s, NULL, NULL, %s)""",
                (owner_user_id, "Seeded self-signed", "{}"),
            )
            certificate_id = cursor.lastrowid

        cursor.execute(
            """INSERT INTO access_list
               (created_on, modified_on, owner_user_id, is_deleted, name,
                meta, satisfy_any, pass_auth)
               VALUES (NOW(), NOW(), %s, 0, %s, %s, 1, 1)""",
            (owner_user_id, "Seed dev allowlist", "{}"),
        )
        access_list_id = cursor.lastrowid
    conn.commit()
    logger.info(
        f"NPM defaults: access_list #{access_list_id}, certificate #{certificate_id} "
        f"(owner user #{owner_user_id})"
    )
    return owner_user_id, access_list_id, certificate_id


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
    logger.info(f"ensure_proxy_hosts: {len(domains)} domains to seed: {domains}")
    if not domains:
        logger.info("ensure_proxy_hosts: no domains to seed, returning empty")
        return links

    _bootstrap_npm_schema()

    # Log NPM DB connection details for troubleshooting
    logger.info(
        f"ensure_proxy_hosts: NPM DB connection target = "
        f"{settings.npm_db_host}:{settings.npm_db_port}, db={settings.npm_db_name}, "
        f"user={settings.npm_db_user}"
    )

    try:
        if not _wait_for_mysql(MYSQL_WAIT_SECONDS):
            logger.warning(
                f"Dev MariaDB ({settings.npm_db_host}:{settings.npm_db_port}) not "
                f"reachable within {MYSQL_WAIT_SECONDS}s — skipping proxy_host seeding. "
                "The healer runs fine without NPM; re-run the seeder later to link."
            )
            return links
        logger.info(f"Dev MariaDB ({settings.npm_db_host}:{settings.npm_db_port}) is reachable")
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"proxy_host seeding skipped — could not reach MariaDB: {exc}")
        return links

    # The database can be reachable while the NPM app is still running its
    # migrations (the seeder and the app both start on `up`), so a schema
    # error on the first attempt is "not finished yet", not "broken" —
    # retry for a while instead of skipping.
    #
    # pymysql raises a closed-cursor misuse as a *str*-args OperationalError
    # ("Cursor closed" / "Not yet connected") rather than the err-no carried
    # by schema errors, so retry those too: if a statement lands outside its
    # cursor's ``with`` block, the whole pass is aborted *before* any INSERT,
    # leaving zero proxy_host rows, and it should be retried rather than
    # silently skipped.
    _TRANSIENT_MARKERS = ("closed", "not yet connected", "not connected")
    last_error = ""
    logger.info(f"proxy_host seeding: starting {len(SEED_HOSTS)} seed hosts, {_SEED_RETRIES} retries max")
    for attempt in range(1, _SEED_RETRIES + 1):
        logger.info(f"proxy_host seeding: attempt {attempt}/{_SEED_RETRIES}")
        try:
            conn = _mysql_connect()
            try:
                result = _seed_proxy_host_once(conn)
                logger.info(f"proxy_host seeding: success — linked {len(result)} hosts: {result}")
                return result
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            err_no = exc.args[0] if exc.args else None
            logger.warning(f"proxy_host seeding attempt {attempt} failed: {exc}")
            retryable = (
                err_no in _MIGRATING_ERRNOS
                or any(m in str(exc).lower() for m in _TRANSIENT_MARKERS)
            )
            if retryable and attempt < _SEED_RETRIES:
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

    ``owner_user_id`` / ``access_list_id`` / ``certificate_id`` come from
    ``_ensure_npm_defaults`` (see its docstring) — the three NOT-NULL
    columns with no defaults, which upstream leaves to the setup wizard.
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
        if domain and domain in existing:
            links[domain] = existing[domain]
    to_create = [spec for spec in SEED_HOSTS if spec.get("domain") and spec["domain"] not in existing]
    if not to_create:
        return links

    owner_user_id, access_list_id, certificate_id = _ensure_npm_defaults(conn)
    for spec in to_create:
        domain = spec["domain"]
        with conn.cursor() as cursor:
            cursor.execute(
                """INSERT INTO proxy_host
                   (domain_names, forward_scheme, forward_host, forward_port,
                    owner_user_id, access_list_id, certificate_id, is_deleted,
                    created_on, modified_on)
                   VALUES (%s, 'http', %s, %s, %s, %s, %s, 0, NOW(), NOW())""",
                (
                    domain,
                    spec.get("ip") or "127.0.0.1",
                    str(spec.get("port") or 80),
                    owner_user_id,
                    access_list_id,
                    certificate_id,
                ),
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

    logger.info("=== seed_dev: starting ===")
    logger.info(f"settings: db_path={settings.db_path}, npm_db_host={settings.npm_db_host}, "
                f"npm_db_port={settings.npm_db_port}, npm_db_name={settings.npm_db_name}, "
                f"npm_db_user={settings.npm_db_user}")
    logger.info(f"SEED_HOSTS count: {len(SEED_HOSTS)}")

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
        logger.info(f"About to apply {len(links)} NPM links to SQLite: {links}")
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            linked = await apply_npm_links(db, links)
        logger.info(f"linked {linked} host(s) to their NPM proxy_host ids")
        # Verify what was actually linked
        async with aiosqlite.connect(settings.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT name, domain, npm_proxy_host_id FROM hosts") as cursor:
                all_hosts = await cursor.fetchall()
            logger.info(f"All hosts in SQLite DB: {[(h['name'], h['domain'], h['npm_proxy_host_id']) for h in all_hosts]}")
    else:
        logger.warning("No NPM links returned — no proxy_host rows were created or found")

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