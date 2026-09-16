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
from typing import Any, Dict, List, Optional, Set, Tuple

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

# Not a "still migrating" error: 1364 is the "Field 'x' doesn't have a default
# value" strict-mode error. It means the schema is *complete but the data is
# incomplete* — fixing it requires a real value (a safe default is auto-filled
# by the introspection helpers below), not more time. Retrying 1364 for ~30s
# against a stable schema is pure waste, so it is deliberately kept out of
# _MIGRATING_ERRNOS and the pass skips with a clear warning instead.
_MISSING_DEFAULT_ERRNO = 1364

# Tables we write to, and the safe values to use for a NOT-NULL column that has
# no database default (i.e. a column NPM's own "wizard leaves empty" migrations
# forgot to give a default). NPM's schema changes across image releases, so
# instead of hardcoding a per-INSERT column list (fragile against renames) the
# seeder introspects each table (SHOW COLUMNS) and auto-fills any such column
# it does not explicitly supply. Only columns that genuinely have no database
# default need an entry here (most have sensible defaults: is_deleted=0,
# enabled=1, forward_scheme=http, ...). Keys are lower-case: introspection
# folds the live column names to lower-case before lookup.
_KNOWN_COLUMNS_WITH_DEFAULTS: Dict[str, Dict[str, Optional[str]]] = {
    "user": {"avatar": ""},
    "access_list": {},
    "certificate": {"meta": "{}"},
    "proxy_host": {"advanced_config": "{}", "meta": "{}"},
}


def _inspect_columns(cursor: Any, table: str) -> List[Dict[str, Any]]:
    """Return ``SHOW COLUMNS`` rows for ``table``, or ``[]`` if the table does
    not exist yet (mid-migration) or the query fails (a transient DB issue).

    Never raises. Column names are folded to lower-case so callers can use a
    case-insensitive default table without per-release guessing.
    """
    try:
        cursor.execute(f"SHOW COLUMNS FROM `{table}`")
    except Exception as exc:  # noqa: BLE001 - table missing/not migrated = empty schema
        logger.debug(f"introspection: could not read {table} columns: {exc}")
        return []
    rows: List[Dict[str, Any]] = []
    try:
        for row in cursor.fetchall():
            rec = dict(row)
            key = str(rec.get("Field", "")).lower()
            rec["Field"] = key
            rec["Name"] = key
            rows.append(rec)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"introspection: could not read {table} rows: {exc}")
        return []
    return rows


def _missing_default_columns(
    table: str, columns: List[Dict[str, Any]], known: Set[str]
) -> List[Tuple[str, str]]:
    """Return ``(column, value)`` pairs for every NOT-NULL column with no
    default that is neither supplied by the caller (``known``) nor auto-filled
    by ``_KNOWN_COLUMNS_WITH_DEFAULTS`` *for this table*.

    These are exactly the columns that would trip error 1364 at insert.
    Returning a non-empty list lets the caller fail the pass loudly and
    immediately instead of seeding 1364s into a healthy database. (The value
    in each pair is a placeholder for display — a missing default means we do
    *not* know a safe value, which is the whole point of surfacing it.)
    """
    table_defaults = _KNOWN_COLUMNS_WITH_DEFAULTS.get(table, {})
    result: List[Tuple[str, str]] = []
    for col in columns:
        if col.get("Extra") == "auto_increment":
            continue  # the surrogate key; never supplied here
        if col.get("Null") != "NO":
            continue  # nullable: an omitted value defaults to NULL
        if col.get("Default") is not None:
            continue  # the database supplies a value
        key = str(col.get("Field", "")).lower()
        if not key or key in known:
            continue  # we provide it
        if key in table_defaults:
            continue  # _fills_for will auto-fill a safe value for this one
        result.append((key, "??"))
    return result


def _fills_for(conn: Any, table: str, known: Set[str]) -> Dict[str, str]:
    """Introspect ``table`` and return the value to use for every NOT-NULL,
    no-default column it does not already supply.

    All statements run *inside* the surrounding ``with conn.cursor()`` block
    (the cursor is closed when the block exits). On any error the introspection
    silently yields an empty dict: in that case the INSERT then omits those
    columns and, as before, fails with the schema error, which the caller
    retries while the schema is still being created.
    """
    with conn.cursor() as cursor:
        columns = _inspect_columns(cursor, table)
    if not columns:
        return {}
    table_defaults = _KNOWN_COLUMNS_WITH_DEFAULTS.get(table, {})
    fills: Dict[str, str] = {}
    for col in columns:
        if col.get("Extra") == "auto_increment":
            continue
        if col.get("Null") != "NO":
            continue
        if col.get("Default") is not None:
            continue
        key = str(col.get("Field", "")).lower()
        if not key or key in known:
            continue
        value = table_defaults.get(key)
        if value is None:
            value = ""  # safe generic non-NULL value; see _KNOWN_COLUMNS_WITH_DEFAULTS
        fills[key] = value
    return fills


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
    healer runs fine without NPM).

    One wrinkle a hard-coded column list cannot survive: NPM's migrations add
    NOT-NULL columns *without* defaults across releases (``user.avatar``,
    ``certificate.meta``, ``proxy_host.advanced_config``/``meta`` on current
    images). A stock sandbox has never run the wizard, so those rows do not
    exist and the seed must create them — but a fixed INSERT omits those
    columns and the whole pass fails (``Cursor closed`` at cursor-close,
    1364 in strict mode, or a missing-column SELECT in non-strict mode). So
    before each INSERT the table is introspected and any NOT-NULL column with
    no database default that the INSERT does not already supply is auto-filled
    with a safe value (see ``_fills_for``).
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
            known = {
                "created_on",
                "modified_on",
                "is_deleted",
                "is_disabled",
                "email",
                "name",
                "nickname",
                "roles",
            }
            values = {
                "email": "healer@example.com",
                "name": "Healer (seeded)",
                "nickname": "healer",
                "roles": '["admin"]',
            }
            values.update(
                _fills_for(conn, "user", known)  # e.g. user.avatar -> ""
            )
            cursor.execute(
                build_insert("user", values, timestamps=True),
                params_for(values, timestamps=True),
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
            known = {
                "created_on",
                "modified_on",
                "owner_user_id",
                "is_deleted",
                "provider",
                "nice_name",
                "domain_names",
                "expires_on",
                "meta",
            }
            values = {
                "owner_user_id": owner_user_id,
                "provider": "manual",
                "nice_name": "Seeded self-signed",
                "domain_names": None,
                "expires_on": None,
                "meta": "{}",
            }
            values.update(_fills_for(conn, "certificate", known))
            cursor.execute(
                build_insert("certificate", values, timestamps=True),
                params_for(values, timestamps=True),
            )
            certificate_id = cursor.lastrowid

        known = {
            "created_on",
            "modified_on",
            "owner_user_id",
            "is_deleted",
            "name",
            "meta",
            "satisfy_any",
            "pass_auth",
        }
        values = {
            "owner_user_id": owner_user_id,
            "name": "Seed dev allowlist",
            "meta": "{}",
            "satisfy_any": 1,
            "pass_auth": 1,
        }
        values.update(_fills_for(conn, "access_list", known))
        cursor.execute(
            build_insert("access_list", values, timestamps=True),
            params_for(values, timestamps=True),
        )
        access_list_id = cursor.lastrowid
    conn.commit()
    logger.info(
        f"NPM defaults: access_list #{access_list_id}, certificate #{certificate_id} "
        f"(owner user #{owner_user_id})"
    )
    return owner_user_id, access_list_id, certificate_id


def _sql_literal(value: Any) -> str:
    """Render a value as a SQL literal or a ``%s`` placeholder.

    ``NOW()``-style raw fragments (``__sql__…__``), ints and bools are inlined
    as literals; ``None`` becomes ``NULL``; everything else is a ``%s``
    placeholder bound by pymysql. The inlined values come from the seed config
    or ``_KNOWN_COLUMNS_WITH_DEFAULTS`` — never from user input — so this is
    safe.
    """
    if isinstance(value, str) and value.startswith("__sql__") and value.endswith("__"):
        return value[len("__sql__") : -2]
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    return "%s"


def build_insert(
    table: str, values: Dict[str, Any], timestamps: bool = False
) -> str:
    """Build an ``INSERT`` statement from a column -> value mapping.

    ``created_on``/``modified_on`` (NOT NULL, no database default) are always
    included, rendered as ``NOW()`` when ``timestamps`` is set — so callers
    supply only the business fields, in insertion order. Returns the SQL
    string; pair it with ``params_for`` for the bound values.
    """
    ordered: List[Tuple[str, str]] = []
    if timestamps:
        ordered.append(("created_on", _sql_literal("__sql__NOW()__")))
        ordered.append(("modified_on", _sql_literal("__sql__NOW()__")))
    for col, value in values.items():
        if timestamps and col in ("created_on", "modified_on"):
            continue  # already emitted above as NOW()
        ordered.append((col, _sql_literal(value)))
    cols = ", ".join(col for col, _ in ordered)
    vals = ", ".join(item for _, item in ordered)
    return f"INSERT INTO {table} ({cols}) VALUES ({vals})"


def params_for(
    values: Dict[str, Any], timestamps: bool = False
) -> tuple:
    """The positional parameter list matching ``build_insert``'s ``%s`` slots.

    A value only needs a bound parameter when ``_sql_literal`` rendered it as
    ``%s`` (i.e. it is neither a ``__sql__…__`` fragment nor an int/float/bool
    literal); ``None`` renders as the ``NULL`` literal and is not bound.
    """
    params: List[Any] = []
    if timestamps:
        pass  # created_on/modified_on are emitted as NOW(), not bound
    for col, value in values.items():
        if timestamps and col in ("created_on", "modified_on"):
            continue
        if _sql_literal(value) == "%s":
            params.append(value)
    return tuple(params)


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
            # 1364 = the schema is *complete* (the introspection above ran) but
            # a required column still has no value we know how to supply. That
            # will not fix itself with time, so it is not transient — fail the
            # pass rather than retrying against a stable schema for ~30s.
            if err_no == _MISSING_DEFAULT_ERRNO:
                retryable = False
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

    # The columns every seeded row supplies. Access-list and certificate FKs
    # are already supplied, so introspection only needs to fill whatever NOT
    # NULL-with-no-default column NPM has added since the last release (the
    # 'advanced_config' / 'meta' pair on current images) — robust against a
    # column *rename* too, because the fill is derived from the live schema.
    known = {
        # created_on/modified_on are always emitted by build_insert as NOW()
        # (timestamps=True) — include them in ``known`` so the unfilled check
        # below doesn't mistake them for missing.
        "created_on",
        "modified_on",
        "domain_names",
        "forward_scheme",
        "forward_host",
        "forward_port",
        "owner_user_id",
        "access_list_id",
        "certificate_id",
        "is_deleted",
    }
    with conn.cursor() as cursor:
        proxy_columns = _inspect_columns(cursor, "proxy_host")
    fills = _fills_for(conn, "proxy_host", known)
    unfilled = _missing_default_columns("proxy_host", proxy_columns, known)
    if unfilled:
        names = ", ".join(f"{name}={value}" for name, value in unfilled)
        # The schema is complete (we read its columns) yet a required column
        # has no known safe default — fail the pass loudly so it is not
        # silently skipped, and so the next release that renames/adds a
        # required column is loud about it.
        raise RuntimeError(
            f"proxy_host has required column(s) with no known safe default: "
            f"{names} — add them to _KNOWN_COLUMNS_WITH_DEFAULTS"
        )

    for spec in to_create:
        domain = spec["domain"]
        values = {
            "domain_names": domain,
            "forward_scheme": "http",
            "forward_host": spec.get("ip") or "127.0.0.1",
            "forward_port": int(spec.get("port") or 80),
            "owner_user_id": owner_user_id,
            "access_list_id": access_list_id,
            "certificate_id": certificate_id,
            "is_deleted": 0,
        }
        values.update(fills)
        with conn.cursor() as cursor:
            cursor.execute(
                build_insert("proxy_host", values, timestamps=True),
                params_for(values, timestamps=True),
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