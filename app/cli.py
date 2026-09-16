"""Command-line administration for use with docker exec."""
import argparse
import asyncio
import json
from datetime import timedelta
from typing import Sequence

import aiosqlite

from app.config import current_time, parse_timestamp, settings
from app.database import init_db
from app.services.notifications import EVENT_TYPES
from app.services.scanner import normalize_mac


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage Upstream Healer configuration")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_host = subparsers.add_parser("add-host", help="Add a host to monitor")
    add_host.add_argument("--name", required=True)
    add_host.add_argument("--mac", required=True)
    add_host.add_argument("--ip", default=None)
    add_host.add_argument("--domain", default=None)
    add_host.add_argument("--port", type=int, default=80, help="Port to monitor (default: 80)")
    add_host.add_argument("--npm-proxy-host-id", type=int, default=None,
                          help="Optional Nginx Proxy Manager proxy host ID")
    add_host.add_argument("--grace-minutes", type=int, default=10)

    subparsers.add_parser("list-hosts", help="List monitored hosts")

    subparsers.add_parser("list-npm-hosts",
                         help="List available Nginx Proxy Manager proxy hosts")

    check = subparsers.add_parser(
        "check-npm-db",
        help="Check the NPM MariaDB connection (status, config, and live proxy_host rows)",
    )
    check.add_argument(
        "--host",
        help="Override the NPM DB host (default: auto-detected from the NPM container env)",
    )
    check.add_argument(
        "--port",
        type=int,
        help="Override the NPM DB port (default: auto-detected from the NPM container env)",
    )
    check.add_argument(
        "--user",
        help="Override the NPM DB user (default: auto-detected from the NPM container env)",
    )
    check.add_argument(
        "--password",
        help="Override the NPM DB password (default: auto-detected from the NPM container env)",
    )

    edit_host = subparsers.add_parser("edit-host", help="Edit an existing host's properties")
    edit_host.add_argument("host_id", type=int, help="Host ID to edit")
    edit_host.add_argument("--name", default=None)
    edit_host.add_argument("--mac", default=None)
    edit_host.add_argument("--ip", default=None)
    edit_host.add_argument("--domain", default=None)
    edit_host.add_argument("--port", type=int, default=None, help="Port to monitor")
    edit_host.add_argument("--npm-proxy-host-id", type=int, default=None,
                           help="Optional Nginx Proxy Manager proxy host ID (use --list-npm-hosts to see available)")
    edit_host.add_argument("--grace-minutes", type=int, default=None)
    edit_host.add_argument("--enable", action="store_true", help="Enable monitoring for this host")
    edit_host.add_argument("--disable", action="store_true", help="Disable monitoring for this host")
    edit_host.add_argument("--notes", default=None)

    list_events = subparsers.add_parser("list-events", help="List recent events")
    list_events.add_argument("--host-id", type=int, default=None)
    list_events.add_argument("--limit", type=int, default=10, help="Maximum events to return")
    list_events.add_argument("--days", type=int, default=1, help="Only events from this many days")

    disable_host = subparsers.add_parser("disable-host", help="Disable monitoring for a host")
    disable_host.add_argument("host_id", type=int)

    add_telegram = subparsers.add_parser("add-telegram", help="Add an enabled Telegram channel")
    add_telegram.add_argument("--name", default="Telegram")
    add_telegram.add_argument("--bot-token", required=True)
    add_telegram.add_argument("--chat-ids", required=True, help="Comma-separated Telegram chat IDs")

    subparsers.add_parser("list-telegram", help="List Telegram channels")

    disable_telegram = subparsers.add_parser(
        "disable-telegram", help="Disable a Telegram channel"
    )
    disable_telegram.add_argument("channel_id", type=int)
    return parser


async def add_host(args: argparse.Namespace, db: aiosqlite.Connection) -> None:
    if args.grace_minutes < 0:
        raise ValueError("--grace-minutes must be zero or greater")
    if not 1 <= args.port <= 65535:
        raise ValueError("--port must be between 1 and 65535")
    now = current_time().isoformat()
    cursor = await db.execute(
        """INSERT INTO hosts
           (name, domain, mac_address, current_ip, npm_proxy_host_id, port,
            grace_minutes, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            args.name,
            args.domain,
            normalize_mac(args.mac),
            args.ip,
            args.npm_proxy_host_id,
            args.port,
            args.grace_minutes,
            now,
            now,
        ),
    )
    host_id = cursor.lastrowid
    await db.execute(
        "INSERT INTO host_state (host_id, status, last_ip) VALUES (?, 'unknown', ?)",
        (host_id, args.ip),
    )
    await db.commit()
    print(json.dumps({"id": host_id, "name": args.name, "enabled": True}))


async def list_hosts(db: aiosqlite.Connection) -> None:
    db.row_factory = aiosqlite.Row
    async with db.execute(
        """SELECT h.id, h.name, h.domain, h.mac_address, h.current_ip, h.port,
              h.grace_minutes, h.enabled, s.status
           FROM hosts h LEFT JOIN host_state s ON s.host_id = h.id
           ORDER BY h.id"""
    ) as cursor:
        print(json.dumps([dict(row) for row in await cursor.fetchall()]))


async def list_events(args: argparse.Namespace, db: aiosqlite.Connection) -> None:
    if args.limit < 1:
        raise ValueError("--limit must be at least 1")
    if args.days < 1:
        raise ValueError("--days must be at least 1")

    db.row_factory = aiosqlite.Row
    query = """SELECT e.id, e.host_id, h.name AS host_name, e.event_type,
                      e.message, e.details, e.created_at
               FROM events e LEFT JOIN hosts h ON h.id = e.host_id"""
    parameters = []
    if args.host_id is not None:
        query += " WHERE e.host_id = ?"
        parameters.append(args.host_id)
    query += " ORDER BY e.id DESC"

    cutoff = current_time() - timedelta(days=args.days)
    events = []
    async with db.execute(query, parameters) as cursor:
        for row in await cursor.fetchall():
            event = dict(row)
            if not event["created_at"]:
                continue
            if parse_timestamp(event["created_at"]) < cutoff:
                continue
            events.append(event)
            if len(events) == args.limit:
                break
    print(json.dumps(events))


async def disable_host(host_id: int, db: aiosqlite.Connection) -> None:
    cursor = await db.execute("UPDATE hosts SET enabled = 0 WHERE id = ?", (host_id,))
    if cursor.rowcount == 0:
        raise ValueError(f"Host {host_id} was not found")
    await db.commit()
    print(json.dumps({"id": host_id, "enabled": False}))


async def add_telegram(args: argparse.Namespace, db: aiosqlite.Connection) -> None:
    chat_ids = [value.strip() for value in args.chat_ids.split(",") if value.strip()]
    if not chat_ids:
        raise ValueError("--chat-ids must contain at least one chat ID")
    now = current_time().isoformat()
    cursor = await db.execute(
        """INSERT INTO notification_channels (type, name, enabled, config, created_at)
           VALUES ('telegram', ?, 1, ?, ?)""",
        (args.name, json.dumps({"bot_token": args.bot_token, "chat_ids": chat_ids}), now),
    )
    channel_id = cursor.lastrowid
    for event_type in EVENT_TYPES:
        await db.execute(
            """INSERT INTO notification_rules (event_type, channel_id, enabled)
               VALUES (?, ?, 1)""",
            (event_type, channel_id),
        )
    await db.commit()
    print(json.dumps({"id": channel_id, "name": args.name, "enabled": True, "events_enabled": EVENT_TYPES}))


async def list_telegram(db: aiosqlite.Connection) -> None:
    db.row_factory = aiosqlite.Row
    async with db.execute(
        "SELECT id, name, enabled, created_at FROM notification_channels WHERE type = 'telegram' ORDER BY id"
    ) as cursor:
        print(json.dumps([dict(row) for row in await cursor.fetchall()]))


async def disable_telegram(channel_id: int, db: aiosqlite.Connection) -> None:
    cursor = await db.execute(
        "UPDATE notification_channels SET enabled = 0 WHERE id = ? AND type = 'telegram'",
        (channel_id,),
    )
    if cursor.rowcount == 0:
        raise ValueError(f"Telegram channel {channel_id} was not found")
    await db.commit()
    print(json.dumps({"id": channel_id, "enabled": False}))


async def list_npm_hosts(db: aiosqlite.Connection) -> None:
    """List available Nginx Proxy Manager proxy hosts."""
    from app.services.npm import NPMClient

    npm = NPMClient()
    if not npm.available:
        print(json.dumps([]))
        return

    proxy_hosts = npm.list_proxy_hosts()
    print(json.dumps(proxy_hosts))


async def check_npm_db(args=None) -> None:
    """Diagnostic: verify Docker/NPM status, DB credentials, and proxy hosts.

    ``args`` may carry --host/--port/--user/--password overrides (argparse
    Namespace from ``check-npm-db``); defaults win when they are unset.
    """
    import subprocess
    import docker as _docker

    print("=" * 60)
    print("  NPM Database Diagnostic")
    print("=" * 60)

    print()
    print("[1] Docker daemon:")
    docker_ok = False
    docker_client = None
    try:
        docker_client = _docker.from_env()
        docker_client.ping()
        docker_ok = True
        print("    Docker daemon is reachable")
    except Exception as exc:
        print(f"    Docker not available: {exc}")

    print()
    print(f"[2] NPM container ({settings.npm_container}):")
    npm_container = None
    if docker_ok:
        try:
            npm_container = docker_client.containers.get(settings.npm_container)
            print(f"    Container running - status: {npm_container.status}")
        except _docker.errors.NotFound:
            print(f"    Container not found: {settings.npm_container}")
        except Exception as exc:
            print(f"    Error checking container: {exc}")
    else:
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) >= 2 and settings.npm_container in parts[0]:
                    print(f"    Found via docker CLI: {parts[0]} ({parts[1]})")
                    break
            else:
                print("    Container not found via docker CLI")
        except Exception as exc:
            print(f"    docker CLI not available: {exc}")

    print()
    print("[3] DB credentials:")
    print(f"    npm_db_host  = {settings.npm_db_host}")
    print(f"    npm_db_port  = {settings.npm_db_port}")
    print(f"    npm_db_name  = {settings.npm_db_name}")
    print(f"    npm_db_user  = {settings.npm_db_user or '(empty — NPM disabled unless discovered)'}")

    db_creds = None
    if docker_ok and npm_container:
        try:
            import re as _re
            exit_code, raw = npm_container.exec_run(
                "printenv | grep DB_MYSQL_", demux=False
            )
            if exit_code == 0 and raw:
                env_text = raw.decode(errors="ignore")
                db_creds = {}
                for line in env_text.strip().splitlines():
                    m = _re.match(r"^(DB_MYSQL_\w+)=?(.*)", line)
                    if m:
                        db_creds[m.group(1)] = m.group(2)
                if db_creds:
                    print("    DB_MYSQL_* env vars found:")
                    for k, v in db_creds.items():
                        masked = v[:3] + "***" if len(v) > 3 else "***"
                        print(f"      {k} = {masked}")
                else:
                    print("    No DB_MYSQL_* variables found in container env")
            else:
                print(f"    exec_run failed (exit={exit_code})")
        except Exception as exc:
            print(f"    Error reading container env: {exc}")

    if not db_creds:
        print("    (using fallback config values from settings)")

    await _check_npm_db_steps2(db_creds, args)


async def _check_npm_db_steps2(db_creds: dict | None, args=None) -> None:
    # 4. Try connecting to NPM DB
    print()
    print("[4] NPM database connectivity:")
    try:
        import pymysql

        import pymysql.cursors  # registers pymysql.cursors.DictCursor

        # CLI flags > container env (DB_MYSQL_*) > app settings
        creds = dict(db_creds or {})
        arg_map = {
            "host": "DB_MYSQL_HOST",
            "port": "DB_MYSQL_PORT",
            "user": "DB_MYSQL_USER",
            "password": "DB_MYSQL_PASSWORD",
        }
        for flag, env_key in arg_map.items():
            value = getattr(args, flag, None)
            if value not in (None, ""):
                creds[env_key] = str(value)
        host = creds.get("DB_MYSQL_HOST") or settings.npm_db_host
        port = int(creds.get("DB_MYSQL_PORT") or settings.npm_db_port)
        user = creds.get("DB_MYSQL_USER") or settings.npm_db_user
        password = creds.get("DB_MYSQL_PASSWORD") or settings.npm_db_password
        database = creds.get("DB_MYSQL_NAME") or settings.npm_db_name
        print(f"    Using: {user}@{host}:{port}/{database}")
        conn = pymysql.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
        )
        print("    Connected to NPM database successfully")
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS cnt FROM proxy_host WHERE is_deleted = 0")
            count = cur.fetchone()["cnt"]
            print(f"    proxy_host table: {count} active rows")
            cur.execute(
                "SELECT id, domain_names, forward_host, forward_port, "
                "owner_user_id, access_list_id, certificate_id, enabled "
                "FROM proxy_host WHERE is_deleted = 0 ORDER BY id"
            )
            rows = cur.fetchall()
            if rows:
                print("    Proxy hosts:")
                for row in rows:
                    print(
                        f"      id={row['id']}  domain={row['domain_names']}  "
                        f"forward={row['forward_host']}:{row['forward_port']}  "
                        f"owner={row['owner_user_id']}  acl={row['access_list_id']}  "
                        f"cert={row['certificate_id']}  enabled={row['enabled']}"
                    )
            else:
                print("    No proxy_host rows - run seed_dev.py to create them")
        conn.close()
    except Exception as exc:
        print(f"    Connection failed: {exc}")

    # 5. List proxy hosts via NPMClient
    print()
    print("[5] NPMClient proxy hosts:")
    try:
        from app.services.npm import NPMClient

        npm = NPMClient()
        print(f"    Docker available: {npm.available}")
        hosts = npm.list_proxy_hosts()
        print(f"    Proxy hosts returned: {len(hosts)}")
        for h in hosts:
            print(f"      id={h['id']}  domain={h.get('domain_names')}  forward={h.get('forward_host')}:{h.get('forward_port')}")
    except Exception as exc:
        print(f"    Error listing hosts via NPMClient: {exc}")

    # 6. Check SQLite DB hosts
    print()
    print("[6] SQLite DB hosts:")
    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT name, domain, npm_proxy_host_id FROM hosts"
        ) as cursor:
            sqlite_hosts = await cursor.fetchall()
        print(f"    Hosts in SQLite DB: {len(sqlite_hosts)}")
        for h in sqlite_hosts:
            linked = "OK" if h["npm_proxy_host_id"] else "UNLINKED"
            print(f"      [{linked}] name={h['name']}  domain={h['domain']}  npm_proxy_host_id={h['npm_proxy_host_id']}")

    print()
    print("=" * 60)
    print("  Diagnostic complete")
    print("=" * 60)


async def edit_host(host_id: int, args: argparse.Namespace, db: aiosqlite.Connection) -> None:
    """Edit an existing host's properties."""
    # Fetch the existing host
    async with db.execute(
        "SELECT id, name, domain, mac_address, current_ip, npm_proxy_host_id, "
        "port, grace_minutes, enabled, notes, updated_at FROM hosts WHERE id = ?",
        (host_id,),
    ) as cursor:
        row = await cursor.fetchone()
        if not row:
            raise ValueError(f"Host {host_id} was not found")

    # Validate port if provided
    if args.port is not None and not (1 <= args.port <= 65535):
        raise ValueError("--port must be between 1 and 65535")

    # Validate grace minutes if provided
    if args.grace_minutes is not None and args.grace_minutes < 0:
        raise ValueError("--grace-minutes must be zero or greater")

    # Build update fields
    updates = []
    values = []

    if args.name is not None:
        updates.append("name = ?")
        values.append(args.name)

    if args.mac is not None:
        updates.append("mac_address = ?")
        values.append(normalize_mac(args.mac))

    if args.ip is not None:
        updates.append("current_ip = ?")
        values.append(args.ip)

    if args.domain is not None:
        updates.append("domain = ?")
        values.append(args.domain)

    if args.npm_proxy_host_id is not None:
        updates.append("npm_proxy_host_id = ?")
        values.append(args.npm_proxy_host_id)

    if args.port is not None:
        updates.append("port = ?")
        values.append(args.port)

    if args.grace_minutes is not None:
        updates.append("grace_minutes = ?")
        values.append(args.grace_minutes)

    if args.enable:
        updates.append("enabled = 1")

    if args.disable:
        updates.append("enabled = 0")

    if args.notes is not None:
        updates.append("notes = ?")
        values.append(args.notes)

    if not updates:
        print("No changes specified. Use --help for available options.")
        return

    now = current_time().isoformat()
    updates.append("updated_at = ?")
    values.append(now)
    values.append(host_id)

    await db.execute(
        f"UPDATE hosts SET {', '.join(updates)} WHERE id = ?",
        values,
    )
    await db.commit()

    # Update host_state last_ip if IP changed
    if args.ip is not None:
        await db.execute(
            "UPDATE host_state SET last_ip = ? WHERE host_id = ?",
            (args.ip, host_id),
        )
        await db.commit()

    print(json.dumps({
        "id": host_id,
        "updated": True,
        "fields": updates[:-1],  # exclude updated_at
    }))


async def run(args: argparse.Namespace) -> None:
    await init_db()
    async with aiosqlite.connect(settings.db_path) as db:
        if args.command == "add-host":
            await add_host(args, db)
        elif args.command == "list-hosts":
            await list_hosts(db)
        elif args.command == "list-npm-hosts":
            await list_npm_hosts(db)
        elif args.command == "check-npm-db":
            await check_npm_db(args)
        elif args.command == "list-events":
            await list_events(args, db)
        elif args.command == "disable-host":
            await disable_host(args.host_id, db)
        elif args.command == "edit-host":
            await edit_host(args.host_id, args, db)
        elif args.command == "add-telegram":
            await add_telegram(args, db)
        elif args.command == "list-telegram":
            await list_telegram(db)
        elif args.command == "disable-telegram":
            await disable_telegram(args.channel_id, db)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        asyncio.run(run(build_parser().parse_args(argv)))
    except (ValueError, aiosqlite.IntegrityError) as error:
        print(f"Error: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
