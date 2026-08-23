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


async def run(args: argparse.Namespace) -> None:
    await init_db()
    async with aiosqlite.connect(settings.db_path) as db:
        if args.command == "add-host":
            await add_host(args, db)
        elif args.command == "list-hosts":
            await list_hosts(db)
        elif args.command == "list-events":
            await list_events(args, db)
        elif args.command == "disable-host":
            await disable_host(args.host_id, db)
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
