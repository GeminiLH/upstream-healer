"""Tests for app.database — init_db behavior on throwaway SQLite files."""
from __future__ import annotations

import aiosqlite
import pytest

from app.database import init_db

EXPECTED_TABLES = {
    "hosts",
    "settings",
    "notification_channels",
    "notification_rules",
    "events",
    "host_state",
}


async def _table_names(db_path):
    async with aiosqlite.connect(db_path) as db:
        async with db.execute("SELECT name FROM sqlite_master WHERE type = 'table'") as cur:
            return {row[0] for row in await cur.fetchall()}


async def test_init_db_creates_all_tables(temp_settings):
    await init_db()
    tables = await _table_names(temp_settings.db_path)
    assert EXPECTED_TABLES.issubset(tables)


async def test_init_db_creates_data_dir(temp_settings):
    await init_db()
    assert temp_settings.data_dir.exists()
    assert temp_settings.db_path.exists()


async def test_init_db_seeds_default_settings(temp_settings):
    await init_db()
    async with aiosqlite.connect(temp_settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT key, value FROM settings") as cur:
            conf = {row["key"]: row["value"] for row in await cur.fetchall()}
    assert conf["grace_minutes"] == "10"
    assert conf["check_interval_seconds"] == "600"
    assert conf["event_retention_days"] == "10"
    assert conf["telegram_enabled"] == "1"
    assert conf["email_enabled"] == "1"


async def test_init_db_is_idempotent(temp_settings):
    await init_db()
    await init_db()
    await init_db()
    tables = await _table_names(temp_settings.db_path)
    assert EXPECTED_TABLES.issubset(tables)
    async with aiosqlite.connect(temp_settings.db_path) as db:
        async with db.execute("SELECT COUNT(*) FROM settings") as cur:
            count = (await cur.fetchone())[0]
    assert count == 5  # seeded once, INSERT OR IGNORE on later runs


async def test_host_identity_unique_on_mac_and_port(temp_settings):
    await init_db()
    async with aiosqlite.connect(temp_settings.db_path) as db:
        await db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES (?, ?, ?)",
            ("h1", "AA:BB:CC:DD:EE:FF", 80),
        )
        # same MAC, different port — allowed
        await db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES (?, ?, ?)",
            ("h2", "AA:BB:CC:DD:EE:FF", 81),
        )
        # same MAC + port — rejected
        with pytest.raises(aiosqlite.IntegrityError):
            await db.execute(
                "INSERT INTO hosts (name, mac_address, port) VALUES (?, ?, ?)",
                ("h3", "AA:BB:CC:DD:EE:FF", 80),
            )