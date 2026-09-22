import asyncio
from unittest.mock import AsyncMock, patch

import aiosqlite

from app.services.monitor import Monitor
from app.config import current_time


async def _setup_db(tmp_path):
    db_path = tmp_path / "healer_test.db"
    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = aiosqlite.Row
    # Minimal schema for hosts and host_state
    await conn.execute(
        """CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mac_address TEXT NOT NULL, current_ip TEXT, npm_proxy_host_id INTEGER, port INTEGER DEFAULT 80, enabled INTEGER DEFAULT 1, created_at TEXT, updated_at TEXT)"""
    )
    await conn.execute(
        """CREATE TABLE host_state (host_id INTEGER PRIMARY KEY, status TEXT DEFAULT 'unknown', last_seen_at TEXT, unreachable_since TEXT, last_check_at TEXT, last_ip TEXT)"""
    )
    await conn.commit()
    return conn


async def test_start_recovery_reachable(tmp_path):
    db = await _setup_db(tmp_path)
    now = current_time().isoformat()
    # Insert a host and its state (unreachable)
    await db.execute(
        "INSERT INTO hosts (id, name, mac_address, current_ip, npm_proxy_host_id, port, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (1, "testhost", "aa:bb:cc:dd:ee:ff", None, None, 80, 1, now, now),
    )
    await db.execute("INSERT INTO host_state (host_id, status, last_ip) VALUES (?,?,?)", (1, "unreachable", None))
    await db.commit()

    mon = Monitor()

    # Patch find_ip_by_mac to return an IP and check_host_reachable to return True
    with patch("app.services.scanner.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.5")), \
        patch("app.services.scanner.check_host_reachable", new=AsyncMock(return_value=True)), \
        patch.object(mon.npm, "update_forward_host", return_value=True) as mock_update, \
        patch.object(mon.npm, "reload_nginx", return_value=True) as mock_reload:

        host_row = {"id": 1, "name": "testhost", "mac_address": "aa:bb:cc:dd:ee:ff", "npm_proxy_host_id": 42, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # Verify DB updated
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 1") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] == "10.0.0.5"


async def test_start_recovery_not_reachable(tmp_path):
    db = await _setup_db(tmp_path)
    now = current_time().isoformat()
    await db.execute(
        "INSERT INTO hosts (id, name, mac_address, current_ip, npm_proxy_host_id, port, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (2, "testhost2", "de:ad:be:ef:00:02", None, None, 80, 1, now, now),
    )
    await db.execute("INSERT INTO host_state (host_id, status, last_ip) VALUES (?,?,?)", (2, "unreachable", None))
    await db.commit()

    mon = Monitor()

    with patch("app.services.scanner.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.6")), \
        patch("app.services.scanner.check_host_reachable", new=AsyncMock(return_value=False)):

        host_row = {"id": 2, "name": "testhost2", "mac_address": "de:ad:be:ef:00:02", "npm_proxy_host_id": None, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # Verify hosts.current_ip not updated, but host_state.last_ip recorded
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 2") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] is None
    async with db.execute("SELECT last_ip FROM host_state WHERE host_id = 2") as cur:
        row = await cur.fetchone()
        assert row["last_ip"] == "10.0.0.6"


async def test_start_recovery_npm_update_failure(tmp_path):
    db = await _setup_db(tmp_path)
    now = current_time().isoformat()
    await db.execute(
        "INSERT INTO hosts (id, name, mac_address, current_ip, npm_proxy_host_id, port, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (3, "testhost3", "aa:aa:aa:aa:aa:03", None, 99, 80, 1, now, now),
    )
    await db.execute("INSERT INTO host_state (host_id, status, last_ip) VALUES (?,?,?)", (3, "unreachable", None))
    await db.commit()

    mon = Monitor()

    # Backend reachable, but NPM update fails
    with patch("app.services.scanner.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.7")), \
        patch("app.services.scanner.check_host_reachable", new=AsyncMock(return_value=True)), \
        patch.object(mon.npm, "update_forward_host", return_value=False) as mock_update, \
        patch.object(mon.npm, "reload_nginx", return_value=True) as mock_reload:

        host_row = {"id": 3, "name": "testhost3", "mac_address": "aa:aa:aa:aa:aa:03", "npm_proxy_host_id": 99, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # Even if NPM update failed, we still persist the discovered IP because the backend answered
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 3") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] == "10.0.0.7"


async def test_start_recovery_npm_reload_failure(tmp_path):
    db = await _setup_db(tmp_path)
    now = current_time().isoformat()
    await db.execute(
        "INSERT INTO hosts (id, name, mac_address, current_ip, npm_proxy_host_id, port, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (4, "testhost4", "aa:aa:aa:aa:aa:04", None, 100, 80, 1, now, now),
    )
    await db.execute("INSERT INTO host_state (host_id, status, last_ip) VALUES (?,?,?)", (4, "unreachable", None))
    await db.commit()

    mon = Monitor()

    # Backend reachable, NPM update succeeds but reload fails
    with patch("app.services.scanner.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.8")), \
        patch("app.services.scanner.check_host_reachable", new=AsyncMock(return_value=True)), \
        patch.object(mon.npm, "update_forward_host", return_value=True) as mock_update, \
        patch.object(mon.npm, "reload_nginx", return_value=False) as mock_reload:

        host_row = {"id": 4, "name": "testhost4", "mac_address": "aa:aa:aa:aa:aa:04", "npm_proxy_host_id": 100, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # IP persisted even if reload failed
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 4") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] == "10.0.0.8"
