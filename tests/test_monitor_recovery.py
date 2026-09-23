from unittest.mock import AsyncMock, patch

import aiosqlite

from app.services.monitor import Monitor
from app.config import current_time
from app.database import SCHEMA


async def _setup_db(tmp_path):
    db_path = tmp_path / "healer_test.db"
    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = aiosqlite.Row
    # Use the app's canonical schema, not a minimal two-table subset:
    # _start_recovery also reads `subnets` (list_subnets, when the host has no
    # pinned subnet) and inserts into `events` (send_event, always — the row
    # is logged even with notify=False). Reusing SCHEMA keeps the fixture from
    # drifting when the schema evolves.
    await conn.executescript(SCHEMA)
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

    # Patch find_ip_by_mac to return an IP and check_host_reachable to return True.
    # Patch where monitor.py *uses* them: it does `from app.services.scanner import ...`,
    # so patching app.services.scanner.* would not affect the names bound in app.services.monitor.
    with patch("app.services.monitor.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.5")), \
        patch("app.services.monitor.check_host_reachable", new=AsyncMock(return_value=True)), \
        patch.object(mon.npm, "update_forward_host", return_value=True), \
        patch.object(mon.npm, "reload_nginx", return_value=True):

        host_row = {"id": 1, "name": "testhost", "mac_address": "aa:bb:cc:dd:ee:ff", "npm_proxy_host_id": 42, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # Verify DB updated
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 1") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] == "10.0.0.5"
    # aiosqlite runs each connection in a non-daemon thread; an unclosed
    # connection hangs interpreter shutdown (pytest exits only after the
    # summary is printed).
    await db.close()


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

    with patch("app.services.monitor.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.6")), \
        patch("app.services.monitor.check_host_reachable", new=AsyncMock(return_value=False)):

        host_row = {"id": 2, "name": "testhost2", "mac_address": "de:ad:be:ef:00:02", "npm_proxy_host_id": None, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # Verify hosts.current_ip not updated, but host_state.last_ip recorded
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 2") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] is None
    async with db.execute("SELECT last_ip FROM host_state WHERE host_id = 2") as cur:
        row = await cur.fetchone()
        assert row["last_ip"] == "10.0.0.6"
    await db.close()


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
    with patch("app.services.monitor.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.7")), \
        patch("app.services.monitor.check_host_reachable", new=AsyncMock(return_value=True)), \
        patch.object(mon.npm, "update_forward_host", return_value=False), \
        patch.object(mon.npm, "reload_nginx", return_value=True):

        host_row = {"id": 3, "name": "testhost3", "mac_address": "aa:aa:aa:aa:aa:03", "npm_proxy_host_id": 99, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # Even if NPM update failed, we still persist the discovered IP because the backend answered
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 3") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] == "10.0.0.7"
    await db.close()


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
    with patch("app.services.monitor.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.8")), \
        patch("app.services.monitor.check_host_reachable", new=AsyncMock(return_value=True)), \
        patch.object(mon.npm, "update_forward_host", return_value=True), \
        patch.object(mon.npm, "reload_nginx", return_value=False):

        host_row = {"id": 4, "name": "testhost4", "mac_address": "aa:aa:aa:aa:aa:04", "npm_proxy_host_id": 100, "port": 80, "subnet_id": None}
        await mon._start_recovery(db, host_row, notify=False)

    # IP persisted even if reload failed
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 4") as cur:
        row = await cur.fetchone()
        assert row["current_ip"] == "10.0.0.8"
    await db.close()


async def test_start_recovery_propagates_new_ip_to_same_mac_siblings(tmp_path):
    """When a box recovers at a new IP, every other record tracking the same MAC
    (other ports on the same device) adopts that IP too — so it confirms healthy
    on its own port next cycle instead of burning a grace period. Only
    ``current_ip`` is propagated; the sibling is not force-marked healthy."""
    db = await _setup_db(tmp_path)
    now = current_time().isoformat()
    await db.execute(
        "INSERT INTO hosts (id, name, mac_address, current_ip, npm_proxy_host_id, port, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (10, "batcave-web", "aa:bb:cc:dd:ee:99", None, None, 8787, 1, now, now),
    )
    await db.execute(
        "INSERT INTO hosts (id, name, mac_address, current_ip, npm_proxy_host_id, port, enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (11, "batcave-npm", "aa:bb:cc:dd:ee:99", None, None, 8181, 1, now, now),
    )
    await db.execute("INSERT INTO host_state (host_id, status, last_ip) VALUES (?,?,?)", (10, "unreachable", None))
    await db.execute("INSERT INTO host_state (host_id, status, last_ip) VALUES (?,?,?)", (11, "unreachable", None))
    await db.commit()

    mon = Monitor()
    with patch("app.services.monitor.find_ip_by_mac", new=AsyncMock(return_value="10.0.0.5")), \
        patch("app.services.monitor.check_host_reachable", new=AsyncMock(return_value=True)):
        host_row = {
            "id": 10, "name": "batcave-web", "mac_address": "aa:bb:cc:dd:ee:99",
            "npm_proxy_host_id": None, "port": 8787, "subnet_id": None,
        }
        await mon._start_recovery(db, host_row, notify=False)

    # The recovering record adopts the new IP…
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 10") as cur:
        assert (await cur.fetchone())["current_ip"] == "10.0.0.5"
    # …and the sibling record on the same box does too.
    async with db.execute("SELECT current_ip FROM hosts WHERE id = 11") as cur:
        assert (await cur.fetchone())["current_ip"] == "10.0.0.5"
    # The sibling is NOT force-marked healthy — its own port is confirmed next cycle.
    async with db.execute("SELECT status FROM host_state WHERE host_id = 11") as cur:
        assert (await cur.fetchone())["status"] == "unreachable"
    await db.close()
