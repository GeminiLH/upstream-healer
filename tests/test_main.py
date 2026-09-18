"""Smoke tests for the FastAPI app (lifespan is NOT triggered, no network)."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.main import app


def test_app_metadata():
    assert app.title == "Upstream Healer"


def test_routes_registered():
    paths = {route.path for route in app.routes}
    assert "/" in paths
    assert "/hosts/add" in paths
    assert "/settings" in paths
    assert "/api/health" in paths
    assert "/api/diagnostic" in paths
    assert "/api/diagnostic/scan" in paths


def test_scan_endpoint_rejects_bad_method(temp_db_file):
    # /api/diagnostic/scan validates its input without touching the network.
    client = TestClient(app)
    resp = client.post("/api/diagnostic/scan", json={"target_mac": "aa:bb:cc:dd:ee:ff", "method": "nope"})
    assert resp.status_code == 400
    assert "Unknown scanner method" in resp.json()["detail"]


def test_scan_endpoint_rejects_empty_mac(temp_db_file):
    client = TestClient(app)
    resp = client.post("/api/diagnostic/scan", json={"target_mac": "   ", "method": "arp-scan"})
    assert resp.status_code == 400
    assert "target_mac is required" in resp.json()["detail"]


def test_scan_endpoint_scopes_to_subnet_cidr(temp_db_file):
    """Auto-detected subnets have no DB id — the UI targets them by CIDR."""
    client = TestClient(app)
    with patch(
        "app.main.run_scan",
        new=AsyncMock(
            return_value={"method": "arp-scan", "found_ip": None, "found_via": None, "output": "", "error": None}
        ),
    ) as mock_scan:
        resp = client.post(
            "/api/diagnostic/scan",
            json={"target_mac": "aa:bb:cc:dd:ee:ff", "method": "arp-scan", "subnet_id": 0, "subnet_cidr": "192.168.86.0/24"},
        )
    assert resp.status_code == 200
    assert mock_scan.call_args.kwargs.get("subnets") == ["192.168.86.0/24"]


def test_scan_endpoint_rejects_invalid_subnet_cidr(temp_db_file):
    client = TestClient(app)
    resp = client.post(
        "/api/diagnostic/scan",
        json={"target_mac": "aa:bb:cc:dd:ee:ff", "method": "arp-scan", "subnet_cidr": "not-a-cidr"},
    )
    assert resp.status_code == 400
    assert "Invalid subnet CIDR" in resp.json()["detail"]


def test_health_endpoint():
    # Used without a context manager so the lifespan (init_db, monitor.start)
    # never runs; /api/health does not touch the database.
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "upstream-healer"}


def test_routes_registered_subnets():
    paths = {route.path for route in app.routes}
    # The subnets CRUD routes live under /settings (no dedicated nav link, to
    # avoid widening the top-bar surface area).
    assert "/settings" in paths
    assert "/settings/subnets" in paths
    assert "/settings/subnets/{subnet_id}/toggle" in paths
    assert "/settings/subnets/{subnet_id}/delete" in paths
    # Auto subnets are not DB rows; they are managed by CIDR instead.
    assert "/settings/subnets/suppress" in paths
    assert "/settings/subnets/rescan" in paths
    assert "/settings/subnets/rescan-all" in paths

async def _read_setting(s, key):
    import aiosqlite

    async with aiosqlite.connect(s.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
            row = await cur.fetchone()
        return None if row is None else row["value"]


def test_subnet_suppress_and_rescan_roundtrip(temp_db_file):
    """Delete (suppress) an auto subnet, verify it leaves the effective list,
    rescan it, verify it is back — exactly the stale-subnet workflow."""
    import json
    from unittest.mock import patch

    from app.services.scanner import list_subnets

    client = TestClient(app)

    async def _check(include): await list_subnets(None)

    resp = client.post("/settings/subnets/suppress", data={"cidr": "192.168.99.0/24"}, follow_redirects=False)
    assert resp.status_code == 303
    assert json.loads(_read_sync(temp_db_file, "suppressed_subnets")) == ["192.168.99.0/24"]

    with patch(
        "app.main.get_default_subnets",
        return_value=[{"cidr": "192.168.99.0/24", "interface": "enp9", "source": "auto"}],
    ), patch("app.main.get_local_interfaces", return_value=[]):
        resp = client.get("/settings")
    assert resp.status_code == 200
    assert "192.168.99.0/24" in resp.text  # still shown
    assert "rescan" in resp.text

    resp = client.post("/settings/subnets/rescan", data={"cidr": "192.168.99.0/24"}, follow_redirects=False)
    assert resp.status_code == 303
    assert json.loads(_read_sync(temp_db_file, "suppressed_subnets")) == []


def _read_sync(s, key):
    import asyncio
    import aiosqlite

    async def _get():
        async with aiosqlite.connect(s.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute("SELECT value FROM settings WHERE key = ?", (key,)) as cur:
                row = await cur.fetchone()
            return None if row is None else row["value"]

    return asyncio.run(_get())


def _subnets_sync(s):
    import asyncio
    import aiosqlite

    async def _get():
        async with aiosqlite.connect(s.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY id"
            ) as cur:
                return [dict(r) for r in await cur.fetchall()]

    return asyncio.run(_get())


def test_settings_page_renders_auto_subnets(temp_db_file):
    from unittest.mock import patch

    with patch(
        "app.main.get_default_subnets",
        return_value=[{"cidr": "10.9.0.0/24", "interface": "enp9", "source": "auto"}],
    ), patch(
        "app.main.get_local_interfaces",
        return_value=[{"name": "enp9", "address": "10.9.0.38", "cidr": "10.9.0.38/24"}],
    ):
        resp = TestClient(app).get("/settings")
    assert resp.status_code == 200
    assert "10.9.0.0/24" in resp.text
    assert "(auto)" in resp.text
    # Interface field is backed by a datalist of real NICs (suggestion)…
    assert "iface-options" in resp.text
    assert "enp9" in resp.text
    # …and the card offers a global "Rescan networks" action.
    assert "rescan-all" in resp.text
    assert "Rescan networks" in resp.text


def test_settings_page_renders_empty_interface_suggestion(temp_db_file):
    """No local NICs (e.g. a Windows dev box) -> no suggestions, still renders."""
    from unittest.mock import patch

    with patch("app.main.get_default_subnets", return_value=[]), \
         patch("app.main.get_local_interfaces", return_value=[]):
        resp = TestClient(app).get("/settings")
    assert resp.status_code == 200
    assert "iface-options" in resp.text
    assert "(none detected)" in resp.text


def test_add_subnet_rejects_host_cidr(temp_db_file):
    """A /32 (single host) can't be swept — rejected with a lay-person message."""
    client = TestClient(app)
    resp = client.post(
        "/settings/subnets",
        data={"name": "Host", "cidr": "192.168.10.5/32", "interface": "", "enabled": "on"},
        follow_redirects=False,
    )
    assert resp.status_code == 400
    assert "single link/host" in resp.json()["detail"]


def test_add_subnet_auto_interface_treated_as_blank(temp_db_file):
    """Typing the literal 'auto' must behave like a blank (auto-detect), not a NIC name."""
    from unittest.mock import patch

    client = TestClient(app)
    with patch("app.main.get_local_interfaces", return_value=[
        {"name": "enp6s0", "address": "192.168.10.2", "cidr": "192.168.10.2/28"},
    ]):
        resp = client.post(
            "/settings/subnets",
            data={"name": "VLAN", "cidr": "192.168.10.0/28", "interface": "auto", "enabled": "on"},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    row = _subnets_sync(temp_db_file)[0]
    assert row["cidr"] == "192.168.10.0/28"
    assert row["interface"] is None


def test_add_subnet_unknown_interface_rejected(temp_db_file):
    """A NIC name that does not exist on this host is rejected, with the real ones offered."""
    from unittest.mock import patch

    client = TestClient(app)
    with patch("app.main.get_local_interfaces", return_value=[
        {"name": "enp6s0", "address": "192.168.10.2", "cidr": "192.168.10.2/28"},
    ]):
        resp = client.post(
            "/settings/subnets",
            data={"name": "VLAN", "cidr": "192.168.10.0/28", "interface": "eth9", "enabled": "on"},
            follow_redirects=False,
        )
    assert resp.status_code == 400
    assert "not found on this host" in resp.json()["detail"]
    assert "enp6s0" in resp.json()["detail"]


def test_add_subnet_interface_not_validated_when_undetectable(temp_db_file):
    """No `ip` (Windows dev box) -> can't see NICs, so an arbitrary name is accepted."""
    from unittest.mock import patch

    client = TestClient(app)
    with patch("app.main.get_local_interfaces", return_value=[]):
        resp = client.post(
            "/settings/subnets",
            data={"name": "VLAN", "cidr": "192.168.10.0/28", "interface": "veth100", "enabled": "on"},
            follow_redirects=False,
        )
    assert resp.status_code == 303
    assert _subnets_sync(temp_db_file)[0]["interface"] == "veth100"


def test_rescan_all_clears_suppression(temp_db_file):
    """The global 'Rescan networks' action re-includes every auto-detected network."""
    import json

    client = TestClient(app)
    client.post("/settings/subnets/suppress", data={"cidr": "192.168.99.0/24"}, follow_redirects=False)
    assert json.loads(_read_sync(temp_db_file, "suppressed_subnets")) == ["192.168.99.0/24"]

    resp = client.post("/settings/subnets/rescan-all", follow_redirects=False)
    assert resp.status_code == 303
    assert json.loads(_read_sync(temp_db_file, "suppressed_subnets")) == []
