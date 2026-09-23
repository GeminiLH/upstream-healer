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


# ───────────────────────────── Validate (host edit screen) ─────────────────────────────


def _insert_host(s, **overrides):
    """Seed one host row into the throwaway test DB; returns its id."""
    import asyncio
    import aiosqlite

    cols = {
        "name": "vault", "local_device_name": None, "quiet_enabled": 0,
        "quiet_start": None, "quiet_end": None, "quiet_mode": "suppress",
        "domain": None, "mac_address": "aa:bb:cc:dd:ee:ff",
        "current_ip": "192.168.86.9", "npm_proxy_host_id": None,
        "subnet_id": None, "port": 80, "grace_minutes": 10,
        "enabled": 1, "notes": None, "created_at": None, "updated_at": None,
    }
    cols.update(overrides)
    keys = ", ".join(cols)
    marks = ", ".join("?" * len(cols))

    async def _ins():
        async with aiosqlite.connect(s.db_path) as db:
            await db.execute(f"INSERT INTO hosts ({keys}) VALUES ({marks})", tuple(cols.values()))
            await db.commit()
            async with db.execute("SELECT id FROM hosts") as cur:
                return (await cur.fetchall())[-1][0]

    return asyncio.run(_ins())


def _count_events(s):
    import asyncio
    import aiosqlite

    async def _n():
        async with aiosqlite.connect(s.db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM events") as cur:
                row = await cur.fetchone()
            return row[0]

    return asyncio.run(_n())


_VALIDATION_RESULT = {
    "sweep": {"subnets": None, "responders": 3, "error": None},
    "mac": {"target": "aa:bb:cc:dd:ee:ff", "found": True, "ip": "192.168.86.9",
            "hostname": "vault.local", "services": []},
    "ip": {"target": "192.168.86.9", "mac": "aa:bb:cc:dd:ee:ff", "mac_routed": False,
           "hostname": "vault.local", "port": 80, "port_state": "open", "services": []},
}


def test_validate_route_registered():
    paths = {route.path for route in app.routes}
    assert "/hosts/{host_id}/validate" in paths


def test_validate_endpoint_returns_result_and_logs_event(temp_db_file):
    host_id = _insert_host(temp_db_file)
    with patch(
        "app.main.validate_host_record",
        new=AsyncMock(return_value=_VALIDATION_RESULT),
    ) as mock_val:
        resp = TestClient(app).post(f"/hosts/{host_id}/validate", json={})
    assert resp.status_code == 200
    assert resp.json() == _VALIDATION_RESULT
    kw = mock_val.call_args.kwargs
    # empty form fields fall back to the saved host row
    assert kw["mac"] == "aa:bb:cc:dd:ee:ff"
    assert kw["ip"] == "192.168.86.9"
    assert kw["port"] == 80
    # logged (no notify) but never mutates the host record
    assert _count_events(temp_db_file) == 1


def test_validate_404_for_unknown_host(temp_db_file):
    resp = TestClient(app).post("/hosts/999/validate", json={})
    assert resp.status_code == 404


def test_validate_rejects_host_with_no_targets(temp_db_file):
    host_id = _insert_host(temp_db_file, mac_address="", current_ip=None)
    resp = TestClient(app).post(f"/hosts/{host_id}/validate", json={})
    assert resp.status_code == 400
    assert "Nothing to validate" in resp.json()["detail"]


def test_validate_rejects_out_of_range_port(temp_db_file):
    host_id = _insert_host(temp_db_file)
    resp = TestClient(app).post(f"/hosts/{host_id}/validate", json={"port": 99999})
    assert resp.status_code == 422


def test_validate_scopes_sweep_to_pinned_subnet(temp_db_file):
    import aiosqlite
    import asyncio

    async def _add_subnet():
        async with aiosqlite.connect(temp_db_file.db_path) as db:
            await db.execute(
                "INSERT INTO subnets (name, cidr, interface, enabled, check_interval_seconds)"
                " VALUES (?, ?, NULL, 1, NULL)",
                ("Test net", "10.9.0.0/24"),
            )
            await db.commit()
            async with db.execute("SELECT id FROM subnets") as cur:
                return (await cur.fetchall())[-1][0]

    subnet_id = asyncio.run(_add_subnet())
    host_id = _insert_host(temp_db_file, subnet_id=subnet_id)
    with patch("app.main.validate_host_record", new=AsyncMock(return_value=_VALIDATION_RESULT)) as mock_val:
        resp = TestClient(app).post(f"/hosts/{host_id}/validate", json={})
    assert resp.status_code == 200
    assert mock_val.call_args.kwargs["subnet_cidrs"] == ["10.9.0.0/24"]


def test_edit_page_shows_validate_button(temp_db_file, npm_client):
    host_id = _insert_host(temp_db_file)
    resp = TestClient(app).get(f"/hosts/{host_id}/edit")
    assert resp.status_code == 200
    assert 'id="validate-btn"' in resp.text
    assert "Validate" in resp.text


def test_add_page_has_no_validate_button(temp_db_file, npm_client):
    resp = TestClient(app).get("/hosts/add")
    assert resp.status_code == 200
    assert 'id="validate-btn"' not in resp.text


# ───────────────────────────── MAC + port uniqueness ─────────────────────────────


def _host_values(s, host_id):
    """Fetch (name, mac_address, port) for a host row from the throwaway test DB."""
    import asyncio
    import aiosqlite

    async def _get():
        async with aiosqlite.connect(s.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT name, mac_address, port FROM hosts WHERE id = ?", (host_id,)
            ) as cur:
                row = await cur.fetchone()
            return None if row is None else (row["name"], row["mac_address"], row["port"])

    return asyncio.run(_get())


def _host_count(s):
    import asyncio
    import aiosqlite

    async def _count():
        async with aiosqlite.connect(s.db_path) as db:
            async with db.execute("SELECT COUNT(*) FROM hosts") as cur:
                return (await cur.fetchone())[0]

    return asyncio.run(_count())


def _edit_form(**overrides):
    """A complete POST body for /hosts/{id}/edit (the form submits every field)."""
    form = {
        "name": "vault", "local_device_name": "", "quiet_enabled": "off",
        "quiet_start": "", "quiet_end": "", "quiet_mode": "suppress",
        "domain": "", "mac_address": "aa:bb:cc:dd:ee:ff",
        "current_ip": "192.168.86.9", "port": 80, "npm_proxy_host_id": "",
        "subnet_id": "", "grace_minutes": 10, "notes": "", "enabled": "on",
    }
    form.update(overrides)
    return form


def test_edit_host_mac_port_conflict_is_prevented(temp_db_file):
    """Updating a host to another host's MAC + port must not 500 (UNIQUE
    constraint): the form re-renders with a clear error naming the conflicting
    host, the row is left unchanged, and the user's input is preserved."""
    a = _insert_host(temp_db_file, name="alpha", mac_address="aa:bb:cc:dd:ee:01")
    _insert_host(temp_db_file, name="bravo", mac_address="aa:bb:cc:dd:ee:02")

    resp = TestClient(app).post(
        f"/hosts/{a}/edit",
        data=_edit_form(name="alpha", mac_address="aa:bb:cc:dd:ee:02"),
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "already used by host" in resp.text
    assert "bravo" in resp.text
    # The submitted values are repopulated so the user can correct them.
    assert 'value="aa:bb:cc:dd:ee:02"' in resp.text
    # Nothing was changed.
    assert _host_values(temp_db_file, a) == ("alpha", "aa:bb:cc:dd:ee:01", 80)


def test_edit_host_own_mac_port_is_not_a_conflict(temp_db_file):
    """Saving a host's own MAC + port (e.g. a rename) must still work."""
    a = _insert_host(temp_db_file, name="alpha")

    resp = TestClient(app).post(
        f"/hosts/{a}/edit",
        data=_edit_form(name="alpha2"),
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert _host_values(temp_db_file, a) == ("alpha2", "aa:bb:cc:dd:ee:ff", 80)


def test_add_host_mac_port_conflict_is_prevented(temp_db_file):
    _insert_host(temp_db_file, name="bravo", mac_address="aa:bb:cc:dd:ee:02")

    resp = TestClient(app).post(
        "/hosts/add",
        data={
            "name": "charlie", "local_device_name": "", "quiet_enabled": "off",
            "quiet_start": "", "quiet_end": "", "quiet_mode": "suppress",
            "domain": "", "mac_address": "aa:bb:cc:dd:ee:02",
            "current_ip": "", "port": 80, "npm_proxy_host_id": "",
            "subnet_id": "", "grace_minutes": 10, "notes": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "already used by host" in resp.text
    assert "bravo" in resp.text
    # No new host was created.
    assert _host_count(temp_db_file) == 1
    # The repopulated add form shows no controls for a non-existent host.
    assert 'id="validate-btn"' not in resp.text
    assert "/hosts//delete" not in resp.text
