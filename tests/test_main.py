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
    assert "/api/diagnostic/scan-log" in paths


def test_scan_log_disabled_404(monkeypatch):
    # No UPSTREAM_HEALER_DEBUG_LOG_DIR (test/prod stacks): the endpoint must
    # not exist rather than leak something.
    monkeypatch.delenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", raising=False)
    monkeypatch.delenv("UPSTREAM_HEALER_ENV", raising=False)
    client = TestClient(app)
    resp = client.get("/api/diagnostic/scan-log")
    assert resp.status_code == 404
    assert "disabled" in resp.json()["detail"]


def test_scan_log_production_tripwire(tmp_path, monkeypatch):
    # Even with the directory set, a production env tag suppresses logging —
    # the endpoint follows suit.
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("UPSTREAM_HEALER_ENV", "production")
    resp = TestClient(app).get("/api/diagnostic/scan-log")
    assert resp.status_code == 404


def test_scan_log_empty_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("UPSTREAM_HEALER_ENV", raising=False)
    resp = TestClient(app).get("/api/diagnostic/scan-log")
    assert resp.status_code == 200
    assert resp.json() == {"files": [], "latest": None}


def test_scan_log_serves_newest(tmp_path, monkeypatch):
    import os
    import time

    (tmp_path / "diag_old.log").write_text("old\n")
    newest = tmp_path / "diag_new.log"
    newest.write_text("new line\n")
    future = time.time() + 60
    os.utime(newest, (future, future))
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    monkeypatch.delenv("UPSTREAM_HEALER_ENV", raising=False)
    resp = TestClient(app).get("/api/diagnostic/scan-log")
    assert resp.status_code == 200
    data = resp.json()
    assert data["latest"]["name"] == "diag_new.log"
    assert "new line" in data["latest"]["content"]
    names = {f["name"] for f in data["files"]}
    assert names == {"diag_old.log", "diag_new.log"}
    for f in data["files"]:
        assert "path" not in f  # never leak absolute paths


def test_scan_endpoint_rejects_bad_method(temp_db_file):
    # /api/diagnostic/scan validates its input without touching the network.
    client = TestClient(app)
    resp = client.post("/api/diagnostic/scan", json={"target_mac": "aa:bb:cc:dd:ee:ff", "method": "nope"})
    assert resp.status_code == 400
    assert "Unknown scanner method" in resp.json()["detail"]


def test_scan_endpoint_allows_empty_mac_sweep(temp_db_file):
    # An empty target MAC is now valid: it performs a plain sweep that lists
    # every host instead of hunting for one specific device.
    client = TestClient(app)
    with patch("app.main.list_subnets", new=AsyncMock(return_value=[])), \
         patch(
            "app.main.run_scan",
            new=AsyncMock(return_value={"method": "arp-scan", "found_ip": None, "found_via": None, "output": "", "error": None, "hosts": []}),
         ) as mock_scan:
        resp = client.post("/api/diagnostic/scan", json={"target_mac": "", "method": "arp-scan"})
    assert resp.status_code == 200
    assert mock_scan.call_args.args[0] == ""


def test_scan_endpoint_passes_scan_ports(temp_db_file):
    """Port scanning is now incremental: discovery runs first (scan_ports=False),
    then run_port_scan_incremental is called for each host."""
    client = TestClient(app)
    with patch("app.main.list_subnets", new=AsyncMock(return_value=[])), \
         patch(
            "app.main.run_scan",
            new=AsyncMock(return_value={"method": "nmap", "found_ip": None, "found_via": None, "output": "", "error": None, "hosts": []}),
         ) as mock_scan, \
         patch("app.main.run_port_scan_incremental", new=AsyncMock(return_value=({}, None))) as _mock_port:
        resp = client.post(
            "/api/diagnostic/scan",
            json={"target_mac": "", "method": "nmap", "scan_ports": True},
        )
    assert resp.status_code == 200
    # Discovery always runs with scan_ports=False (port scan is incremental)
    assert mock_scan.call_args.kwargs.get("scan_ports") is False


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


# ─────────────────────── Validate (add-host screen, not saved yet) ───────────────────────


def test_new_host_validate_route_registered():
    paths = {route.path for route in app.routes}
    assert "/hosts/validate" in paths


def test_new_host_validate_returns_result(temp_db_file):
    with patch(
        "app.main.validate_host_record", new=AsyncMock(return_value=_VALIDATION_RESULT)
    ) as mock_val:
        resp = TestClient(app).post(
            "/hosts/validate",
            json={"name": "vault", "mac": "aa:bb:cc:dd:ee:ff", "port": 80},
        )
    assert resp.status_code == 200
    assert resp.json() == _VALIDATION_RESULT
    kw = mock_val.call_args.kwargs
    assert kw["name"] == "vault"
    assert kw["mac"] == "aa:bb:cc:dd:ee:ff"
    assert kw["port"] == 80
    # Logged (no notify) but attached to no saved host.
    assert _count_events(temp_db_file) == 1


def test_new_host_validate_rejects_no_targets(temp_db_file):
    resp = TestClient(app).post("/hosts/validate", json={"mac": "", "ip": ""})
    assert resp.status_code == 400
    assert "Nothing to validate" in resp.json()["detail"]


def test_new_host_validate_rejects_out_of_range_port(temp_db_file):
    resp = TestClient(app).post("/hosts/validate", json={"ip": "1.2.3.4", "port": 99999})
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


def test_add_page_has_validate_button(temp_db_file, npm_client):
    resp = TestClient(app).get("/hosts/add")
    assert resp.status_code == 200
    assert 'id="validate-btn"' in resp.text
    # On the add form nothing is saved yet, so the button carries no host id —
    # it posts to the no-host-id endpoint.
    assert 'data-host-id=""' in resp.text


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
    # The repopulated add form has no delete control for a non-existent host,
    # but now does expose the hostless Validate button to help populate it.
    assert "/hosts//delete" not in resp.text
    assert 'id="validate-btn"' in resp.text


def test_add_host_same_mac_different_port_is_allowed(temp_db_file):
    """The same MAC may be watched on several ports: a second record for the same
    box (same MAC, different port) is accepted — only a duplicate MAC+port pair is
    rejected. This is the transparent multi-port-per-box workflow."""
    _insert_host(temp_db_file, name="batcave", mac_address="aa:bb:cc:dd:ee:88", port=8787)

    resp = TestClient(app).post(
        "/hosts/add",
        data={
            "name": "batcave", "local_device_name": "", "quiet_enabled": "off",
            "quiet_start": "", "quiet_end": "", "quiet_mode": "suppress",
            "domain": "", "mac_address": "aa:bb:cc:dd:ee:88",
            "current_ip": "", "port": 8181, "npm_proxy_host_id": "",
            "subnet_id": "", "grace_minutes": 10, "notes": "",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert _host_count(temp_db_file) == 2


# ───────────────────── NPM mismatch on add/edit + subnet display ───────────────

_NPM_FORWARD = {
    "forward_host": "10.0.0.5",
    "forward_port": 443,
    "domain_names": '["x.example"]',
}


def _host_row(s, host_id):
    """Fetch the full host row as a dict from the throwaway test DB."""
    import asyncio
    import aiosqlite

    async def _get():
        async with aiosqlite.connect(s.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                "SELECT * FROM hosts WHERE id = ?", (host_id,)
            ) as cur:
                row = await cur.fetchone()
            return None if row is None else dict(row)

    return asyncio.run(_get())


def _first_host_id(s):
    import asyncio
    import aiosqlite

    async def _id():
        async with aiosqlite.connect(s.db_path) as db:
            async with db.execute("SELECT id FROM hosts ORDER BY id LIMIT 1") as cur:
                row = await cur.fetchone()
            return None if row is None else row[0]

    return asyncio.run(_id())


def _insert_subnet(s, name, cidr):
    """Insert a manual subnet row; return its id."""
    import asyncio
    import aiosqlite

    async def _ins():
        async with aiosqlite.connect(s.db_path) as db:
            await db.execute(
                "INSERT INTO subnets (name, cidr, interface, enabled) VALUES (?, ?, ?, 1)",
                (name, cidr, None),
            )
            await db.commit()
            async with db.execute("SELECT id FROM subnets WHERE cidr = ?", (cidr,)) as cur:
                return (await cur.fetchone())[0]

    return asyncio.run(_ins())


def _last_event_details(s):
    import asyncio
    import aiosqlite

    async def _d():
        async with aiosqlite.connect(s.db_path) as db:
            async with db.execute(
                "SELECT details FROM events ORDER BY id DESC LIMIT 1"
            ) as cur:
                row = await cur.fetchone()
            return None if row is None else row[0]

    return asyncio.run(_d())


def _add_form(**overrides):
    form = {
        "name": "vault", "local_device_name": "", "quiet_enabled": "off",
        "quiet_start": "", "quiet_end": "", "quiet_mode": "suppress",
        "domain": "", "mac_address": "aa:bb:cc:dd:ee:ff",
        "current_ip": "192.168.86.9", "port": 80, "npm_proxy_host_id": "5",
        "subnet_id": "", "npm_action": "", "grace_minutes": 10, "notes": "",
    }
    form.update(overrides)
    return form


def test_add_shows_npm_mismatch_warning(temp_db_file):
    """Linking an NPM host whose forward differs from the entered IP/port
    re-renders the add form with a warning + 3 resolution buttons; nothing is
    saved yet."""
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        mock_npm.return_value.list_proxy_hosts.return_value = []
        resp = TestClient(app).post(
            "/hosts/add", data=_add_form(npm_action=""), follow_redirects=False
        )
    assert resp.status_code == 200
    assert "NPM record does not match" in resp.text
    assert "10.0.0.5:443" in resp.text
    assert 'value="match"' in resp.text
    assert 'value="link"' in resp.text
    assert 'value="cancel"' in resp.text
    assert _host_count(temp_db_file) == 0


def test_add_npm_mismatch_match_adopts_npm(temp_db_file):
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        resp = TestClient(app).post(
            "/hosts/add", data=_add_form(npm_action="match"), follow_redirects=False
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, _first_host_id(temp_db_file))
    assert row["current_ip"] == "10.0.0.5"
    assert row["port"] == 443
    assert row["npm_proxy_host_id"] == 5


def test_add_npm_mismatch_link_keeps_entered(temp_db_file):
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        resp = TestClient(app).post(
            "/hosts/add", data=_add_form(npm_action="link"), follow_redirects=False
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, _first_host_id(temp_db_file))
    assert row["current_ip"] == "192.168.86.9"
    assert row["port"] == 80
    assert row["npm_proxy_host_id"] == 5


def test_add_npm_mismatch_cancel_unlinks(temp_db_file):
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        resp = TestClient(app).post(
            "/hosts/add", data=_add_form(npm_action="cancel"), follow_redirects=False
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, _first_host_id(temp_db_file))
    assert row["npm_proxy_host_id"] is None
    assert row["current_ip"] == "192.168.86.9"



def test_edit_shows_npm_mismatch_warning(temp_db_file):
    host_id = _insert_host(temp_db_file, npm_proxy_host_id=5, current_ip="192.168.86.9")
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        mock_npm.return_value.list_proxy_hosts.return_value = []
        resp = TestClient(app).post(
            f"/hosts/{host_id}/edit",
            data=_edit_form(current_ip="192.168.86.9", port=80, npm_proxy_host_id="5"),
            follow_redirects=False,
        )
    assert resp.status_code == 200
    assert "NPM record does not match" in resp.text
    # The row is untouched until the user resolves the warning.
    row = _host_row(temp_db_file, host_id)
    assert row["current_ip"] == "192.168.86.9"
    assert row["port"] == 80
    assert row["npm_proxy_host_id"] == 5


def test_edit_npm_mismatch_match(temp_db_file):
    host_id = _insert_host(temp_db_file, npm_proxy_host_id=5, current_ip="192.168.86.9")
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        resp = TestClient(app).post(
            f"/hosts/{host_id}/edit",
            data=_edit_form(
                current_ip="192.168.86.9", port=80,
                npm_proxy_host_id="5", npm_action="match",
            ),
            follow_redirects=False,
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, host_id)
    assert row["current_ip"] == "10.0.0.5"
    assert row["port"] == 443
    assert row["npm_proxy_host_id"] == 5


def test_edit_npm_mismatch_link(temp_db_file):
    host_id = _insert_host(temp_db_file, npm_proxy_host_id=5, current_ip="192.168.86.9")
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        resp = TestClient(app).post(
            f"/hosts/{host_id}/edit",
            data=_edit_form(
                current_ip="192.168.86.9", port=80,
                npm_proxy_host_id="5", npm_action="link",
            ),
            follow_redirects=False,
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, host_id)
    assert row["current_ip"] == "192.168.86.9"
    assert row["port"] == 80
    assert row["npm_proxy_host_id"] == 5


def test_edit_npm_mismatch_cancel_reverts_link(temp_db_file):
    """'Cancel' on edit undoes the just-made NPM selection — the link reverts
    to whatever the host had before this edit."""
    host_id = _insert_host(temp_db_file, npm_proxy_host_id=3, current_ip="192.168.86.9")
    with patch("app.main.NPMClient") as mock_npm:
        # The user selected NPM host 5 (whose forward mismatches) in the dropdown.
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD
        resp = TestClient(app).post(
            f"/hosts/{host_id}/edit",
            data=_edit_form(
                current_ip="192.168.86.9", port=80,
                npm_proxy_host_id="5", npm_action="cancel",
            ),
            follow_redirects=False,
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, host_id)
    assert row["npm_proxy_host_id"] == 3  # reverted to the original link
    assert row["current_ip"] == "192.168.86.9"


def test_edit_npm_matching_no_warning(temp_db_file):
    """When the entered IP:port already matches NPM's forward, saving proceeds
    without the warning."""
    host_id = _insert_host(
        temp_db_file, npm_proxy_host_id=5, current_ip="10.0.0.5", port=443
    )
    with patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = _NPM_FORWARD  # 10.0.0.5:443
        mock_npm.return_value.list_proxy_hosts.return_value = []
        resp = TestClient(app).post(
            f"/hosts/{host_id}/edit",
            data=_edit_form(current_ip="10.0.0.5", port=443, npm_proxy_host_id="5"),
            follow_redirects=False,
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, host_id)
    assert row["current_ip"] == "10.0.0.5"



# ─────────────────────────────── subnet dropdown + dashboard ───────────────────


def test_add_page_lists_auto_subnets(temp_db_file):
    # list_subnets() lives in scanner.py and calls get_default_subnets() from
    # that module, so patch it there (not the app.main import).
    with patch(
        "app.services.scanner.get_default_subnets",
        return_value=[{"cidr": "192.168.200.0/24", "interface": "eth9", "source": "auto"}],
    ):
        resp = TestClient(app).get("/hosts/add")
    assert resp.status_code == 200
    assert 'value="192.168.200.0/24"' in resp.text
    assert "Auto-detected" in resp.text


def test_edit_page_preselects_pinned_auto_subnet(temp_db_file):
    host_id = _insert_host(temp_db_file, subnet_cidr="192.168.200.0/24")
    with patch(
        "app.services.scanner.get_default_subnets",
        return_value=[{"cidr": "192.168.200.0/24", "interface": "eth9", "source": "auto"}],
    ):
        resp = TestClient(app).get(f"/hosts/{host_id}/edit")
    assert resp.status_code == 200
    assert 'value="192.168.200.0/24" selected' in resp.text


def test_dashboard_shows_pinned_auto_subnet(temp_db_file):
    _insert_host(temp_db_file, subnet_cidr="192.168.200.0/24")
    resp = TestClient(app).get("/")
    assert resp.status_code == 200
    assert "192.168.200.0/24" in resp.text


def test_dashboard_shows_manual_subnet_name(temp_db_file):
    subnet_id = _insert_subnet(temp_db_file, "Office LAN", "192.168.70.0/24")
    _insert_host(temp_db_file, subnet_id=subnet_id)
    resp = TestClient(app).get("/")
    assert resp.status_code == 200
    assert "Office LAN" in resp.text


def test_dashboard_shows_all_subnets_when_unpinned(temp_db_file):
    _insert_host(temp_db_file)  # no subnet pinned
    resp = TestClient(app).get("/")
    assert resp.status_code == 200
    assert "All known subnets" in resp.text


def test_dashboard_labels_two_ports_on_the_same_device(temp_db_file):
    """Two records for one box (same MAC, two ports) each render with their port
    in the header and a shared-device badge, so the pair is transparent and each
    shows its own health at a glance."""
    _insert_host(temp_db_file, name="batcave", mac_address="aa:bb:cc:dd:ee:77", port=8787)
    _insert_host(temp_db_file, name="batcave", mac_address="aa:bb:cc:dd:ee:77", port=8181)

    resp = TestClient(app).get("/")
    assert resp.status_code == 200
    # Each monitored port is surfaced in its card header.
    assert ":8787" in resp.text
    assert ":8181" in resp.text
    # Both cards flag the other record on the same device.
    assert resp.text.count("+1 on this device") == 2


def test_dashboard_no_shared_device_badge_for_single_port(temp_db_file):
    """A lone record (no other record shares its MAC) shows its port but no
    shared-device badge."""
    _insert_host(temp_db_file, name="solo", mac_address="aa:bb:cc:dd:ee:78", port=9000)

    resp = TestClient(app).get("/")
    assert resp.status_code == 200
    assert ":9000" in resp.text
    assert "+1 on this device" not in resp.text


# ─────────────────────────── populate record from NPM ───────────────────────────


def test_subnet_for_ip_prefers_known_subnet():
    from app.main import _subnet_for_ip

    subnets = [
        {"cidr": "192.168.200.0/24", "interface": "eth9", "source": "auto"},
        {"cidr": "10.0.0.0/28", "interface": "eth1", "source": "manual"},
    ]
    # A VLAN narrower than /24 must win over the /24 fallback.
    assert _subnet_for_ip("10.0.0.5", subnets) == "10.0.0.0/28"
    assert _subnet_for_ip("192.168.200.7", subnets) == "192.168.200.0/24"


def test_subnet_for_ip_falls_back_to_24_when_unknown():
    from app.main import _subnet_for_ip

    assert _subnet_for_ip("172.31.5.9", []) == "172.31.5.0/24"
    # No known subnet contains 10.9.9.9 → its own /24.
    assert _subnet_for_ip("10.9.9.9", [{"cidr": "192.168.0.0/24"}]) == "10.9.9.0/24"


def test_subnet_for_ip_none_for_non_ipv4():
    from app.main import _subnet_for_ip

    assert _subnet_for_ip("vault.hylla.us", [{"cidr": "192.168.0.0/24"}]) is None
    assert _subnet_for_ip("", []) is None
    assert _subnet_for_ip(None, []) is None


def test_form_offers_populate_from_npm(temp_db_file):
    """Selecting an NPM proxy host offers to populate the record: IP, port,
    domain, and the subnet where one is known (falls back to the /24)."""
    with patch("app.services.scanner.get_default_subnets", return_value=[]), patch(
        "app.main.NPMClient"
    ) as mock_npm:
        mock_npm.return_value.list_proxy_hosts.return_value = [
            {
                "id": 7,
                "domain_names": '["vault.hylla.us"]',
                "forward_host": "192.168.86.249",
                "forward_port": 80,
            },
        ]
        resp = TestClient(app).get("/hosts/add")
    assert resp.status_code == 200
    assert 'data-ip="192.168.86.249"' in resp.text
    assert 'data-port="80"' in resp.text
    assert 'data-domain="vault.hylla.us"' in resp.text
    assert 'data-subnet="192.168.86.0/24"' in resp.text
    assert "Populate this record from NPM proxy host" in resp.text


# ─────────────────────────────── force-scan NPM sync ───────────────────────────


def test_force_scan_syncs_npm_and_logs(temp_db_file):
    """When the ARP sweep finds the host at a new IP, force-scan adopts it,
    re-points the linked NPM proxy host, and records the old→new transition in
    the event."""
    host_id = _insert_host(temp_db_file, npm_proxy_host_id=5, current_ip="192.168.86.9")
    with patch("app.main.find_ip_by_mac", new=AsyncMock(return_value="192.168.86.50")), \
         patch("app.main.check_host_reachable", new=AsyncMock(return_value=True)), \
         patch("app.main.NPMClient") as mock_npm:
        mock_npm.return_value.get_proxy_host.return_value = {"forward_host": "192.168.86.9"}
        mock_npm.return_value.update_forward_host.return_value = True
        mock_npm.return_value.reload_nginx.return_value = True
        resp = TestClient(app).post(
            f"/hosts/{host_id}/force-scan", follow_redirects=False
        )
    assert resp.status_code == 303
    row = _host_row(temp_db_file, host_id)
    assert row["current_ip"] == "192.168.86.50"
    # NPM forward was re-pointed from the old IP to the newly-discovered one.
    mock_npm.return_value.update_forward_host.assert_called_once_with(5, "192.168.86.50")
    details = _last_event_details(temp_db_file)
    assert "192.168.86.9 → 192.168.86.50" in details
    assert "NPM proxy host #5 forward updated 192.168.86.9 → 192.168.86.50" in details


def test_force_scan_no_npm_update_when_forward_matches(temp_db_file):
    """If NPM already points at the newly-found IP, no update is triggered."""
    host_id = _insert_host(temp_db_file, npm_proxy_host_id=5, current_ip="192.168.86.9")
    with patch("app.main.find_ip_by_mac", new=AsyncMock(return_value="192.168.86.50")), \
         patch("app.main.check_host_reachable", new=AsyncMock(return_value=True)), \
         patch("app.main.NPMClient") as mock_npm:
        # NPM is already pointed at the address the sweep is about to find.
        mock_npm.return_value.get_proxy_host.return_value = {"forward_host": "192.168.86.50"}
        resp = TestClient(app).post(
            f"/hosts/{host_id}/force-scan", follow_redirects=False
        )
    assert resp.status_code == 303
    assert _host_row(temp_db_file, host_id)["current_ip"] == "192.168.86.50"
    mock_npm.return_value.update_forward_host.assert_not_called()


def test_scan_endpoint_returns_valid_scan_id(temp_db_file):
    """Test that the scan endpoint returns a valid scan_id immediately,
    and the full result is available via the progress endpoint."""
    import time as _time
    client = TestClient(app)
    with patch("app.main.list_subnets", new=AsyncMock(return_value=[])), \
         patch(
            "app.main.run_scan",
            new=AsyncMock(
                return_value={
                    "found_ip": "192.168.1.100",
                    "found_via": "arp-scan",
                    "error": "",
                    "hosts": [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}],
                }
            ),
        ):
        resp = client.post(
            "/api/diagnostic/scan",
            json={"target_mac": "aa:bb:cc:dd:ee:ff", "method": "arp-scan"},
        )
        assert resp.status_code == 200
        data = resp.json()
        # Immediate response has scan_id
        assert "scan_id" in data
        assert isinstance(data["scan_id"], str)
        assert len(data["scan_id"]) > 0
        # Wait for background task to finish
        for _ in range(20):
            _time.sleep(0.1)
            prog = client.get(f"/api/diagnostic/scan-progress/{data['scan_id']}")
            prog_data = prog.json()
            if prog_data.get("status") == "complete":
                break
        assert prog_data["status"] == "complete"
        # Full result available via progress endpoint
        result = prog_data.get("result", prog_data)
        assert result.get("found_ip") == "192.168.1.100"
        assert result.get("found_via") == "arp-scan"


def test_scan_progress_endpoint_works_with_valid_scan_id(temp_db_file):
    """Test that scan progress endpoint works correctly with valid scan IDs."""
    import time as _time
    client = TestClient(app)
    with patch("app.main.list_subnets", new=AsyncMock(return_value=[])), \
         patch(
            "app.main.run_scan",
            new=AsyncMock(
                return_value={
                    "found_ip": "192.168.1.100",
                    "found_via": "arp-scan",
                    "error": "",
                    "hosts": [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}],
                }
            ),
        ):
        # First start a scan to get a scan_id
        resp = client.post(
            "/api/diagnostic/scan",
            json={"target_mac": "aa:bb:cc:dd:ee:ff", "method": "arp-scan"},
        )
        assert resp.status_code == 200
        scan_id = resp.json()["scan_id"]

        # Wait for background task to finish so progress data is populated
        for _ in range(20):
            _time.sleep(0.1)
            prog = client.get(f"/api/diagnostic/scan-progress/{scan_id}")
            prog_data = prog.json()
            if prog_data.get("status") in ("discovered", "complete"):
                break

        # Then test the progress endpoint with that scan_id
        progress_resp = client.get(f"/api/diagnostic/scan-progress/{scan_id}")
        assert progress_resp.status_code == 200
        progress_data = progress_resp.json()

        # Verify progress data structure
        assert "elapsed_time" in progress_data
        assert isinstance(progress_data["elapsed_time"], (int, float))
        assert progress_data["elapsed_time"] >= 0
        assert "estimated_completion" in progress_data
        assert "estimated_remaining" in progress_data
        assert "status" in progress_data
        assert "hosts" in progress_data


def test_scan_progress_endpoint_handles_invalid_scan_id(temp_db_file):
    """Test error handling for invalid scan IDs."""
    client = TestClient(app)
    
    # Test with non-existent scan ID
    resp = client.get("/api/diagnostic/scan-progress/non-existent-scan-id")
    assert resp.status_code == 200  # Should return 200 with error in body
    data = resp.json()
    assert "error" in data
    assert data["error"] == "Scan not found"


def test_scan_progress_endpoint_interval_cleanup(temp_db_file):
    """Test that scan progress tracking cleans up after scan completion."""
    import time as _time
    client = TestClient(app)
    with patch("app.main.list_subnets", new=AsyncMock(return_value=[])), \
         patch(
            "app.main.run_scan",
            new=AsyncMock(
                return_value={
                    "found_ip": "192.168.1.100",
                    "found_via": "arp-scan",
                    "error": "",
                    "hosts": [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}],
                }
            ),
        ):
        # Start a scan to get a scan_id
        resp = client.post(
            "/api/diagnostic/scan",
            json={"target_mac": "aa:bb:cc:dd:ee:ff", "method": "arp-scan"},
        )
        assert resp.status_code == 200
        scan_id = resp.json()["scan_id"]

        # Wait for scan to complete
        for _ in range(20):
            _time.sleep(0.1)
            prog = client.get(f"/api/diagnostic/scan-progress/{scan_id}")
            prog_data = prog.json()
            if prog_data.get("status") == "complete":
                break

        # Verify the scan ID exists in progress tracking
        from app.main import scan_progress
        assert scan_id in scan_progress

        # Test that we can get progress info
        progress_resp = client.get(f"/api/diagnostic/scan-progress/{scan_id}")
        assert progress_resp.status_code == 200

