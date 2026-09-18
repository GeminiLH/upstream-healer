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