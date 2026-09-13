"""Smoke tests for the FastAPI app (lifespan is NOT triggered, no network)."""
from __future__ import annotations

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


def test_health_endpoint():
    # Used without a context manager so the lifespan (init_db, monitor.start)
    # never runs; /api/health does not touch the database.
    client = TestClient(app)
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "upstream-healer"}