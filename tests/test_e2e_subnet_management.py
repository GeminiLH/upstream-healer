"""
End-to-end tests for subnet management functionality.
This covers the workflows for adding, editing, and managing network subnets.
"""
from __future__ import annotations

from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from app.main import app


def test_subnet_add_form_renders(temp_db_file):
    """E2E Test: Subnet add form renders correctly."""
    client = TestClient(app)
    
    # Test that the subnet settings page renders (which contains the add form)
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Add Subnet" in resp.text


def test_subnet_add_and_view(temp_db_file):
    """E2E Test: Add a new subnet and verify it appears on settings page."""
    client = TestClient(app)
    
    # Add a new subnet via POST to the settings endpoint
    resp = client.post("/settings/subnets", data={
        "name": "Test Subnet",
        "cidr": "192.168.2.0/24",
        "interface": "eth0",
        "enabled": 1
    })
    
    # Should redirect after successful POST
    assert resp.status_code == 303
    
    # Verify the subnet appears on the settings page
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Test Subnet" in resp.text


def test_subnet_toggle_functionality(temp_db_file):
    """E2E Test: Toggle a subnet enabled/disabled."""
    client = TestClient(app)
    
    # Add a subnet first to test with
    resp = client.post("/settings/subnets", data={
        "name": "Toggle Test Subnet",
        "cidr": "192.168.3.0/24",
        "interface": "eth0",
        "enabled": 1
    })
    assert resp.status_code == 303
    
    # Toggle the subnet (this would be via POST to /settings/subnets/{id}/toggle)
    # For now, just verify that we can hit the endpoint
    resp = client.post("/settings/subnets/1/toggle")
    assert resp.status_code in [200, 303]  # Either redirect or direct response


def test_subnet_delete_functionality(temp_db_file):
    """E2E Test: Delete a subnet."""
    client = TestClient(app)
    
    # Add a subnet first to test with
    resp = client.post("/settings/subnets", data={
        "name": "Delete Test Subnet",
        "cidr": "192.168.4.0/24",
        "interface": "eth0",
        "enabled": 1
    })
    assert resp.status_code == 303
    
    # Delete the subnet (this would be via POST to /settings/subnets/{id}/delete)
    # For now, just verify that we can hit the endpoint
    resp = client.post("/settings/subnets/1/delete")
    assert resp.status_code in [200, 303]  # Either redirect or direct response


def test_subnet_suppress_functionality(temp_db_file):
    """E2E Test: Suppress a subnet."""
    client = TestClient(app)
    
    # Try to suppress a subnet (this would be via POST to /settings/subnets/suppress)
    resp = client.post("/settings/subnets/suppress", data={
        "cidr": "192.168.5.0/24"
    })
    assert resp.status_code in [200, 303]  # Either redirect or direct response


def test_subnet_rescan_functionality(temp_db_file):
    """E2E Test: Rescan a subnet."""
    client = TestClient(app)
    
    # Try to rescan a subnet (this would be via POST to /settings/subnets/rescan)
    resp = client.post("/settings/subnets/rescan", data={
        "subnet_id": 1
    })
    assert resp.status_code in [200, 303]  # Either redirect or direct response


def test_subnet_rescan_all_functionality(temp_db_file):
    """E2E Test: Rescan all subnets."""
    client = TestClient(app)
    
    # Try to rescan all subnets (this would be via POST to /settings/subnets/rescan-all)
    resp = client.post("/settings/subnets/rescan-all")
    assert resp.status_code in [200, 303]  # Either redirect or direct response


def test_settings_save_functionality(temp_db_file):
    """E2E Test: Save application settings."""
    client = TestClient(app)
    
    # Try to save settings (this would be via POST to /settings)
    resp = client.post("/settings", data={
        "grace_minutes": 15,
        "check_interval_seconds": 900,
        "event_retention_days": 14
    })
    assert resp.status_code in [200, 303]  # Either redirect or direct response


def test_diagnostic_scan_functionality(temp_db_file):
    """E2E Test: Run diagnostic scan."""
    client = TestClient(app)
    
    # Test that we can access the diagnostic page
    resp = client.get("/diagnostic")
    assert resp.status_code == 200
    
    # Try to run a diagnostic scan (this would be via POST to /api/diagnostic/scan)
    with patch("app.main.run_scan", new=AsyncMock(return_value=[])):
        resp = client.post("/api/diagnostic/scan", json={
            "target_mac": "AA:BB:CC:DD:EE:FF",
            "method": "arp"
        })
        assert resp.status_code in [200, 202]  # Scan initiated or accepted