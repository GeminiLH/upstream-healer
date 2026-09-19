"""Tests for app.services.mdns — mDNS/avahi hostname discovery helpers.

Only the pure, deterministic helpers are exercised directly; the networked
``discover_hostnames`` / ``_discover_sync`` paths are covered by mocking the
worker or forcing the ``zeroconf`` import to fail, so the suite never touches
the real network (matching the conftest philosophy).
"""
from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from app.services.mdns import (
    _discover_sync,
    discover_hostnames,
    instance_display_name,
    instance_mac,
)


class TestInstanceDisplayName:
    @pytest.mark.parametrize(
        "fqdn,expected",
        [
            ("WDMyCloud._http._tcp.local.", "WDMyCloud"),
            ("0469F88FEE99@Living Room Apple TV._raop._tcp.local.", "Living Room Apple TV"),
            ("Living Room Apple TV._airplay._tcp.local.", "Living Room Apple TV"),
            ("flash [dc:a6:32:02:59:63]._workstation._tcp.local.", "flash [dc:a6:32:02:59:63]"),
            ("no-dot-name", "no-dot-name"),
            ("", ""),
        ],
    )
    def test_display_name(self, fqdn, expected):
        assert instance_display_name(fqdn) == expected


class TestInstanceMac:
    @pytest.mark.parametrize(
        "fqdn,expected",
        [
            ("0469F88FEE99@Living Room Apple TV._raop._tcp.local.", "04:69:f8:8f:ee:99"),
            ("flash [dc:a6:32:02:59:63]._workstation._tcp.local.", "dc:a6:32:02:59:63"),
            ("DA7FD95C99D1@Laura’s MacBook Air._raop._tcp.local.", "da:7f:d9:5c:99:d1"),
            ("WDMyCloud._http._tcp.local.", None),  # no MAC embedded
            ("", None),
        ],
    )
    def test_mac(self, fqdn, expected):
        assert instance_mac(fqdn) == expected


class TestDiscoverHostnames:
    async def test_returns_sync_result(self):
        with patch(
            "app.services.mdns._discover_sync",
            return_value=({"10.0.0.1": "x"}, {"aa:bb:cc:dd:ee:ff": "y"}),
        ):
            assert await discover_hostnames(timeout=0.01) == (
                {"10.0.0.1": "x"},
                {"aa:bb:cc:dd:ee:ff": "y"},
            )

    async def test_swallows_worker_errors(self):
        with patch("app.services.mdns._discover_sync", side_effect=RuntimeError("boom")):
            assert await discover_hostnames(timeout=0.01) == ({}, {})

    def test_missing_zeroconf_returns_empty(self, monkeypatch):
        # Forcing sys.modules['zeroconf'] = None makes `import zeroconf` raise
        # ImportError, exercising the graceful-degradation branch deterministically
        # regardless of whether zeroconf happens to be installed on the box.
        monkeypatch.setitem(sys.modules, "zeroconf", None)
        assert _discover_sync(0.01) == ({}, {})
