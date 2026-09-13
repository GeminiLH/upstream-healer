"""Tests for app.services.scanner — MAC normalization and reachability."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.scanner import check_host_reachable, find_ip_by_mac, normalize_mac


class TestNormalizeMac:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("ab:cd:ef:01:23:45", "ab:cd:ef:01:23:45"),
            ("aB-CD-EF-01-23-45", "ab:cd:ef:01:23:45"),
            ("ab.cd.ef.01.23.45", "ab:cd:ef:01:23:45"),
            ("ABCDEF012345", "ab:cd:ef:01:23:45"),
            ("  ab:cd:ef:01:23:45  ", "ab:cd:ef:01:23:45"),
            ("ab:cd:ef:01:23", "ab:cd:ef:01:23"),  # incomplete: left as-is (lowercased)
            ("", ""),
            ("not-a-mac", "not:a:mac"),  # non-MAC string: separators are still normalized
        ],
    )
    def test_normalization(self, raw, expected):
        assert normalize_mac(raw) == expected


class TestCheckHostReachable:
    async def test_closed_port_is_unreachable(self):
        # port 1 on loopback is closed in any sane environment
        assert await check_host_reachable("127.0.0.1", port=1, timeout=1.0) is False

    async def test_blackhole_ip_is_unreachable(self):
        # 192.0.2.0/24 is IANA's TEST-NET-1 — must never respond
        assert await check_host_reachable("192.0.2.1", port=80, timeout=1.0) is False


class TestFindIpByMac:
    async def test_arp_scan_result_wins(self):
        with patch("app.services.scanner._scan_with_arp_scan", new=AsyncMock(return_value="10.0.0.5")), \
                patch("app.services.scanner._scan_with_scapy", new=AsyncMock()) as mock_scapy:
            assert await find_ip_by_mac("AA:BB:CC:DD:EE:FF") == "10.0.0.5"
        mock_scapy.assert_not_called()

    async def test_falls_back_to_scapy(self):
        with patch("app.services.scanner._scan_with_arp_scan", new=AsyncMock(return_value=None)), \
                patch("app.services.scanner._scan_with_scapy", new=AsyncMock(return_value="10.0.0.9")):
            assert await find_ip_by_mac("AA:BB:CC:DD:EE:FF") == "10.0.0.9"

    async def test_not_found_returns_none(self):
        with patch("app.services.scanner._scan_with_arp_scan", new=AsyncMock(return_value=None)), \
                patch("app.services.scanner._scan_with_scapy", new=AsyncMock(return_value=None)):
            assert await find_ip_by_mac("AA:BB:CC:DD:EE:FF") is None