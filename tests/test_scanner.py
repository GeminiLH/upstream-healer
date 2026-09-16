"""Tests for app.services.scanner — MAC normalization and reachability."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.scanner import (
    check_host_reachable,
    find_ip_by_mac,
    normalize_mac,
    run_arp_scan,
    run_scan,
    run_scapy_scan,
)


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


class TestRunArpScan:
    def test_returns_raw_output(self):
        proc = _FakeProc("192.168.86.5  aa:bb:cc:dd:ee:ff  VMWARE, INC.\n")
        with patch("app.services.scanner.subprocess.run", return_value=proc):
            found_ip, output, error = run_arp_scan()
        assert found_ip is None  # a full list has no single target
        assert "192.168.86.5" in output
        assert error is None

    def test_binary_missing_reports_error(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            found_ip, output, error = run_arp_scan()
        assert found_ip is None
        assert output == ""
        assert error is not None

    def test_empty_output_gets_placeholder(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("   \n")):
            _, output, error = run_arp_scan()
        assert error is None
        assert "no output" in output


class TestRunScapyScan:
    def test_missing_scapy_reports_error(self):
        import builtins

        real_import = builtins.__import__

        def _boom(name, *args, **kwargs):
            if name == "scapy.all":
                raise ImportError("no scapy")
            return real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_boom):
            found_ip, output, error = run_scapy_scan("aa:bb:cc:dd:ee:ff")
        assert found_ip is None
        assert error is not None
        assert "scapy" in error

    def test_found_target_and_full_table(self):
        import scapy.all as scapy_all

        # A real (untransmitted) packet — `conf.verb = 0` inside the function is
        # a scapy descriptor that needs a real packet instance to resolve, so we
        # build the request the same way the production code does.
        request = scapy_all.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy_all.ARP(pdst="192.168.86.0/24")
        pkt = _FakeScapyPkt("192.168.86.10", "aa:bb:cc:dd:ee:ff")
        other = _FakeScapyPkt("192.168.86.20", "11:22:33:44:55:66")
        with patch.object(scapy_all, "srp", return_value=([("x", pkt), ("x", other)], [])), \
                patch.object(scapy_all, "Ether", return_value=request), \
                patch.object(scapy_all, "ARP", return_value=request), \
                patch("app.services.scanner._get_primary_ip", return_value="192.168.86.1"):
            found_ip, output, error = run_scapy_scan("aa:bb:cc:dd:ee:ff")
        assert found_ip == "192.168.86.10"
        assert error is None
        assert "192.168.86.10  aa:bb:cc:dd:ee:ff" in output
        assert "192.168.86.20  11:22:33:44:55:66" in output

    def test_no_responders(self):
        import scapy.all as scapy_all

        request = scapy_all.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy_all.ARP(pdst="192.168.86.0/24")
        with patch.object(scapy_all, "srp", return_value=([], [])), \
                patch.object(scapy_all, "Ether", return_value=request), \
                patch.object(scapy_all, "ARP", return_value=request), \
                patch("app.services.scanner._get_primary_ip", return_value="192.168.86.1"):
            found_ip, output, error = run_scapy_scan("aa:bb:cc:dd:ee:ff")
        assert found_ip is None
        assert error is None
        assert "no ARP responses" in output


class TestRunScan:
    async def test_arp_scan_dispatcher_matches_target(self):
        table = "192.168.86.5  aa:bb:cc:dd:ee:ff  VMWARE\n192.168.86.9  11:22:33:44:55:66\n"
        with patch("app.services.scanner.run_arp_scan", return_value=(None, table, None)):
            result = await run_scan("aa:bb:cc:dd:ee:ff", "arp-scan")
        assert result["found_ip"] == "192.168.86.5"
        assert result["found_via"] == "arp-scan"
        assert result["error"] is None
        assert result["output"] == table

    async def test_scapy_dispatcher_reports_found_ip(self):
        with patch(
            "app.services.scanner.run_scapy_scan",
            return_value=("192.168.86.10", "192.168.86.10  aa:bb:cc:dd:ee:ff", None),
        ):
            result = await run_scan("aa:bb:cc:dd:ee:ff", "scapy")
        assert result["found_ip"] == "192.168.86.10"
        assert result["found_via"] == "scapy"

    async def test_scapy_not_found(self):
        with patch("app.services.scanner.run_scapy_scan", return_value=(None, "(no ARP responses received)", None)):
            result = await run_scan("aa:bb:cc:dd:ee:ff", "scapy")
        assert result["found_ip"] is None
        assert result["found_via"] is None


class _FakeProc:
    def __init__(self, stdout, stderr=""):
        self.stdout = stdout
        self.stderr = stderr


class _FakeScapyPkt:
    def __init__(self, psrc, hwsrc):
        self.psrc = psrc
        self.hwsrc = hwsrc