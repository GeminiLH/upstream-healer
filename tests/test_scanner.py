"""Tests for app.services.scanner — MAC normalization and reachability."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.scanner import (
    check_host_reachable,
    find_ip_by_mac,
    get_default_subnets,
    get_local_ip_for_network,
    ip_in_subnets,
    list_subnets,
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

    def test_per_sweep_failure_is_isolated(self):
        """A scapy failure while sweeping ONE subnet must not abort the whole
        multi-subnet run — the remaining networks are still swept and the target
        is still found.  Regression: the historical ``conf.iface = "enp6s0"``
        mutation made scapy do ``int("enp6s0")`` and raise, aborting every sweep."""
        import scapy.all as scapy_all

        request = scapy_all.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy_all.ARP(pdst="192.168.86.0/24")
        pkt = _FakeScapyPkt("192.168.86.10", "aa:bb:cc:dd:ee:ff")
        swept: list = []

        def flaky_srp(packet, **kwargs):
            # The request is built with the first subnet's pdst and re-stamped
            # per-network only at send time (via scapy's conf), so the reliable
            # per-sweep discriminator is the egress ``iface`` we pass.
            swept.append(kwargs.get("iface") or "default")
            if kwargs.get("iface") == "enp6s0":
                raise ValueError('"enp6s0" is not a valid numeric value')
            return [(None, pkt)], []

        # Per-subnet local source: 10.0.0.0/24 owns 10.0.0.5 (on enp6s0); the
        # 192.168.86.0/24 has no local iface on this fake box, so it sweeps via
        # the default interface.  Each maps to a DIFFERENT egress iface.
        local_ip = {
            "192.168.86.0/24": None,  # no local iface -> default interface
            "10.0.0.0/24": "10.0.0.5",  # on enp6s0
        }
        with patch.object(scapy_all, "srp", side_effect=flaky_srp), \
                patch.object(scapy_all, "Ether", return_value=request), \
                patch.object(scapy_all, "ARP", return_value=request), \
                patch.object(scapy_all, "conf", create=True), \
                patch("app.services.scanner.get_local_ip_for_network", side_effect=lambda cidr: local_ip.get(cidr)):
            scapy_all.conf.get_if_addresses = lambda: {"enp6s0": ["10.0.0.5"]}
            found_ip, output, error = run_scapy_scan(
                "aa:bb:cc:dd:ee:ff", subnets=["192.168.86.0/24", "10.0.0.0/24"]
            )
        assert error is None
        assert "enp6s0" in swept and "default" in swept
        assert found_ip == "192.168.86.10"
        # The failed sweep contributed no rows; the good one did.
        assert "192.168.86.10" in output
        assert "10.0.0.5" not in output


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


class TestIpInSubnets:
    def test_match_in_range(self):
        assert ip_in_subnets("192.168.10.5", ["192.168.10.0/24"])

    def test_no_match(self):
        assert not ip_in_subnets("10.0.0.5", ["192.168.10.0/24"])

    def test_invalid_input_is_falsy(self):
        assert not ip_in_subnets("not-an-ip", ["192.168.10.0/24"])
        assert not ip_in_subnets("", ["192.168.10.0/24"])

    def test_invalid_cidr_is_ignored(self):
        assert not ip_in_subnets("192.168.10.5", ["bogus", "10.0.0.0/8"])

    def test_matches_any_subnet_in_list(self):
        assert ip_in_subnets("10.1.2.3", ["192.168.10.0/24", "10.1.0.0/16"])


class TestGetLocalIpForNetwork:
    def test_returns_src_from_ip_route(self):
        proc = _FakeProc("192.168.10.0/24 via 192.168.10.1 dev eth0 src 192.168.10.5 uid 0\n")
        with patch("app.services.scanner.subprocess.run", return_value=proc):
            assert get_local_ip_for_network("192.168.10.0/24") == "192.168.10.5"

    def test_returns_none_when_no_src(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("")):
            assert get_local_ip_for_network("192.168.10.0/24") is None

    def test_empty_cidr_returns_none_without_subprocess(self):
        with patch("app.services.scanner.subprocess.run") as mock_run:
            assert get_local_ip_for_network("") is None
        mock_run.assert_not_called()

    def test_binary_missing_returns_none(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            assert get_local_ip_for_network("10.0.0.0/8") is None


class TestGetDefaultSubnets:
    def test_parses_ip_addr_output(self):
        out = (
            "1: lo    inet 127.0.0.1/8 scope host lo\n"
            "2: eth0    inet 192.168.10.5/24 brd 192.168.10.255 scope global eth0\n"
            "3: eth1    inet 10.0.0.15/24 brd 10.0.0.255 scope global eth1\n"
            "4: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\n"
        )
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            got = get_default_subnets()
        assert [g["cidr"] for g in got] == ["192.168.10.0/24", "10.0.0.0/24"]
        assert all(g["source"] == "auto" for g in got)

    def test_empty_when_ip_fails(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            assert get_default_subnets() == []


class TestListSubnets:
    class _FakeDb:
        def __init__(self, rows):
            self._rows = rows

        def execute(self, sql, params=None):
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def fetchall(self):
            return self._rows

    async def test_merges_manual_and_auto(self):
        rows = [{"id": 1, "name": "lan", "cidr": "192.168.10.0/24", "interface": "eth0"}]
        auto = [{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}]
        with patch("app.services.scanner.get_default_subnets", return_value=auto):
            got = await list_subnets(self._FakeDb(rows))
        assert [g["cidr"] for g in got] == ["192.168.10.0/24", "10.0.0.0/24"]
        assert got[0]["source"] == "manual"
        assert got[1]["source"] == "auto"

    async def test_none_db_returns_only_auto(self):
        auto = [
            {"cidr": "192.168.10.0/24", "interface": "eth0", "source": "auto"},
            {"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"},
        ]
        with patch("app.services.scanner.get_default_subnets", return_value=auto):
            got = await list_subnets(None)
        assert [g["cidr"] for g in got] == ["192.168.10.0/24", "10.0.0.0/24"]

    async def test_dedupes_manual_and_auto_on_same_cidr(self):
        rows = [{"id": 1, "name": "lan", "cidr": "192.168.10.0/24", "interface": "eth0"}]
        auto = [{"cidr": "192.168.10.0/24", "interface": "eth0", "source": "auto"}]
        with patch("app.services.scanner.get_default_subnets", return_value=auto):
            got = await list_subnets(self._FakeDb(rows))
        assert len(got) == 1
        assert got[0]["source"] == "manual"


class TestRunArpScanWithSubnets:
    def test_no_subnets_means_historic_all_interfaces(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("x")) as mock_run:
            run_arp_scan()
        assert "-i" not in mock_run.call_args[0][0]

    def test_known_subnet_adds_interface_flag(self):
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ),              patch("app.services.scanner.subprocess.run", return_value=_FakeProc("x")) as mock_run:
            run_arp_scan(subnets=["10.0.0.0/24"])
        args = mock_run.call_args[0][0]
        assert "-i" in args and "eth1" in args

    def test_unknown_subnet_is_skipped_with_note(self):
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ),              patch("app.services.scanner.subprocess.run", return_value=_FakeProc("10.0.0.5  aa:bb  X\n")):
            _, output, error = run_arp_scan(subnets=["172.16.5.0/24", "10.0.0.0/24"])
        assert error is None
        assert "(skipped 172.16.5.0/24" in output
        assert "10.0.0.5" in output

    def test_unparseable_subnet_is_skipped_with_note(self):
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ),              patch("app.services.scanner.subprocess.run", return_value=_FakeProc("10.0.0.5  aa:bb  X\n")):
            _, output, error = run_arp_scan(subnets=["not-a-cidr"])
        assert error is None
        assert "(skipped unparseable subnet" in output

    def test_host_only_subnet_is_noted_not_really_skipped(self):
        """A /32 (a single host, not a network) is not ARP-sweepable.  We should
        emit a *specific* note rather than the misleading "no local interface",
        which implies the interface is missing when it is usually present."""
        with patch("app.services.scanner.get_default_subnets", return_value=[]), \
                patch("app.services.scanner.subprocess.run", return_value=_FakeProc("10.0.0.5  aa:bb  X\n")):
            _, output, error = run_arp_scan(subnets=["192.168.70.0/32"])
        assert error is None
        assert "single host" in output
        assert "no local interface" not in output


class TestMatchMacInOutputSubnetScope:
    def test_scopes_to_subnets(self):
        from app.services.scanner import _match_mac_in_output

        output = (
            "192.168.10.5  aa:bb:cc:dd:ee:ff  A\n"
            "10.0.0.5      aa:bb:cc:dd:ee:ff  B\n"
        )
        assert _match_mac_in_output("aa:bb:cc:dd:ee:ff", output) == "192.168.10.5"
        assert _match_mac_in_output("aa:bb:cc:dd:ee:ff", output, subnets=["10.0.0.0/8"]) == "10.0.0.5"
        assert _match_mac_in_output("aa:bb:cc:dd:ee:ff", output, subnets=["172.16.0.0/12"]) is None


class TestFindIpByMacSubnets:
    async def test_forwards_subnets_to_helpers(self):
        with patch("app.services.scanner._scan_with_arp_scan", new=AsyncMock(return_value=None)) as arp,              patch("app.services.scanner._scan_with_scapy", new=AsyncMock(return_value=None)) as scapy:
            await find_ip_by_mac("aa:bb:cc:dd:ee:ff", subnets=["10.0.0.0/24"])
        arp.assert_awaited_once_with("aa:bb:cc:dd:ee:ff", subnets=["10.0.0.0/24"])
        assert scapy.call_args.kwargs.get("subnets") == ["10.0.0.0/24"]

    async def test_none_subnets_is_default(self):
        with patch("app.services.scanner._scan_with_arp_scan", new=AsyncMock(return_value="10.0.0.5")) as arp,              patch("app.services.scanner._scan_with_scapy", new=AsyncMock()) as scapy:
            assert await find_ip_by_mac("aa:bb:cc:dd:ee:ff") == "10.0.0.5"
        assert arp.call_args.kwargs.get("subnets") is None
        scapy.assert_not_called()
