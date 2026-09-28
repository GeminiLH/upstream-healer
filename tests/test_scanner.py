"""Tests for app.services.scanner — MAC normalization and reachability."""
from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.scanner import (
    _l3_alive_nmap,
    _l3_alive_ping,
    _l3_alive_scapy,
    _l3_probe_egress,
    _parse_scan_output,
    _usable_hosts,
    apply_hostnames,
    build_port_spec,
    parse_nmap_services_by_host,
    parse_nmap_services_json,
    parse_nmap_services_xml,
    check_host_reachable,
    classify_subnet,
    find_ip_by_mac,
    get_default_subnets,
    get_interface_flags,
    get_local_interfaces,
    get_local_ip_for_network,
    ip_in_subnets,
    is_tunnel_interface,
    list_subnets,
    load_known_hostnames,
    load_known_hostnames_by_ip,
    load_mdns_names,
    load_suppressed_subnets,
    normalize_mac,
    probe_services,
    remember_mdns_names,
    resolve_hostname,
    resolve_hostnames,
    run_arp_scan,
    run_l3_probe,
    run_nmap_scan,
    run_port_scan,
    run_port_scan_incremental,
    run_scan,
    run_scapy_scan,
    run_service_scan,
    save_suppressed_subnets,
    subnet_is_l3_only,
    sweep_responder_hosts,
    validate_host_record,
)


class _FakeProc:
    """Stand-in for a ``subprocess.run`` result: ``stdout`` / ``stderr`` only.

    Defined up front because the scan tests below patch ``subprocess.run`` and
    need it; sweep command assertions read ``mock_run.call_args_list``.
    """

    def __init__(self, stdout, stderr="", code=0):
        self.stdout = stdout
        self.stderr = stderr
        # Real ``subprocess.run`` results always expose ``returncode``; helpers such
        # as ``get_interface_flags`` read it unguarded, so the fake must too.
        self.returncode = code


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
    def test_none_sweeps_locally_attached_networks(self):
        """subnets=None actively sweeps each auto-discovered /24 (the historic
        passive `-l` table dump missed every host on a quiet box)."""
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ), patch(
            "app.services.scanner.subprocess.run", return_value=_FakeProc("10.0.0.5  aa:bb  X\n")
        ) as mock_run:
            found_ip, output, error = run_arp_scan()
        assert found_ip is None  # a full list has no single target
        assert error is None
        assert "10.0.0.5" in output
        assert mock_run.call_args[0][0] == ["arp-scan", "-q", "--retry=3", "--interface=eth1", "10.0.0.0/24"]

    def test_none_falls_back_to_passive_list_when_no_local_networks(self):
        # No /24s, no primary IP (e.g. Windows dev box): historic `arp-scan -l`.
        with patch("app.services.scanner.get_default_subnets", return_value=[]), \
             patch("app.services.scanner._get_primary_ip", return_value=None), \
             patch("app.services.scanner.subprocess.run", return_value=_FakeProc("x")) as mock_run:
            run_arp_scan()
        assert "-l" in mock_run.call_args[0][0]

    def test_binary_missing_reports_error(self):
        with patch("app.services.scanner.get_default_subnets", return_value=[]), \
             patch("app.services.scanner._get_primary_ip", return_value=None), \
             patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            found_ip, output, error = run_arp_scan()
        assert found_ip is None
        assert output == ""
        assert error is not None

    def test_empty_output_gets_placeholder(self):
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ), patch("app.services.scanner.subprocess.run", return_value=_FakeProc("   \n")):
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
            "192.168.86.0/24": (None, None),  # no local iface -> default interface
            "10.0.0.0/24": ("10.0.0.5", "enp6s0"),  # on enp6s0
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
    def test_returns_src_and_dev_from_ip_route(self):
        proc = _FakeProc("192.168.10.0/24 via 192.168.10.1 dev eth0 src 192.168.10.5 uid 0\n")
        with patch("app.services.scanner.subprocess.run", return_value=proc):
            assert get_local_ip_for_network("192.168.10.0/24") == ("192.168.10.5", "eth0")

    def test_returns_none_when_no_src(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("")):
            assert get_local_ip_for_network("192.168.10.0/24") == (None, None)

    def test_empty_cidr_returns_none_without_subprocess(self):
        with patch("app.services.scanner.subprocess.run") as mock_run:
            assert get_local_ip_for_network("") == (None, None)
        mock_run.assert_not_called()

    def test_binary_missing_returns_none(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            assert get_local_ip_for_network("10.0.0.0/8") == (None, None)


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


class TestGetLocalInterfaces:
    def test_lists_every_ipv4_interface_deduped(self):
        # Unlike get_default_subnets (only /24), this should surface a /28 VLAN NIC
        # too — it is a valid egress suggestion.  Loops out 127.x and ``lo``.
        lines = [
            "1: lo    inet 127.0.0.1/8 scope host lo",
            "2: eth0    inet 192.168.10.5/24 brd 192.168.10.255 scope global eth0",
            "3: eth0    inet 192.168.11.5/24 scope global eth0",
            "4: vlan20  inet 10.20.0.3/28 brd 10.20.0.15 scope global vlan20",
            "5: ens2    inet 169.254.1.9/16 scope link ens2",
        ]
        out = chr(10).join(lines)

        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            got = get_local_interfaces()
        names = [i["name"] for i in got]
        assert names == ["eth0", "vlan20", "ens2"]  # eth0 deduped, lo skipped
        by_name = {i["name"]: i for i in got}
        assert by_name["eth0"] == {"name": "eth0", "address": "192.168.10.5", "cidr": "192.168.10.5/24"}
        assert by_name["vlan20"]["cidr"] == "10.20.0.3/28"  # non-/24 still listed

    def test_empty_when_ip_unavailable(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            assert get_local_interfaces() == []


class _FakeCursor:
    """Test double: awaitable AND usable as an async context, like aiosqlite's cursor."""

    def __init__(self, rows):
        self._rows = rows

    def __await__(self):
        async def _coro():
            return self

        return _coro().__await__()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None

    async def fetchall(self):
        return self._rows


class _SuppressedDb:
    """Test double of an aiosqlite connection for the suppressed-subnet helpers."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.last_sql = None
        self.last_params = None
        self.committed = False

    def execute(self, sql, params=None):
        self.last_sql = sql
        self.last_params = params
        return _FakeCursor(self.rows)

    async def commit(self):
        self.committed = True


class TestSuppressedSubnets:
    async def test_load_empty_when_key_absent(self):
        assert await load_suppressed_subnets(_SuppressedDb()) == []

    async def test_save_then_load_roundtrip(self):
        import json

        db = _SuppressedDb()
        await save_suppressed_subnets(db, ["10.0.0.0/24", "10.1.0.0/24"])
        assert json.loads(db.last_params[0]) == ["10.0.0.0/24", "10.1.0.0/24"]
        assert db.committed
        db.rows = [{"value": db.last_params[0]}]
        assert await load_suppressed_subnets(db) == ["10.0.0.0/24", "10.1.0.0/24"]

    async def test_load_tolerates_bad_json(self):
        assert await load_suppressed_subnets(_SuppressedDb([{"value": "not-json"}])) == []


class TestListSubnets:
    class _FakeDb:
        def __init__(self, rows, suppressed=None):
            self._rows = rows
            self._suppressed = suppressed or []

        def execute(self, sql, params=None):
            self._sql = sql
            return self

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def fetchall(self):
            if "suppressed_subnets" in self._sql:
                import json as _json

                return [{"value": _json.dumps(self._suppressed)}]
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

    async def test_suppressed_auto_subnet_is_excluded(self):
        """An auto subnet the user deleted on the settings page must drop out
        of the effective scan list (and of every scan, since they all go
        through list_subnets); manual rows are unaffected."""
        rows = [{"id": 1, "name": "manual", "cidr": "192.168.70.0/24", "interface": None}]
        auto = [
            {"cidr": "192.168.86.0/24", "interface": "enp6s0", "source": "auto"},
            {"cidr": "192.168.99.0/24", "interface": "enp6s1", "source": "auto"},
        ]
        db = self._FakeDb(rows, suppressed=["192.168.99.0/24"])
        with patch("app.services.scanner.get_default_subnets", return_value=auto):
            got = await list_subnets(db)
            assert [g["cidr"] for g in got] == ["192.168.70.0/24", "192.168.86.0/24"]
            got_all = await list_subnets(db, include_suppressed=True)
            assert [g["cidr"] for g in got_all] == ["192.168.70.0/24", "192.168.86.0/24", "192.168.99.0/24"]

    async def test_manual_row_wins_over_suppressed_auto_same_cidr(self):
        rows = [{"id": 1, "name": "lan", "cidr": "10.0.0.0/24", "interface": "eth0"}]
        auto = [{"cidr": "10.0.0.0/24", "interface": "eth0", "source": "auto"}]
        db = self._FakeDb(rows, suppressed=["10.0.0.0/24"])
        with patch("app.services.scanner.get_default_subnets", return_value=auto):
            got = await list_subnets(db)
        assert [g["cidr"] for g in got] == ["10.0.0.0/24"]
        assert got[0]["source"] == "manual"


class TestRunArpScanWithSubnets:
    def test_known_subnet_sweeps_with_interface_and_target(self):
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ),              patch("app.services.scanner.subprocess.run", return_value=_FakeProc("x")) as mock_run:
            run_arp_scan(subnets=["10.0.0.0/24"])
        assert mock_run.call_args[0][0] == ["arp-scan", "-q", "--retry=3", "--interface=eth1", "10.0.0.0/24"]

    def test_failed_sweep_records_error_not_host_output(self):
        """A non-zero arp-scan exit (bad NIC / arg) is recorded as an error and its
        error banner must never leak into the host output."""
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ), patch(
            "app.services.scanner.classify_subnet",
            return_value={"kind": "broadcast"},
        ), patch(
            "app.services.scanner.subprocess.run",
            return_value=_FakeProc("", stderr='ERROR: "eth1" is not a valid numeric value', code=1),
        ):
            _, output, error = run_arp_scan(subnets=["10.0.0.0/24"])
        assert error is not None
        assert "10.0.0.0/24" in error
        assert "not a valid numeric value" not in output

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
        assert error is not None
        assert "No scannable subnets" in error
        assert "(skipped unparseable subnet" in output

    def test_only_nonlocal_subnet_errors_without_sweeping(self):
        """Selecting a subnet this box is not attached to must NOT silently
        fall back to sweeping the default interface — that is how hosts of an
        unselected network used to leak into the results."""
        with patch("app.services.scanner.get_default_subnets", return_value=[]), \
                patch("app.services.scanner.get_local_ip_for_network", return_value=(None, None)), \
                patch("app.services.scanner.subprocess.run", return_value=_FakeProc("")) as mock_run:
            _, output, error = run_arp_scan(subnets=["192.168.70.0/24"])
        assert error is not None
        assert "No scannable subnets" in error
        assert "no local interface" in output
        mock_run.assert_not_called()  # no arp-scan may run against an unselected net

    def test_output_is_filtered_to_requested_networks(self):
        """A responder on another local network must not appear when only a
        specific subnet was requested."""
        out = (
            "Starting arp-scan 1.10.0 with 256 hosts\n"
            "192.168.86.5  aa:bb:cc:dd:ee:ff  Vendor\n"
            "10.0.0.5  aa:bb:cc:dd:ee:ff  Vendor\n"
            "14 packets received by filter, 0 packets dropped by kernel\n"
        )
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ),              patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            _, output, error = run_arp_scan(subnets=["10.0.0.0/24"])
        assert error is None
        assert "10.0.0.5" in output
        assert "192.168.86.5" not in output  # unselected network never leaks
        assert "packets received" in output  # summary lines pass through

    def test_host_only_subnet_is_noted_and_errors(self):
        """A /32 (a single host, not a network) is not ARP-sweptable: specific
        note, no misleading 'no local interface', and a hard error."""
        with patch("app.services.scanner.get_default_subnets", return_value=[]), \
                patch("app.services.scanner.subprocess.run", return_value=_FakeProc("10.0.0.5  aa:bb  X\n")) as mock_run:
            _, output, error = run_arp_scan(subnets=["192.168.70.0/32"])
        assert error is not None
        assert "single host" in output
        assert "no local interface" not in output
        mock_run.assert_not_called()

    def test_two_subnets_sweep_separately(self):
        out = "10.0.0.5  aa:bb  X\n10.1.0.5  aa:bb  Y\n"
        # ``classify_subnet`` is stubbed to "broadcast" so this test exercises the
        # per-sweep arp-scan plumbing in isolation (one sweep → one arp-scan call);
        # the L3/tunnel branch is covered by its own tests below.
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[
                {"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"},
                {"cidr": "10.1.0.0/24", "interface": "eth1", "source": "auto"},
            ],
        ), \
             patch("app.services.scanner.classify_subnet", return_value={"kind": "broadcast", "cidr": None, "iface": "eth1", "egress": "eth1"}), \
             patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)) as mock_run:
            _, output, error = run_arp_scan(subnets=["10.0.0.0/24", "10.1.0.0/24"])
        assert error is None
        assert mock_run.call_count == 2
        assert "10.0.0.5" in output and "10.1.0.5" in output


class TestParseScanOutput:
    def test_parses_arp_scan_lines(self):
        out = (
            "Starting arp-scan 1.10.0 with 256 hosts\n"
            "192.168.86.1  aa:bb:cc:dd:ee:01  D-LINK\n"
            "192.168.86.2  aa:bb:cc:dd:ee:02\n"
            "14 packets received by filter, 0 packets dropped by kernel\n"
        )
        got = _parse_scan_output(out)
        assert [g["ip"] for g in got] == ["192.168.86.1", "192.168.86.2"]
        assert got[0]["mac"] == "aa:bb:cc:dd:ee:01"
        assert got[0]["detail"] == "D-LINK"

    def test_scopes_to_subnets_and_dedupes(self):
        out = (
            "10.0.0.5  aa:bb:cc:dd:ee:ff\n"
            "10.0.0.5  aa:bb:cc:dd:ee:ff\n"
            "192.168.86.9  11:22:33:44:55:66\n"
        )
        got = _parse_scan_output(out, subnets=["10.0.0.0/24"])
        assert len(got) == 1
        assert got[0]["ip"] == "10.0.0.5"

    def test_scapy_via_lines(self):
        out = "192.168.86.10  aa:bb:cc:dd:ee:ff  (via 192.168.86.0/24)\n"
        got = _parse_scan_output(out)
        assert got[0]["ip"] == "192.168.86.10"
        assert got[0]["detail"].startswith("(via")


class TestResolveHostnames:
    async def test_fills_hostname_from_reverse_lookup(self):
        calls = []

        def fake(addr):
            calls.append(addr)
            # Real gethostbyaddr shape: (hostname, aliases, addrlist) tuple.
            return ("box.lan", [], [addr])

        with patch("socket.gethostbyaddr", side_effect=fake):
            got = await resolve_hostnames([{"ip": "10.0.0.5", "mac": "aa"}])
        assert got[0]["hostname"] == "box.lan"
        assert calls == ["10.0.0.5"]

    async def test_lookup_failure_leaves_none(self):
        import socket

        with patch("socket.gethostbyaddr", side_effect=socket.gaierror("nope")):
            got = await resolve_hostnames([{"ip": "10.0.0.5", "mac": "aa"}])
        assert got[0]["hostname"] is None

    async def test_existing_hostname_is_kept_and_not_reversed(self):
        # Reverse DNS is the *last-resort* source: a host that already carries a
        # name (e.g. parsed from nmap's grepable output) must keep it, and no
        # gethostbyaddr call is made for it.
        calls = []

        def fake(addr):
            calls.append(addr)
            # Real gethostbyaddr shape: (hostname, aliases, addrlist) tuple.
            return ("wrong.lan", [], [addr])

        with patch("socket.gethostbyaddr", side_effect=fake):
            got = await resolve_hostnames(
                [
                    {"ip": "10.0.0.5", "mac": None, "hostname": "frick"},
                    {"ip": "10.0.0.9", "mac": None},
                ]
            )
        assert got[0]["hostname"] == "frick"
        assert calls == ["10.0.0.9"]  # only the unnamed host was reversed

    async def test_falsy_existing_hostname_is_resolved(self):
        with patch(
            "socket.gethostbyaddr",
            # Real gethostbyaddr shape: (hostname, aliases, addrlist) tuple.
            side_effect=lambda a: ("a.lan", [], [a]),
        ):
            got = await resolve_hostnames([{"ip": "10.0.0.5", "mac": None, "hostname": ""}])
        assert got[0]["hostname"] == "a.lan"


class TestRunScanHosts:
    async def test_result_includes_structured_hosts(self):
        table = "192.168.86.5  aa:bb:cc:dd:ee:ff  VMWARE\n192.168.86.9  11:22:33:44:55:66\n"
        with patch("app.services.scanner.run_arp_scan", return_value=(None, table, None)), \
                patch("app.services.scanner.resolve_hostnames", new=AsyncMock(side_effect=lambda hosts: hosts)):
            result = await run_scan("aa:bb:cc:dd:ee:ff", "arp-scan")
        assert [h["ip"] for h in result["hosts"]] == ["192.168.86.5", "192.168.86.9"]


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

class _KnownHostsCursor:
    """Async stand-in for an aiosqlite cursor yielding a fixed set of rows."""

    def __init__(self, rows):
        self._rows = rows

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def fetchall(self):
        return self._rows


class _KnownHostsDb:
    """A db object whose ``execute`` returns a cursor over fixed rows."""

    def __init__(self, rows):
        self._rows = rows

    def execute(self, *args, **kwargs):
        return _KnownHostsCursor(self._rows)


class TestLoadKnownHostnames:
    async def test_none_db(self):
        assert await load_known_hostnames(None) == {}

    async def test_maps_normalized_mac_to_name(self):
        db = _KnownHostsDb(
            [
                {"name": "vault", "mac_address": "46:DC:21:61:26:93"},
                {"name": "jellyfin", "mac_address": "a0:ad:9f:85:d7:cb"},
            ]
        )
        assert await load_known_hostnames(db) == {
            "46:dc:21:61:26:93": "vault",
            "a0:ad:9f:85:d7:cb": "jellyfin",
        }

    async def test_skips_blank_rows(self):
        db = _KnownHostsDb(
            [
                {"name": "", "mac_address": "aa:bb:cc:dd:ee:ff"},
                {"name": "ghost", "mac_address": ""},
                {"name": "ok", "mac_address": "11:22:33:44:55:66"},
            ]
        )
        assert await load_known_hostnames(db) == {"11:22:33:44:55:66": "ok"}

    async def test_db_error_returns_empty(self):
        class _BoomDb:
            def execute(self, *args, **kwargs):
                raise RuntimeError("no hosts table")

        assert await load_known_hostnames(_BoomDb()) == {}


class TestLoadKnownHostnamesByIp:
    async def test_none_db(self):
        assert await load_known_hostnames_by_ip(None) == {}

    async def test_maps_current_ip_to_name(self):
        db = _KnownHostsDb(
            [
                {"name": "frick", "current_ip": "10.66.0.7"},
                {"name": "frack", "current_ip": "10.66.0.9"},
            ]
        )
        assert await load_known_hostnames_by_ip(db) == {
            "10.66.0.7": "frick",
            "10.66.0.9": "frack",
        }

    async def test_skips_blank_rows(self):
        db = _KnownHostsDb(
            [
                {"name": "noip", "current_ip": ""},
                {"name": "", "current_ip": "10.0.0.5"},
                {"name": "ok", "current_ip": "10.0.0.6"},
            ]
        )
        assert await load_known_hostnames_by_ip(db) == {"10.0.0.6": "ok"}

    async def test_db_error_returns_empty(self):
        class _BoomDb:
            def execute(self, *args, **kwargs):
                raise RuntimeError("no hosts table")

        assert await load_known_hostnames_by_ip(_BoomDb()) == {}


class TestApplyHostnames:
    def test_known_name_wins_over_mdns_and_ptr(self):
        hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ptr-name"}]
        mdns = ({"10.0.0.5": "mdns-by-ip"}, {"aa:bb:cc:dd:ee:ff": "mdns-by-mac"})
        out = apply_hostnames(hosts, mdns=mdns, known={"aa:bb:cc:dd:ee:ff": "vault"})
        assert out[0]["hostname"] == "vault"

    def test_known_by_ip_labels_macless_routed_host(self):
        # A routed/tunnel host has no visible MAC — its curated name is matched
        # by ``current_ip`` instead (the ``frick``/``frack`` case).
        hosts = [{"ip": "10.0.0.5", "mac": None, "hostname": None}]
        out = apply_hostnames(hosts, mdns=({}, {}), known={}, known_by_ip={"10.0.0.5": "frick"})
        assert out[0]["hostname"] == "frick"

    def test_known_by_mac_beats_known_by_ip(self):
        hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": None}]
        out = apply_hostnames(
            hosts,
            mdns=({}, {}),
            known={"aa:bb:cc:dd:ee:ff": "vault"},
            known_by_ip={"10.0.0.5": "other"},
        )
        assert out[0]["hostname"] == "vault"

    def test_known_by_ip_beats_mdns_and_ptr(self):
        hosts = [{"ip": "10.0.0.5", "mac": None, "hostname": "ptr-name"}]
        out = apply_hostnames(
            hosts,
            mdns=({"10.0.0.5": "mdns-by-ip"}, {}),
            known_by_ip={"10.0.0.5": "frick"},
        )
        assert out[0]["hostname"] == "frick"

    def test_known_by_ip_ignored_when_ip_not_listed(self):
        # No mislabeling: a host whose IP is not a stored ``current_ip`` gets no name.
        hosts = [{"ip": "10.0.0.99", "mac": None, "hostname": None}]
        out = apply_hostnames(hosts, mdns=({}, {}), known_by_ip={"10.0.0.5": "frick"})
        assert out[0]["hostname"] is None

    def test_mdns_by_ip_beats_ptr(self):
        hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ptr-name"}]
        out = apply_hostnames(hosts, mdns=({"10.0.0.5": "mdns-by-ip"}, {}), known={})
        assert out[0]["hostname"] == "mdns-by-ip"

    def test_mdns_by_mac_when_ip_not_matched(self):
        hosts = [{"ip": "10.0.0.99", "mac": "aa:bb:cc:dd:ee:ff", "hostname": None}]
        mdns = ({"10.0.0.5": "some-other-host"}, {"aa:bb:cc:dd:ee:ff": "by-mac"})
        out = apply_hostnames(hosts, mdns=mdns, known={})
        assert out[0]["hostname"] == "by-mac"

    def test_ptr_kept_when_nothing_matches(self):
        hosts = [{"ip": "10.0.0.99", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ptr-name"}]
        out = apply_hostnames(hosts, mdns=({}, {}), known={})
        assert out[0]["hostname"] == "ptr-name"

    def test_none_when_nothing_matches(self):
        hosts = [{"ip": "10.0.0.99", "mac": "aa:bb:cc:dd:ee:ff", "hostname": None}]
        out = apply_hostnames(hosts)
        assert out[0]["hostname"] is None

    def test_named_hosts_sorted_first(self):
        hosts = [
            {"ip": "10.0.0.9", "mac": "00:00:00:00:00:01", "hostname": None},
            {"ip": "10.0.0.2", "mac": "00:00:00:00:00:02", "hostname": None},
        ]
        out = apply_hostnames(hosts, mdns=({"10.0.0.9": "niner"}, {}))
        assert [h["ip"] for h in out] == ["10.0.0.9", "10.0.0.2"]

    def test_cached_name_used_when_no_live_or_known(self):
        hosts = [{"ip": "10.0.0.99", "mac": "aa:bb:cc:dd:ee:ff", "hostname": None}]
        out = apply_hostnames(hosts, mdns=({}, {}), known={}, cached={"aa:bb:cc:dd:ee:ff": "vault"})
        assert out[0]["hostname"] == "vault"

    def test_live_mdns_beats_cached(self):
        hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": None}]
        out = apply_hostnames(
            hosts,
            mdns=({}, {"aa:bb:cc:dd:ee:ff": "live"}),
            cached={"aa:bb:cc:dd:ee:ff": "stale"},
        )
        assert out[0]["hostname"] == "live"

    def test_known_beats_cached(self):
        hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": None}]
        out = apply_hostnames(
            hosts,
            mdns=({}, {}),
            known={"aa:bb:cc:dd:ee:ff": "vault"},
            cached={"aa:bb:cc:dd:ee:ff": "mdns"},
        )
        assert out[0]["hostname"] == "vault"

    def test_cached_beats_ptr(self):
        hosts = [{"ip": "10.0.0.99", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ptr-name"}]
        out = apply_hostnames(hosts, mdns=({}, {}), cached={"aa:bb:cc:dd:ee:ff": "mdns"})
        assert out[0]["hostname"] == "mdns"


class TestMdnsNameCache:
    async def _db(self):
        import aiosqlite

        db = await aiosqlite.connect(":memory:")
        db.row_factory = aiosqlite.Row
        await db.execute(
            "CREATE TABLE mdns_names (mac TEXT PRIMARY KEY, hostname TEXT NOT NULL, updated_at TEXT)"
        )
        await db.commit()
        return db

    async def test_remember_none_db_is_noop(self):
        assert await remember_mdns_names(None, {"aa:bb:cc:dd:ee:ff": "x"}) is None

    async def test_load_none_db_is_empty(self):
        assert await load_mdns_names(None) == {}

    async def test_remember_then_load_roundtrip(self):
        db = await self._db()
        try:
            await remember_mdns_names(
                db,
                {"AA:BB:CC:DD:EE:FF": "Apple TV", "11:22:33:44:55:66": "Printer"},
            )
            assert await load_mdns_names(db) == {
                "aa:bb:cc:dd:ee:ff": "Apple TV",
                "11:22:33:44:55:66": "Printer",
            }
        finally:
            await db.close()

    async def test_remember_overwrites_existing_name(self):
        db = await self._db()
        try:
            await remember_mdns_names(db, {"aa:bb:cc:dd:ee:ff": "Old Name"})
            await remember_mdns_names(db, {"aa:bb:cc:dd:ee:ff": "New Name"})
            assert await load_mdns_names(db) == {"aa:bb:cc:dd:ee:ff": "New Name"}
        finally:
            await db.close()

    async def test_skips_blank_mac_or_name(self):
        db = await self._db()
        try:
            await remember_mdns_names(db, {"": "no-mac", "aa:bb:cc:dd:ee:ff": "   "})
            assert await load_mdns_names(db) == {}
        finally:
            await db.close()


# =============================================================================
# Layer-3 (tunnel / routed) discovery + nmap diagnostic
# =============================================================================


class TestGetInterfaceFlags:
    def test_parses_flags(self):
        out = "2: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UP\n"
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            assert get_interface_flags("wg0") == "POINTOPOINT,NOARP,UP,LOWER_UP"

    def test_broadcast_flags(self):
        out = "1: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            assert get_interface_flags("eth1") == "BROADCAST,MULTICAST,UP,LOWER_UP"

    def test_no_flags_returns_none(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("1: eth1: nope\n")):
            assert get_interface_flags("eth1") is None

    def test_ip_missing_returns_none(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            assert get_interface_flags("eth1") is None

    def test_nonzero_returncode_returns_none(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("1: x <A,B>\n", code=1)):
            assert get_interface_flags("eth1") is None

    def test_empty_iface_returns_none(self):
        assert get_interface_flags(None) is None


class TestIsTunnelInterface:
    def test_broadcast_flag_is_false(self):
        with patch("app.services.scanner.get_interface_flags", return_value="BROADCAST,MULTICAST,UP"):
            assert is_tunnel_interface("eth1") is False

    def test_pointopoint_flag_is_true(self):
        with patch("app.services.scanner.get_interface_flags", return_value="POINTOPOINT,NOARP,UP"):
            assert is_tunnel_interface("wg0") is True

    def test_noarp_flag_is_true(self):
        with patch("app.services.scanner.get_interface_flags", return_value="NOARP,UP"):
            assert is_tunnel_interface("gre0") is True

    def test_name_heuristic_when_flags_unreadable(self):
        with patch("app.services.scanner.get_interface_flags", return_value=None):
            assert is_tunnel_interface("wg0") is True
            assert is_tunnel_interface("tun0") is True
            assert is_tunnel_interface("eth1") is False

    def test_empty_iface_is_false(self):
        assert is_tunnel_interface(None) is False

    def test_prepassed_flags_avoid_subprocess(self):
        with patch("app.services.scanner.get_interface_flags") as mock_flags:
            assert is_tunnel_interface("eth1", "BROADCAST,UP") is False
            mock_flags.assert_not_called()


class TestClassifySubnet:
    def _classify(self, *, local="eth1", flags="BROADCAST,MULTICAST,UP", has_addr=True, tunnel=False):
        with patch("app.services.scanner.get_local_ip_for_network", return_value=("10.0.0.1", local)), \
             patch("app.services.scanner.get_interface_flags", return_value=flags), \
             patch("app.services.scanner.is_tunnel_interface", return_value=tunnel), \
             patch("app.services.scanner.interface_has_address_in", return_value=has_addr):
            return classify_subnet("10.0.0.0/24", local)

    def test_broadcast(self):
        r = self._classify(flags="BROADCAST,MULTICAST,UP", has_addr=True, tunnel=False)
        assert r["kind"] == "broadcast" and r["egress"] == "eth1" and r["cidr"] == "10.0.0.0/24"

    def test_routed_when_no_local_address(self):
        assert self._classify(flags="BROADCAST,MULTICAST,UP", has_addr=False, tunnel=False)["kind"] == "routed"

    def test_tunnel(self):
        assert self._classify(local="wg0", flags="POINTOPOINT,NOARP,UP", tunnel=True)["kind"] == "tunnel"

    def test_unknown_when_no_flags(self):
        assert self._classify(local="eth1", flags=None, tunnel=False)["kind"] == "unknown"

    def test_subnet_is_l3_only_helper(self):
        with patch("app.services.scanner.classify_subnet", return_value={"kind": "routed", "egress": "wg0"}):
            assert subnet_is_l3_only("10.0.0.0/24", "wg0") is True
        with patch("app.services.scanner.classify_subnet", return_value={"kind": "broadcast", "egress": "eth1"}):
            assert subnet_is_l3_only("10.0.0.0/24", "eth1") is False


class TestUsableHosts:
    def test_slash24(self):
        hosts = _usable_hosts("10.0.0.0/24")
        assert len(hosts) == 254 and "10.0.0.1" in hosts and "10.0.0.254" in hosts

    def test_slash30(self):
        assert _usable_hosts("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]

    def test_slash8_too_large(self):
        with pytest.raises(ValueError):
            _usable_hosts("10.0.0.0/8")

    def test_invalid(self):
        with pytest.raises(ValueError):
            _usable_hosts("not-a-cidr")


class TestL3ProbeEgress:
    def test_explicit_wins(self):
        assert _l3_probe_egress("10.0.0.0/24", "eth0") == "eth0"

    def test_auto_resolves_via_kernel_route(self):
        with patch("app.services.scanner.get_local_ip_for_network", return_value=("10.0.0.1", "eth2")):
            assert _l3_probe_egress("10.0.0.0/24", "auto") == "eth2"

    def test_none_resolves_via_kernel_route(self):
        with patch("app.services.scanner.get_local_ip_for_network", return_value=(None, None)):
            assert _l3_probe_egress("10.0.0.0/24", None) is None


class TestL3AliveScapy:
    def test_empty_hosts(self):
        assert _l3_alive_scapy([], None, 1.0) == set()

    def test_import_failure_returns_none(self, monkeypatch):
        # Forcing the scapy imports to fail must yield None (so the caller
        # falls back), never an exception.
        #
        # Every scapy module is set to ``None`` (the documented way to force an
        # ImportError), not just the top-level package: once an earlier test in
        # the session has imported ``scapy.all`` / ``scapy.sendrecv``, a plain
        # ``sys.modules["scapy"] = None`` is NOT enough — the import machinery
        # returns the already-cached submodules without re-importing the parent
        # package, so ``from scapy.all import ...`` would succeed and the real
        # ``sr()`` would run (2 s socket timeout; under a root CI runner it
        # returns an empty set instead of None and this test fails).
        for mod in ("scapy", "scapy.all", "scapy.sendrecv"):
            monkeypatch.setitem(sys.modules, mod, None)
        assert _l3_alive_scapy(["10.0.0.5"], None, 1.0) is None


class TestL3AliveNmap:
    def test_parses_grepable_up_hosts(self):
        out = (
            "# Nmap scan initiated\n"
            "# Hosts:  256 total, 2 up\n"
            "- HOSTS:\n"
            "Host: 10.0.0.5 (10.0.0.5) Status: up\n"
            "Host: 10.0.0.7 (10.0.0.7) Status: up\n"
            "Host: 10.0.0.99 (10.0.0.99) Status: down\n"
            "- HOSTS: 256 total, 2 up\n"
        )
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            assert _l3_alive_nmap("10.0.0.0/24", "wg0") == {
                # no reverse-DNS name → nmap echoes the IP → hostname stays None
                "10.0.0.5": {"mac": None, "hostname": None},
                "10.0.0.7": {"mac": None, "hostname": None},
            }

    def test_parses_hostname_from_grepable_line(self):
        # ``nmap -sn`` does reverse DNS by default; the name (possibly with
        # spaces) rides in the parenthesised part of the ``Host:`` line.
        out = (
            "Host: 192.168.1.5 (frick) Status: up\n"
            "Host: 192.168.1.9 (frick) Status: up\n"
        )
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            assert _l3_alive_nmap("192.168.1.0/24", None) == {
                "192.168.1.5": {"mac": None, "hostname": "frick"},
                "192.168.1.9": {"mac": None, "hostname": "frick"},
            }

    def test_nmap_missing_returns_none(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            assert _l3_alive_nmap("10.0.0.0/24", None) is None

    def test_all_down_is_empty(self):
        out = "Host: 10.0.0.99 (10.0.0.99) Status: down\n"
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            assert _l3_alive_nmap("10.0.0.0/24", None) == {}

    def test_captures_mac_and_hostname_when_present(self):
        # A locally-attached host emits a MAC line right after its Host line; a
        # routed/tunnel host has none (its MAC stays None).  ``nmap -sn`` also
        # reverse-resolves both, so both carry a hostname.
        out = (
            "Host: 192.168.1.5 (frick)\tStatus: Up\n"
            "MAC Address: aa:bb:cc:dd:ee:ff (VMware)\n"
            "Host: 192.168.1.9 (flash)\tStatus: Up\n"
        )
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)):
            assert _l3_alive_nmap("192.168.1.0/24", None) == {
                "192.168.1.5": {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "frick"},
                "192.168.1.9": {"mac": None, "hostname": "flash"},
            }


class TestL3AlivePing:
    def test_collects_replies(self):
        def fake_run(cmd, **_kw):
            return _FakeProc("", code=0 if cmd[-1] == "10.0.0.5" else 1)

        with patch("app.services.scanner.subprocess.run", side_effect=fake_run):
            assert _l3_alive_ping(["10.0.0.5", "10.0.0.9"], None) == {"10.0.0.5"}

    def test_empty(self):
        assert _l3_alive_ping([], None) == set()


class TestRunL3Probe:
    def test_invalid_subnet(self):
        found, output, error = run_l3_probe("not-a-cidr")
        assert found is None and output == "" and "invalid subnet" in error

    def test_scapy_happy_path(self):
        with patch("app.services.scanner._l3_alive_scapy", return_value={"10.0.0.5"}):
            found, output, error = run_l3_probe("10.0.0.0/24", "wg0")
        assert error is None
        assert "10.0.0.5" in output and "--" in output
        assert "routed via wg0" in output and "scapy ICMP" in output

    def test_falls_back_to_ping(self):
        with patch("app.services.scanner._l3_alive_scapy", return_value=None), \
             patch("app.services.scanner._l3_alive_nmap", return_value=None), \
             patch("app.services.scanner._l3_alive_ping", return_value={"10.0.0.9"}):
            found, output, error = run_l3_probe("10.0.0.0/24", "wg0")
        assert error is None
        assert "10.0.0.9" in output and "ping" in output

    def test_no_live_hosts(self):
        with patch("app.services.scanner._l3_alive_scapy", return_value=None), \
             patch("app.services.scanner._l3_alive_nmap", return_value=None), \
             patch("app.services.scanner._l3_alive_ping", return_value=set()):
            found, output, error = run_l3_probe("10.0.0.0/24", "wg0")
        assert error is None and output == "" and found is None


class TestRunNmapScan:
    def test_happy_path(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("", code=0)) as mock_run, \
             patch("app.services.scanner.classify_subnet",
                   return_value={"kind": "routed", "cidr": "10.0.0.0/24", "iface": "wg0", "egress": "wg0"}), \
             patch("app.services.scanner._l3_alive_nmap",
                   return_value={"10.0.0.5": {"mac": None, "hostname": None},
                                 "10.0.0.7": {"mac": None, "hostname": "box7"}}):
            found, output, error = run_nmap_scan(subnets=["10.0.0.0/24"], interface="wg0")
        assert error is None
        assert "10.0.0.5" in output and "10.0.0.7" in output and "--" in output
        assert "routed via wg0" in output
        # nmap's reverse-DNS name rides through to the parseable output line
        assert "hostname:box7" in output
        # the only subprocess call is the `nmap -V` availability probe
        assert mock_run.call_count == 1 and mock_run.call_args[0][0] == ["nmap", "-V"]

    def test_local_host_carries_mac(self):
        # A locally-attached host (kind "local") carries its real MAC in the
        # output line — what lets the UI do MAC-keyed hostname lookup.
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("", code=0)), \
             patch("app.services.scanner.classify_subnet",
                   return_value={"kind": "local", "egress": "enp6s0"}), \
             patch("app.services.scanner._l3_alive_nmap",
                   return_value={"192.168.1.5": {"mac": "aa:bb:cc:dd:ee:ff", "hostname": "frick"}}):
            found, output, error = run_nmap_scan(subnets=["192.168.1.0/24"])
        assert error is None
        assert "192.168.1.5  aa:bb:cc:dd:ee:ff" in output
        assert "hostname:frick" in output
        assert "routed" not in output

    def test_nmap_not_installed(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            found, output, error = run_nmap_scan(subnets=["10.0.0.0/24"])
        assert "not installed" in error

    def test_probe_failed_on_subnet(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("", code=0)), \
             patch("app.services.scanner.classify_subnet", return_value={"kind": "tunnel", "egress": "wg0"}), \
             patch("app.services.scanner._l3_alive_nmap", return_value=None):
            found, output, error = run_nmap_scan(subnets=["10.0.0.0/24"], interface="wg0")
        assert "nmap failed on" in error

    def test_partial_failure_keeps_good_subnets(self):
        # A probe failure on ONE subnet must not discard the others' results:
        # the failed CIDR is named in ``error`` while the good subnet's hosts are
        # still returned (the old code returned immediately, losing everything).
        def fake_alive(cidr, egress, kind=None):
            return None if cidr == "10.0.0.0/24" else {"192.168.100.5": None}
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("", code=0)), \
             patch("app.services.scanner.classify_subnet",
                    return_value={"kind": "routed", "egress": "enp6s0"}), \
             patch("app.services.scanner._l3_alive_nmap", side_effect=fake_alive):
            found, output, error = run_nmap_scan(
                subnets=["10.0.0.0/24", "192.168.100.0/24"]
            )
        assert "192.168.100.5" in output  # the good subnet survived
        assert "nmap failed on 10.0.0.0/24" in error  # the bad one is named

    def test_all_subnets_failed_is_hard_error(self):
        # Every subnet failing = nothing to salvage → a hard error naming all of them.
        def fake_alive(cidr, egress, kind=None):
            return None
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc("", code=0)), \
             patch("app.services.scanner.classify_subnet",
                    return_value={"kind": "routed", "egress": "enp6s0"}), \
             patch("app.services.scanner._l3_alive_nmap", side_effect=fake_alive):
            found, output, error = run_nmap_scan(
                subnets=["10.0.0.0/24", "192.168.100.0/24"]
            )
        assert found is None
        assert output == ""
        assert "10.0.0.0/24" in error and "192.168.100.0/24" in error

    def test_empty_subnets(self):
        assert run_nmap_scan(subnets=[]) == (None, "", None)


class TestRunScanNmapDispatch:
    async def test_nmap_dispatch(self):
        with patch(
            "app.services.scanner.run_nmap_scan",
            return_value=(None, "10.0.0.5  --  (routed via wg0, nmap -sn)", None),
        ), patch("app.services.scanner.run_arp_scan") as mock_arp, \
             patch("app.services.scanner.run_scapy_scan") as mock_scapy, \
             patch("app.services.scanner.resolve_hostnames", new=AsyncMock(return_value=[])):
            result = await run_scan("aa:bb:cc:dd:ee:ff", "nmap")
        assert result["method"] == "nmap"
        assert result["error"] is None
        assert "10.0.0.5" in result["output"]
        mock_arp.assert_not_called()
        mock_scapy.assert_not_called()


class TestL3BranchDelegation:
    def test_arp_scan_delegates_tunnel_subnet_to_l3(self):
        l3_out = "10.0.0.5  --  (routed via wg0, scapy ICMP)"
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[{"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"}],
        ), patch(
            "app.services.scanner.classify_subnet",
            return_value={"kind": "tunnel", "cidr": "10.0.0.0/24", "iface": "eth1", "egress": "wg0"},
        ), patch(
            "app.services.scanner.run_l3_probe", return_value=(None, l3_out, None)
        ) as mock_l3, patch("app.services.scanner.subprocess.run") as mock_run:
            found, output, error = run_arp_scan(subnets=["10.0.0.0/24"])
        assert mock_l3.called
        mock_run.assert_not_called()  # no arp-scan broadcast on a tunnel subnet
        assert error is None and "10.0.0.5" in output and "--" in output

    def test_scapy_delegates_routed_subnet_to_l3(self, monkeypatch):
        fake_all = SimpleNamespace(ARP=object, Ether=object, srp=object, conf=SimpleNamespace(verb=0))
        monkeypatch.setitem(sys.modules, "scapy", SimpleNamespace(all=fake_all))
        monkeypatch.setitem(sys.modules, "scapy.all", fake_all)
        l3_out = "10.0.0.5  --  (routed via wg0, scapy ICMP)"
        with patch(
            "app.services.scanner.classify_subnet",
            return_value={"kind": "routed", "cidr": "10.0.0.0/24", "iface": "wg0", "egress": "wg0"},
        ), patch("app.services.scanner.run_l3_probe", return_value=(None, l3_out, None)) as mock_l3:
            found, output, error = run_scapy_scan("aa:bb:cc:dd:ee:ff", "wg0", subnets=["10.0.0.0/24"])
        assert mock_l3.called
        assert error is None and "10.0.0.5" in output


class TestParseScanOutputL3Line:
    def test_dash_mac_maps_to_none(self):
        hosts = _parse_scan_output("10.0.0.5  --  (routed via wg0, nmap -sn)")
        assert hosts == [
            {
                "ip": "10.0.0.5",
                "mac": None,
                "detail": "(routed via wg0, nmap -sn)",
                "hostname": None,
            }
        ]

    def test_real_mac_parsed(self):
        hosts = _parse_scan_output("10.0.0.5  aa:bb:cc:dd:ee:ff  Vendor")
        assert hosts[0]["mac"] == "aa:bb:cc:dd:ee:ff"

    def test_hostname_token_is_extracted(self):
        # A name learned by the sweep itself (``nmap -sn`` reverse DNS) is
        # carried in a trailing ``hostname:<name>`` token; it is lifted out of
        # ``detail`` (names may contain spaces).
        hosts = _parse_scan_output("10.0.0.5  --  (routed via wg0, nmap -sn)  hostname:frick")
        assert hosts[0]["hostname"] == "frick"
        assert "hostname:" not in hosts[0]["detail"]

    def test_hostname_token_with_spaces(self):
        hosts = _parse_scan_output("10.0.0.9  --  (routed via wg0, nmap -sn)  hostname:my box")
        assert hosts[0]["hostname"] == "my box"


# ───────────────────────────── Host validation (Validate button) ─────────────────────────────


async def test_validate_scopes_to_the_given_port_for_a_shared_device():
    """Two records for one box share an ip+mac but each validates its own port:
    the requested port is actually probed (so its state is derivable even when
    it is not a default service-scan port) and ``result['ip']['port_state']``
    reflects it, so the same device can be verified on multiple ports
    independently (log-only, no DB)."""
    from app.services.scanner import validate_host_record

    row = {"ip": "10.0.0.50", "mac": "aa:bb:cc:dd:ee:77", "detail": "arp"}
    services = [
        {"port": 8787, "protocol": "tcp", "state": "open", "service": "http"},
        {"port": 8181, "protocol": "tcp", "state": "open", "service": "http"},
    ]
    probe = AsyncMock(return_value={"ok": True, "error": None, "services": services})
    with patch("app.services.scanner.sweep_responder_hosts", new=AsyncMock(return_value=([row], None))), \
        patch("app.services.scanner.probe_services", new=probe), \
        patch("app.services.scanner.discover_hostnames", new=AsyncMock(return_value=({}, {}))), \
        patch("app.services.scanner.resolve_hostname", new=AsyncMock(return_value="batcave")):
        r1 = await validate_host_record(
            None, name="batcave-web", mac="aa:bb:cc:dd:ee:77", ip="10.0.0.50", port=8787,
        )
        r2 = await validate_host_record(
            None, name="batcave-npm", mac="aa:bb:cc:dd:ee:77", ip="10.0.0.50", port=8181,
        )

    assert r1["ip"]["port"] == 8787
    assert r1["ip"]["port_state"] == "open"
    assert r2["ip"]["port"] == 8181
    assert r2["ip"]["port_state"] == "open"
    # Both records resolve the same device identity (same IP the MAC answers on).
    assert r1["mac"]["found"] is True
    assert r1["mac"]["ip"] == "10.0.0.50"
    assert r2["mac"]["ip"] == "10.0.0.50"
    # The requested (non-default) port is probed for each record, so a monitored
    # port outside the standard service-scan list is still checked.
    assert probe.call_args_list[0].kwargs["tcp_ports"] == [8787]
    assert probe.call_args_list[1].kwargs["tcp_ports"] == [8181]


class TestBuildPortSpec:
    def test_combined(self):
        assert build_port_spec([22, 80], [53, 161]) == "T:22,80,U:53,161"

    def test_tcp_only(self):
        assert build_port_spec([80], []) == "T:80"

    def test_udp_only(self):
        assert build_port_spec([], [53]) == "U:53"

    def test_empty_lists_give_empty_spec(self):
        assert build_port_spec([], []) == ""


class TestParseNmapServicesJson:
    _DOC = json.dumps({
        "hosts": [
            {
                "address": "192.168.86.9",
                "hostnames": [],
                "ports": [
                    {"id": 80, "protocol": "tcp", "state": "open",
                     "service": {"name": "http", "product": "nginx", "version": "1.24.0", "extrainfo": None}},
                    {"id": 22, "protocol": "tcp", "state": "closed", "service": "ssh"},
                    {"id": 53, "protocol": "udp", "state": "open", "service": {"name": "domain"}},
                ],
            },
            {"address": "192.168.86.1", "ports": []},
        ],
        "runstats": {"hosts_up": 1},
    })


    def test_dict_and_string_services(self):
        rows = parse_nmap_services_json(self._DOC)
        assert [r["port"] for r in rows] == [80, 22, 53]
        assert rows[0]["service"] == "http"
        assert rows[0]["product"] == "nginx"
        assert rows[0]["version"] == "1.24.0"
        assert rows[1]["service"] == "ssh"  # older-nmap plain-string form
        assert rows[1]["product"] is None
        assert rows[2]["protocol"] == "udp"
        assert rows[2]["state"] == "open"

    def test_bad_or_empty_input_is_empty_list(self):
        assert parse_nmap_services_json("") == []
        assert parse_nmap_services_json("nmap: usage error") == []
        assert parse_nmap_services_json("{not json") == []

    def test_hosts_without_ports(self):
        assert parse_nmap_services_json('{"hosts":[{"address":"1.1.1.1"}]}') == []


class TestParseNmapServicesXml:
    _DOC = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE nmaprun SYSTEM "http://www.insecure.org/nmap/nmap.xsd">'
        '<nmaprun version="7.93" args="nmap">'
        '<host><address addr="192.168.86.9" addrtype="ipv4"/>'
        '<ports>'
        '<port protocol="tcp" portid="80"><state state="open"/>'
        '<service name="http" product="nginx" version="1.24.0" extrainfo=""/>'
        '</port>'
        '<port protocol="tcp" portid="22"><state state="closed"/>'
        '<service name="ssh"/>'
        '</port>'
        '<port protocol="udp" portid="53"><state state="open"/>'
        '<service name="domain"/>'
        '</port></ports></host>'
        '<host><address addr="192.168.86.1" addrtype="ipv4"/></host>'
        '</nmaprun>'
    )

    def test_ports_and_services(self):
        ports = parse_nmap_services_xml(self._DOC)
        assert [p["port"] for p in ports] == [80, 22, 53]
        assert ports[0]["protocol"] == "tcp"
        assert ports[0]["state"] == "open"
        assert ports[0]["service"] == "http"
        assert ports[0]["product"] == "nginx"
        assert ports[0]["version"] == "1.24.0"
        assert ports[2]["protocol"] == "udp"

    def test_empty_and_unparseable(self):
        assert parse_nmap_services_xml("") == []
        assert parse_nmap_services_xml("not xml at all") == []
        assert parse_nmap_services_xml('<nmaprun><host><ports><port portid=""></nmaprun>') == []


class TestRunServiceScan:
    def test_happy_path_builds_nmap_cmd(self):
        xml = (
            '<?xml version="1.0"?>'
            '<nmaprun version="7.93" args="nmap -Pn">'
            '<host><address addr="192.168.86.9" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="80">'
            '<state state="open"/><service name="http" product="Apache"/>'
            '</port></ports></host></nmaprun>'
        )
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(stdout=xml, code=0)) as mock_run:
            services, error = run_service_scan("192.168.86.9", tcp_ports=[80], udp_ports=[])
        assert error is None
        assert services[0]["service"] == "http"
        assert services[0]["port"] == 80
        assert services[0]["product"] == "Apache"
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "nmap"
        for flag in ("-Pn", "-sT", "-sU", "-sV", "--open", "-oX"):
            assert flag in cmd
        assert "-oJ" not in cmd  # nmap 7.93 re-parses -oJ as deprecated -o + filename "J"
        assert cmd[cmd.index("-oX") + 1] == "-"  # XML to stdout, like the L3 sweeps' -oG -
        assert "192.168.86.9" in cmd
        spec = cmd[cmd.index("-p") + 1]
        assert "80" in spec  # the caller's port is merged in
        assert "22" in spec  # the default list is always included

    def test_missing_binary_is_reported(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            services, error = run_service_scan("1.2.3.4")
        assert services == []
        assert "not found" in error

    def test_timeout_is_reported(self):
        with patch("app.services.scanner.subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 60)):
            services, error = run_service_scan("1.2.3.4")
        assert services == []
        assert "timed out" in error

    def test_unparseable_output_is_reported(self):
        with patch("app.services.scanner.subprocess.run", return_value=_FakeProc(stdout="garbage", stderr="bad args", code=1)):
            services, error = run_service_scan("1.2.3.4")
        assert services == []
        assert "no results" in error

    async def test_probe_services_wraps_result(self):
        with patch("app.services.scanner.run_service_scan", return_value=([{"port": 80}], None)):
            result = await probe_services("1.2.3.4")
        assert result == {"ok": True, "error": None, "services": [{"port": 80}]}

    async def test_probe_services_never_raises(self):
        with patch("app.services.scanner.run_service_scan", side_effect=RuntimeError("boom")):
            result = await probe_services("1.2.3.4")
        assert result["ok"] is False
        assert "boom" in result["error"]
        assert result["services"] == []


class TestSweepResponderHosts:
    async def test_rows_from_arp_scan(self):
        with patch(
            "app.services.scanner.run_arp_scan",
            return_value=(None, "192.168.86.9  aa:bb:cc:dd:ee:ff  VENDOR\n", None),
        ):
            rows, error = await sweep_responder_hosts()
        assert error is None
        assert rows == [
            {
                "ip": "192.168.86.9",
                "mac": "aa:bb:cc:dd:ee:ff",
                "detail": "VENDOR",
                "hostname": None,
            }
        ]

    async def test_scapy_fallback_when_arp_scan_fails(self):
        with patch(
            "app.services.scanner.run_arp_scan",
            return_value=(None, "", "arp-scan binary not found"),
        ), patch(
            "app.services.scanner.run_scapy_scan",
            return_value=(None, "10.0.0.5  11:22:33:44:55:66  (via 10.0.0.0/24)\n", None),
        ) as mock_scapy:
            rows, error = await sweep_responder_hosts()
        assert mock_scapy.called
        assert error is None
        assert rows[0]["mac"] == "11:22:33:44:55:66"

    async def test_arp_scan_output_wins_over_fallback(self):
        with patch(
            "app.services.scanner.run_arp_scan",
            return_value=(None, "192.168.86.9  aa:bb:cc:dd:ee:ff  VENDOR\n", "partial sweep note"),
        ), patch("app.services.scanner.run_scapy_scan") as mock_scapy:
            rows, error = await sweep_responder_hosts()
        assert not mock_scapy.called  # rows exist -> no fallback needed
        assert len(rows) == 1
        assert error == "partial sweep note"


class TestResolveHostname:
    async def test_live_mdns_by_ip(self):
        with patch(
            "app.services.scanner.discover_hostnames",
            new=AsyncMock(return_value=({"192.168.86.9": "vault.local"}, {})),
        ):
            assert await resolve_hostname(ip="192.168.86.9") == "vault.local"

    async def test_mac_maps_first(self):
        with patch(
            "app.services.scanner.discover_hostnames",
            new=AsyncMock(return_value=({"192.168.86.9": "other"}, {"aa:bb:cc:dd:ee:ff": "vault.local"})),
        ):
            name = await resolve_hostname(ip="192.168.86.9", mac="AA:BB:CC:DD:EE:FF")
        assert name == "vault.local"

    async def test_reverse_dns_last_resort(self):
        with patch(
            "app.services.scanner.discover_hostnames",
            new=AsyncMock(return_value=({}, {})),
        ), patch("socket.gethostbyaddr", return_value=("vault.example.com", [], ["192.168.86.9"])):
            assert await resolve_hostname(ip="192.168.86.9") == "vault.example.com"

    async def test_no_inputs_no_name(self):
        with patch(
            "app.services.scanner.discover_hostnames",
            new=AsyncMock(return_value=({}, {})),
        ), patch("socket.gethostbyaddr", side_effect=OSError):
            assert await resolve_hostname() is None
            assert await resolve_hostname(ip="") is None


class TestValidateHostRecord:
    def _rows(self):
        return [
            {"ip": "192.168.86.9", "mac": "aa:bb:cc:dd:ee:ff", "detail": "VENDOR"},
            {"ip": "192.168.86.20", "mac": None, "detail": "(routed via L3, nmap -sn)"},
        ]

    def _service(self, port=80):
        return {"port": port, "protocol": "tcp", "state": "open", "service": "http"}

    def _patches(self, rows):
        return (
            patch(
                "app.services.scanner.sweep_responder_hosts",
                new=AsyncMock(return_value=(rows, None)),
            ),
            patch(
                "app.services.scanner.discover_hostnames",
                new=AsyncMock(return_value=({}, {})),
            ),
            patch(
                "app.services.scanner.probe_services",
                new=AsyncMock(return_value={"ok": True, "error": None, "services": [self._service()]}),
            ),
            patch(
                "app.services.scanner.resolve_hostname",
                new=AsyncMock(return_value="vault.local"),
            ),
        )

    async def test_mac_and_ip_point_at_same_host(self):
        p1, p2, p3, p4 = self._patches(self._rows())
        with p1, p2, p3 as mock_probe, p4:
            result = await validate_host_record(
                None, name="vault", mac="AA:BB:CC:DD:EE:FF", ip="192.168.86.9", port=80
            )
        assert result["mac"]["found"] is True
        assert result["mac"]["ip"] == "192.168.86.9"
        assert result["mac"]["hostname"] == "vault.local"
        assert result["ip"]["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["ip"]["mac_routed"] is False
        assert result["ip"]["hostname"] == "vault.local"
        assert result["ip"]["port_state"] == "open"
        assert result["sweep"]["responders"] == 2
        assert mock_probe.call_count == 1  # one distinct IP -> one nmap run

    async def test_mac_at_a_different_ip_probes_both(self):
        p1, p2, p3, p4 = self._patches(self._rows())
        with p1, p2, p3 as mock_probe, p4:
            result = await validate_host_record(
                None, name="vault", mac="aa:bb:cc:dd:ee:ff", ip="192.168.86.20", port=80
            )
        assert result["mac"]["found"] is True
        assert result["mac"]["ip"] == "192.168.86.9"
        # the entered IP is the routed one: no locally visible MAC
        assert result["ip"]["mac"] is None
        assert result["ip"]["mac_routed"] is True
        assert mock_probe.call_count == 2  # two distinct IPs

    async def test_mac_not_found(self):
        p1, p2, p3, p4 = self._patches(self._rows())
        with p1, p2, p3, p4:
            result = await validate_host_record(
                None, name="vault", mac="de:ad:be:ef:00:01", ip="10.99.99.1", port=80
            )
        assert result["mac"]["found"] is False
        assert result["mac"]["ip"] is None
        assert result["mac"]["services"] == []
        assert result["ip"]["mac"] is None
        # the (mocked) probe reports http open on the host port
        assert result["ip"]["port_state"] == "open"

    async def test_missing_mac_section_when_not_given(self):
        p1, p2, p3, p4 = self._patches(self._rows())
        with p1, p2, p3, p4:
            result = await validate_host_record(
                None, name="vault", mac="", ip="192.168.86.9", port=80
            )
        assert result["mac"] is None
        assert result["ip"] is not None
        assert result["ip"]["mac"] == "aa:bb:cc:dd:ee:ff"


class TestParseNmapServicesByHost:
    def test_groups_by_host(self):
        doc = (
            "<nmaprun>"
            "<host><address addr=\"10.0.0.5\" addrtype=\"ipv4\"/><ports>"
            "<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\"/></port>"
            "<port protocol=\"tcp\" portid=\"443\"><state state=\"open\"/><service name=\"https\"/></port>"
            "</ports></host>"
            "<host><address addr=\"10.0.0.7\" addrtype=\"ipv4\"/><ports>"
            "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/><service name=\"ssh\"/></port>"
            "</ports></host>"
            "</nmaprun>"
        )
        out = parse_nmap_services_by_host(doc)
        assert set(out) == {"10.0.0.5", "10.0.0.7"}
        assert {p["port"] for p in out["10.0.0.5"]} == {80, 443}
        assert {p["service"] for p in out["10.0.0.5"]} == {"http", "https"}
        assert out["10.0.0.7"][0]["service"] == "ssh"

    def test_skips_host_with_no_ports(self):
        doc = (
            "<nmaprun>"
            "<host><address addr=\"10.0.0.5\" addrtype=\"ipv4\"/><ports></ports></host>"
            "</nmaprun>"
        )
        assert parse_nmap_services_by_host(doc) == {}

    def test_empty_and_bad(self):
        assert parse_nmap_services_by_host("") == {}
        assert parse_nmap_services_by_host("not xml at all") == {}


class TestRunPortScan:
    def test_no_hosts_is_noop(self):
        assert run_port_scan([]) == ({}, None)

    def test_nmap_missing_reports_error(self):
        with patch("app.services.scanner.subprocess.run", side_effect=FileNotFoundError):
            out, err = run_port_scan(["10.0.0.5"])
        assert out == {}
        assert "not installed" in err

    def test_happy_path_scans_all_ports(self):
        doc = (
            "<nmaprun><host><address addr=\"10.0.0.5\" addrtype=\"ipv4\"/><ports>"
            "<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/><service name=\"http\"/></port>"
            "</ports></host></nmaprun>"
        )

        def fake_run(cmd, **_kw):
            if cmd[:2] == ["nmap", "-V"]:
                return _FakeProc("", code=0)
            assert "-p-" in cmd and "-oX" in cmd and "-sT" in cmd and "-sV" in cmd
            return _FakeProc(doc, code=0)

        with patch("app.services.scanner.subprocess.run", side_effect=fake_run):
            out, err = run_port_scan(["10.0.0.5"], timeout=10)
        assert err is None
        assert out["10.0.0.5"][0]["port"] == 80
        assert out["10.0.0.5"][0]["service"] == "http"


class TestRunScanPorts:
    async def test_scan_ports_attaches_open_ports(self):
        table = "192.168.86.5  aa:bb:cc:dd:ee:ff  VMWARE\n"
        with patch("app.services.scanner.run_arp_scan", return_value=(None, table, None)), \
             patch("app.services.scanner.resolve_hostnames",
                   new=AsyncMock(side_effect=lambda hosts, **_kw: hosts)), \
             patch("app.services.scanner.run_port_scan",
                   new=MagicMock(
                       return_value=(
                           {"192.168.86.5": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}]},
                           None,
                       )
                   )):
            result = await run_scan("", "arp-scan", scan_ports=True)
        assert result["found_ip"] is None
        assert result["hosts"][0]["ip"] == "192.168.86.5"
        assert result["hosts"][0]["ports"][0]["port"] == 80
        assert "ports_error" not in result

    async def test_scan_ports_error_is_reported(self):
        table = "192.168.86.5  aa:bb:cc:dd:ee:ff  VMWARE\n"
        with patch("app.services.scanner.run_arp_scan", return_value=(None, table, None)), \
             patch("app.services.scanner.resolve_hostnames",
                   new=AsyncMock(side_effect=lambda hosts, **_kw: hosts)), \
             patch("app.services.scanner.run_port_scan",
                   new=MagicMock(
                       return_value=({}, "nmap is not installed; open ports could not be scanned.")
                   )):
            result = await run_scan("", "arp-scan", scan_ports=True)
        assert result["hosts"][0]["ports"] == []
        assert "nmap is not installed" in result["ports_error"]

    async def test_empty_mac_target_is_plain_sweep(self):
        table = "192.168.86.5  aa:bb:cc:dd:ee:ff  VMWARE\n"
        with patch("app.services.scanner.run_arp_scan", return_value=(None, table, None)), \
             patch("app.services.scanner.resolve_hostnames",
                   new=AsyncMock(side_effect=lambda hosts, **_kw: hosts)):
            result = await run_scan("", "arp-scan")
        assert result["found_ip"] is None
        assert result["found_via"] is None
        assert result["error"] is None
        assert len(result["hosts"]) == 1
        assert "ports" not in result["hosts"][0]  # no port scan requested


class TestRunPortScanIncremental:
    """Tests for the incremental (host-by-host) port scanner."""

    async def test_calls_callback_per_host(self):
        """Each host's result is passed to the callback as it finishes."""
        calls = []
        host_idx = [0]  # mutable counter for per-host output

        async def cb(data):
            calls.append(data.copy())

        def fake_subprocess(cmd, **kw):
            if cmd[0] == "nmap" and "-V" in cmd:
                return MagicMock(returncode=0, stdout="nmap 7.94")
            # Per-host XML output — note the addrtype='ipv4' required by parser
            ips = ["10.0.0.1", "10.0.0.2"]
            ports = [22, 80]
            idx = min(host_idx[0], len(ips) - 1)
            host_idx[0] += 1
            return MagicMock(returncode=0, stdout=f"""<?xml version="1.0"?>
<nmaprun>
  <host><address addr="{ips[idx]}" addrtype="ipv4"/><status state="up"/>
    <ports><port protocol="tcp" portid="{ports[idx]}"><state state="open"/></port></ports>
  </host>
</nmaprun>""")

        with patch("subprocess.run", side_effect=fake_subprocess):
            result, err = await run_port_scan_incremental(
                ["10.0.0.1", "10.0.0.2"], callback=cb
            )

        assert len(calls) == 2
        assert calls[0]["_index"] == 0
        assert calls[0]["_total"] == 2
        assert calls[1]["_index"] == 1
        assert calls[1]["_total"] == 2
        assert result["10.0.0.1"][0]["port"] == 22
        assert result["10.0.0.2"][0]["port"] == 80

    async def test_empty_host_list_returns_empty(self):
        """No hosts means no nmap invocation."""
        def fake_subprocess(cmd, **kw):
            if cmd[0] == "nmap" and "-V" in cmd:
                return MagicMock(returncode=0, stdout="nmap 7.94")
            return MagicMock(returncode=0, stdout="")

        with patch("subprocess.run", side_effect=fake_subprocess):
            result, err = await run_port_scan_incremental([])
        assert result == {}
        assert err is None

    async def test_port_scan_does_not_block_event_loop(self):
        """The per-host nmap must run off the event-loop thread: while a
        (slow) host scan is in flight, the loop must stay responsive so the
        /api/diagnostic/scan-progress endpoint keeps answering.  A bare
        subprocess.run on the loop thread would freeze the whole app."""
        import time as _time

        calls = []

        async def cb(data):
            calls.append(data.copy())

        def fake_subprocess(cmd, **kw):
            if cmd[0] == "nmap" and "-V" in cmd:
                return MagicMock(returncode=0, stdout="nmap 7.94")
            _time.sleep(0.3)  # simulate a slow per-host service scan
            return MagicMock(returncode=0, stdout="")

        async def _heartbeat():
            # Yield control on the loop; if the port scan blocked the loop,
            # this would not run until the scan finished.
            await asyncio.sleep(0)
            return _time.monotonic()

        with patch("subprocess.run", side_effect=fake_subprocess):
            scan_task = asyncio.create_task(
                run_port_scan_incremental(["10.0.0.1"], callback=cb)
            )
            # Give the scan a head start (it should be mid-first-host-scan).
            await asyncio.sleep(0.1)
            hb_start = await _heartbeat()
            # The heartbeat must have returned quickly (the loop is free).
            assert _time.monotonic() - hb_start < 0.2
            result, err = await scan_task

        assert err is None
        assert result == {}
        assert len(calls) == 1
        assert calls[0]["_index"] == 0

