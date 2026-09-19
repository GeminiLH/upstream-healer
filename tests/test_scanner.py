"""Tests for app.services.scanner — MAC normalization and reachability."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.services.scanner import (
    _parse_scan_output,
    apply_hostnames,
    check_host_reachable,
    find_ip_by_mac,
    get_default_subnets,
    get_local_interfaces,
    get_local_ip_for_network,
    ip_in_subnets,
    list_subnets,
    load_known_hostnames,
    load_suppressed_subnets,
    normalize_mac,
    resolve_hostnames,
    run_arp_scan,
    run_scan,
    run_scapy_scan,
    save_suppressed_subnets,
)


class _FakeProc:
    """Stand-in for a ``subprocess.run`` result: ``stdout`` / ``stderr`` only.

    Defined up front because the scan tests below patch ``subprocess.run`` and
    need it; sweep command assertions read ``mock_run.call_args_list``.
    """

    def __init__(self, stdout, stderr=""):
        self.stdout = stdout
        self.stderr = stderr


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
        assert mock_run.call_args[0][0] == ["arp-scan", "-q", "--retry=3", "-i", "eth1", "10.0.0.0/24"]

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
        assert mock_run.call_args[0][0] == ["arp-scan", "-q", "--retry=3", "-i", "eth1", "10.0.0.0/24"]

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
        with patch(
            "app.services.scanner.get_default_subnets",
            return_value=[
                {"cidr": "10.0.0.0/24", "interface": "eth1", "source": "auto"},
                {"cidr": "10.1.0.0/24", "interface": "eth1", "source": "auto"},
            ],
        ),              patch("app.services.scanner.subprocess.run", return_value=_FakeProc(out)) as mock_run:
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
        import types

        calls = []

        def fake(addr):
            calls.append(addr)
            return types.SimpleNamespace(hostname="box.lan", aliases=[], ipaddr_list=[addr])

        with patch("socket.gethostbyaddr", side_effect=fake):
            got = await resolve_hostnames([{"ip": "10.0.0.5", "mac": "aa"}])
        assert got[0]["hostname"] == "box.lan"
        assert calls == ["10.0.0.5"]

    async def test_lookup_failure_leaves_none(self):
        import socket

        with patch("socket.gethostbyaddr", side_effect=socket.gaierror("nope")):
            got = await resolve_hostnames([{"ip": "10.0.0.5", "mac": "aa"}])
        assert got[0]["hostname"] is None


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


class TestApplyHostnames:
    def test_known_name_wins_over_mdns_and_ptr(self):
        hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "ptr-name"}]
        mdns = ({"10.0.0.5": "mdns-by-ip"}, {"aa:bb:cc:dd:ee:ff": "mdns-by-mac"})
        out = apply_hostnames(hosts, mdns=mdns, known={"aa:bb:cc:dd:ee:ff": "vault"})
        assert out[0]["hostname"] == "vault"

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

