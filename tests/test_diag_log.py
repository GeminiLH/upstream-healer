"""Tests for the opt-in diagnostic debug logging (``app/services/diag_log``).

Covers the safety contract: disabled by default, production tripwire,
self-identity + self-target detection in the header, size cap, rotation,
never-raises behaviour, and the scanner wiring (a mocked sweep still lands
in the per-scan file).
"""
from __future__ import annotations

import time
from unittest import mock

import pytest

from app.services import diag_log
from app.services.scanner import _run_sweeps, run_scan


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", raising=False)
    monkeypatch.delenv("UPSTREAM_HEALER_ENV", raising=False)
    monkeypatch.delenv("UPSTREAM_HEALER_DEBUG_MAX_BYTES", raising=False)
    monkeypatch.delenv("UPSTREAM_HEALER_DEBUG_KEEP", raising=False)
    yield


def test_disabled_by_default():
    assert diag_log.log_dir() is None
    assert diag_log.enabled() is False
    # Every helper is a silent no-op:
    diag_log.emit("x", "y")
    diag_log.proc("t", ["a"], None)
    diag_log.exc("t", ValueError("boom"))
    diag_log.close()
    with diag_log.scan_context(target_mac="aa:bb:cc:dd:ee:ff", method="arp-scan") as log:
        assert log is None


def test_env_var_enables(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    assert diag_log.log_dir() == str(tmp_path)
    assert diag_log.enabled() is True


def test_production_tripwire(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("UPSTREAM_HEALER_ENV", "production")
    assert diag_log.log_dir() is None
    assert not diag_log.enabled()


_FAKE_IDENTITY = {
    "hostname": "testhost",
    "interfaces": {"eth0": {"mac": "aa:bb:cc:dd:ee:00", "ipv4": ["10.0.0.2/24"]}},
    "routes": "default via 10.0.0.1",
    "neighbours": None,
}
_EMPTY_IDENTITY = {"hostname": "h", "interfaces": {}, "routes": None, "neighbours": None}


def test_scan_context_writes_header_and_summary(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    with mock.patch.object(diag_log, "self_identity", return_value=_FAKE_IDENTITY):
        with diag_log.scan_context(
            target_mac="aa:bb:cc:dd:ee:01", method="arp-scan", subnets=["10.0.0.0/24"]
        ) as log:
            assert log is not None
            diag_log.emit("arp-scan", "binary not found", "cmd=arp-scan -q")
    files = list(tmp_path.glob("diag_*.log"))
    assert len(files) == 1
    text = files[0].read_text()
    assert "hostname=testhost" in text
    assert "aa:bb:cc:dd:ee:00" in text
    assert "default via 10.0.0.1" in text
    assert "target_mac=aa:bb:cc:dd:ee:01" in text
    assert "binary not found" in text
    assert "does not match any local interface MAC" in text
    assert "scan complete" in text


def test_self_target_warning(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    identity = {
        "hostname": "me",
        "interfaces": {"enp6s0": {"mac": "b4:2e:99:e9:80:fc", "ipv4": ["192.168.86.38/24"]}},
        "routes": None,
        "neighbours": None,
    }
    with mock.patch.object(diag_log, "self_identity", return_value=identity):
        with diag_log.scan_context(target_mac="B4:2E:99:E9:80:FC", method="scapy") as log:
            assert log is not None
    text = list(tmp_path.glob("diag_*.log"))[0].read_text()
    assert "TARGET IS THIS MACHINE ITSELF" in text


def test_size_cap(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_MAX_BYTES", "4096")
    with mock.patch.object(diag_log, "self_identity", return_value=_EMPTY_IDENTITY):
        with diag_log.scan_context(target_mac="aa:bb:cc:dd:ee:01", method="arp-scan"):
            diag_log.emit("big", "x" * 100_000)
            diag_log.emit("after-cap", "dropped-or-not")
    files = list(tmp_path.glob("diag_*.log"))
    text = files[0].read_text()
    assert "size cap reached" in text
    assert files[0].stat().st_size < 4096 + 2048


def test_rotation_keeps_newest(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_KEEP", "2")
    with mock.patch.object(diag_log, "self_identity", return_value=_EMPTY_IDENTITY):
        for _ in range(5):
            with diag_log.scan_context(target_mac="aa:bb:cc:dd:ee:01", method="arp-scan"):
                pass
            time.sleep(0.01)
    remaining = list(tmp_path.glob("diag_*.log"))
    assert len(remaining) == 2


def test_unwritable_dir_never_raises(tmp_path, monkeypatch):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")  # a file where the dir must be created
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(blocker / "logs"))
    with diag_log.scan_context(target_mac="aa:bb:cc:dd:ee:01", method="arp-scan") as log:
        assert log is not None  # constructed, but internally inert
        diag_log.emit("never lands", "but must not raise")


def test_snap_caps_and_flattens():
    assert diag_log._snap("a\nb") == "a \\ b"
    out = diag_log._snap("y" * 50_000, limit=100)
    assert len(out) < 1010 and "499" in out


def test_scanner_wiring_writes_to_active_log(tmp_path, monkeypatch):
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))
    fake_proc = mock.Mock(
        returncode=0, stdout="10.0.0.5  aa:bb:cc:dd:ee:00  Fake\n", stderr=""
    )
    with mock.patch.object(diag_log, "self_identity", return_value=_EMPTY_IDENTITY), \
        mock.patch("app.services.scanner.subprocess.run", return_value=fake_proc), \
        mock.patch(
            "app.services.scanner.classify_subnet",
            side_effect=lambda cidr, iface=None: {"kind": "local", "egress": "eth0"},
        ):
        with diag_log.scan_context(
            target_mac="aa:bb:cc:dd:ee:01", method="arp-scan", subnets=["10.0.0.0/24"]
        ):
            _run_sweeps([("eth0", "10.0.0.0/24")])
    files = list(tmp_path.glob("diag_*.log"))
    assert len(files) == 1
    text = files[0].read_text()
    assert "arp-scan" in text
    assert "10.0.0.0/24" in text
    assert "aa:bb:cc:dd:ee:00" in text  # raw output was captured


async def test_worker_thread_lines_land_via_dispatch(tmp_path, monkeypatch):
    """Regression: the active-scan ContextVar must reach the worker thread that
    ``run_scan`` dispatches to.

    ``run_scan`` dispatches sweeps with ``asyncio.to_thread`` (which copies the
    running context), so every ``diag_log.emit``/``proc``/``exc`` inside the sweep
    thread lands in the per-scan file.  A bare ``loop.run_in_executor`` drops the
    ContextVar on Python 3.12 (the dev image) and the worker would silently log
    *nothing* — the exact bug this guards.  Unlike
    ``test_scanner_wiring_writes_to_active_log`` (which calls ``_run_sweeps``
    directly in-thread), this drives the *real* ``run_scan`` dispatch so the
    context-propagation path is actually exercised.
    """
    monkeypatch.setenv("UPSTREAM_HEALER_DEBUG_LOG_DIR", str(tmp_path))

    def fake_run(cmd, **kwargs):
        joined = " ".join(str(c) for c in cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        if "arp-scan" in joined:
            return mock.Mock(returncode=0, stdout="10.0.0.5  aa:bb:cc:dd:ee:00  Fake\n", stderr="")
        return mock.Mock(returncode=0, stdout="", stderr="")

    with mock.patch.object(diag_log, "self_identity", return_value=_EMPTY_IDENTITY), \
        mock.patch("app.services.scanner.subprocess.run", side_effect=fake_run), \
        mock.patch(
            "app.services.scanner.classify_subnet",
            side_effect=lambda cidr, iface=None: {"kind": "local", "egress": "eth0"},
        ), \
        mock.patch("app.services.scanner.get_local_ip_for_network",
                    return_value=("10.0.0.1", "eth0")), \
        mock.patch("app.services.scanner.get_default_subnets", return_value=[]), \
        mock.patch("app.services.scanner.resolve_hostnames",
                    new=mock.AsyncMock(return_value=[])):
        with diag_log.scan_context(
            target_mac="aa:bb:cc:dd:ee:01", method="arp-scan", subnets=["10.0.0.0/24"]
        ):
            result = await run_scan("aa:bb:cc:dd:ee:01", "arp-scan", subnets=["10.0.0.0/24"])

    files = list(tmp_path.glob("diag_*.log"))
    assert len(files) == 1
    text = files[0].read_text()
    # Worker-side marker: the raw arp-scan responder captured in the sweep thread.
    assert "10.0.0.5" in text
    assert "aa:bb:cc:dd:ee:00" in text
    assert result["error"] is None
