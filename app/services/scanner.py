"""
LAN scanner – finds devices by MAC address.
Uses arp-scan when available, falls back to scapy.
Designed to be quiet on Windows (local development).
"""
from __future__ import annotations

import asyncio
import logging
import re
import subprocess
from typing import Optional

logger = logging.getLogger("healer.scanner")


def normalize_mac(mac: str) -> str:
    """Normalize MAC to lowercase with colons."""
    mac = mac.lower().strip()
    mac = mac.replace("-", ":").replace(".", ":")
    # Handle formats like aabbccddeeff
    if re.match(r"^[0-9a-f]{12}$", mac):
        mac = ":".join(mac[i : i + 2] for i in range(0, 12, 2))
    return mac


async def find_ip_by_mac(target_mac: str, interface: Optional[str] = None) -> Optional[str]:
    """
    Search the local network for a device with the given MAC.
    Returns the IP address if found, else None.
    """
    target_mac = normalize_mac(target_mac)
    logger.info(f"Scanning for MAC {target_mac}")

    # Try arp-scan first (fast and reliable on Linux)
    ip = await _scan_with_arp_scan(target_mac)
    if ip:
        return ip

    # Fallback to scapy (mainly useful on Linux)
    ip = await _scan_with_scapy(target_mac, interface)
    return ip


async def run_scan(
    target_mac: str,
    method: str = "arp-scan",
    interface: Optional[str] = None,
) -> dict:
    """Run one scanner and return a JSON-ready dict for the diagnostic UI.

    The scanner work is dispatched to a thread pool (``run_in_executor``) so the
    long ``arp-scan``/scapy run never blocks the event loop. ``method`` selects
    the scanner; ``"auto"`` is not valid here — ``find_ip_by_mac`` owns that
    fallback logic and returns a single IP rather than raw output.

    Returns ``{"method", "found_ip", "found_via", "output", "error"}`` where
    ``found_via`` names the scanner that actually produced the answer.
    """
    target_mac = normalize_mac(target_mac)
    method = (method or "arp-scan").strip().lower()
    loop = asyncio.get_running_loop()

    if method == "scapy":
        found_ip, output, error = await loop.run_in_executor(
            None, lambda: run_scapy_scan(target_mac, interface)
        )
    else:  # "arp-scan" (the only other method we ship)
        found_ip, output, error = await loop.run_in_executor(None, run_arp_scan)
        if not error:
            found_ip = _match_mac_in_output(target_mac, output)

    return {
        "method": method,
        "found_ip": found_ip,
        "found_via": method if found_ip else None,
        "output": output,
        "error": error,
    }


def _match_mac_in_output(target_mac: str, output: str) -> Optional[str]:
    """Return the IP for ``target_mac`` in an arp-scan table, or ``None``."""
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and normalize_mac(parts[1]) == target_mac:
            return parts[0]
    return None


def run_arp_scan() -> tuple[Optional[str], str, Optional[str]]:
    """Run ``arp-scan -l`` and report the raw table.

    Returns ``(found_ip, raw_output, error)`` where ``found_ip`` is ``None``
    (there is no single "the" target for a full list) and ``raw_output`` is the
    combined stdout/stderr. ``error`` is set only when the binary is missing or
    the process fails to run. Cheap, synchronous: wraps the subprocess call so
    a test can drive it from a thread pool or a TestClient without an event
    loop of its own.
    """
    try:
        proc = subprocess.run(
            ["arp-scan", "-l", "-q", "--retry=3"],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except FileNotFoundError:
        return None, "", "arp-scan binary not found"
    except Exception as exc:  # noqa: BLE001
        return None, "", f"arp-scan failed: {exc}"
    output = (proc.stdout or "") + (proc.stderr or "")
    if not output.strip():
        output = "(arp-scan produced no output)"
    return None, output, None


def run_scapy_scan(target_mac: str, interface: Optional[str] = None) -> tuple[Optional[str], str, Optional[str]]:
    """ARP-sweep the local /24 with scapy and find ``target_mac``.

    Returns ``(found_ip, raw_output, error)``. ``raw_output`` lists every
    responder (IP -> MAC) so the diagnostic UI can show the full sweep, not just
    whether the target was present. Importing scapy is deferred so that a
    machine without it (e.g. Windows dev) still works — ``error`` is set in that
    case rather than raising.
    """
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
    except ImportError:
        return None, "", "scapy library not installed"

    try:
        conf.verb = 0
        if interface:
            conf.iface = interface

        local_ip = _get_primary_ip()
        if not local_ip:
            return None, "", "could not determine local IP"

        target_mac = normalize_mac(target_mac)
        network = ".".join(local_ip.split(".")[:3]) + ".0/24"
        logger.info(f"Scapy scanning {network} for {target_mac}")

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=3,
            retry=2,
            verbose=0,
        )

        found_ip: Optional[str] = None
        lines = []
        for _, received in ans:
            mac = normalize_mac(received.hwsrc)
            ip = received.psrc
            lines.append(f"{ip}  {mac}")
            if mac == target_mac:
                found_ip = ip

        if found_ip:
            logger.info(f"Found {target_mac} at {found_ip} via scapy")
        output = "\n".join(lines) if lines else "(no ARP responses received)"
        return found_ip, output, None
    except Exception as exc:  # noqa: BLE001
        return None, "", f"scapy scan failed: {exc}"


async def _scan_with_arp_scan(target_mac: str) -> Optional[str]:
    """Find a single MAC via ``arp-scan`` (async wrapper over :func:`run_arp_scan`)."""
    target_mac = normalize_mac(target_mac)

    def _work() -> Optional[str]:
        _, output, error = run_arp_scan()
        if error:
            return None
        for line in output.splitlines():
            # Typical line: 192.168.86.23  aa:bb:cc:dd:ee:ff  Some Vendor
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = normalize_mac(parts[1])
                if mac == target_mac:
                    logger.info(f"Found {target_mac} at {ip} via arp-scan")
                    return ip
        return None

    return await asyncio.get_running_loop().run_in_executor(None, _work)


async def _scan_with_scapy(target_mac: str, interface: Optional[str] = None) -> Optional[str]:
    """Find a single MAC via scapy (async wrapper over :func:`run_scapy_scan`)."""
    found_ip, _, _ = run_scapy_scan(target_mac, interface)
    return found_ip


def _get_primary_ip() -> Optional[str]:
    """Best-effort way to get the primary local IPv4 address."""
    # Linux
    try:
        result = subprocess.run(
            ["ip", "-4", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    # Fallback for Windows / other systems
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass

    return None


async def check_host_reachable(ip: str, port: int = 80, timeout: float = 3.0) -> bool:
    """Simple TCP connect check."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False