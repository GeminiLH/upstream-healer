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


async def _scan_with_arp_scan(target_mac: str) -> Optional[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "arp-scan",
            "-l",
            "-q",
            "--retry=3",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
        output = stdout.decode(errors="ignore")

        for line in output.splitlines():
            # Typical line: 192.168.86.23  aa:bb:cc:dd:ee:ff  Some Vendor
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = normalize_mac(parts[1])
                if mac == target_mac:
                    logger.info(f"Found {target_mac} at {ip} via arp-scan")
                    return ip
    except FileNotFoundError:
        logger.debug("arp-scan not found, falling back to scapy")
    except Exception as e:
        logger.warning(f"arp-scan failed: {e}")
    return None


async def _scan_with_scapy(target_mac: str, interface: Optional[str] = None) -> Optional[str]:
    try:
        # Import scapy only when needed (avoids Windows noise at startup)
        from scapy.all import ARP, Ether, srp, conf  # type: ignore

        conf.verb = 0
        if interface:
            conf.iface = interface

        local_ip = _get_primary_ip()
        if not local_ip:
            logger.error("Could not determine local IP")
            return None

        network = ".".join(local_ip.split(".")[:3]) + ".0/24"
        logger.info(f"Scapy scanning {network}")

        def _do_scan() -> Optional[str]:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                timeout=3,
                retry=2,
                verbose=0,
            )
            for _, received in ans:
                if normalize_mac(received.hwsrc) == target_mac:
                    return received.psrc
            return None

        ip = await asyncio.get_event_loop().run_in_executor(None, _do_scan)
        if ip:
            logger.info(f"Found {target_mac} at {ip} via scapy")
        return ip
    except ImportError:
        logger.debug("scapy not available")
        return None
    except Exception as e:
        logger.error(f"Scapy scan failed: {e}")
        return None


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