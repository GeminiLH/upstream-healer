"""
LAN scanner – finds devices by MAC address.
Uses arp-scan when available, falls back to scapy.
Designed to be quiet on Windows (local development).
"""
from __future__ import annotations

import asyncio
import ipaddress
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


async def find_ip_by_mac(target_mac: str, interface: Optional[str] = None, subnets: Optional[list[str]] = None) -> Optional[str]:
    """
    Search the local network for a device with the given MAC.
    Returns the IP address if found, else None.

    ``subnets`` optionally scopes the scan to specific CIDRs (e.g. the subnet
    a host is pinned to).  When ``None``, the scanner uses its default target —
    the primary interface's /24 — which is the historic behaviour.
    """
    target_mac = normalize_mac(target_mac)
    logger.info(f"Scanning for MAC {target_mac}" + (f" (subnets={subnets})" if subnets else ""))

    # Try arp-scan first (fast and reliable on Linux)
    ip = await _scan_with_arp_scan(target_mac, subnets=subnets)
    if ip:
        return ip

    # Fallback to scapy (mainly useful on Linux)
    ip = await _scan_with_scapy(target_mac, interface, subnets=subnets)
    return ip


async def run_scan(
    target_mac: str,
    method: str = "arp-scan",
    interface: Optional[str] = None,
    subnets: Optional[list[str]] = None,
) -> dict:
    """Run one scanner and return a JSON-ready dict for the diagnostic UI.

    The scanner work is dispatched to a thread pool (``run_in_executor``) so the
    long ``arp-scan``/scapy run never blocks the event loop. ``method`` selects
    the scanner; ``"auto"`` is not valid here — ``find_ip_by_mac`` owns that
    fallback logic and returns a single IP rather than raw output.

    ``subnets`` optionally restricts the scan to the given CIDRs; when ``None``
    the scanner targets its default (the primary interface's /24).

    Returns ``{"method", "found_ip", "found_via", "output", "error"}`` where
    ``found_via`` names the scanner that actually produced the answer.
    """
    target_mac = normalize_mac(target_mac)
    method = (method or "arp-scan").strip().lower()
    loop = asyncio.get_running_loop()

    if method == "scapy":
        found_ip, output, error = await loop.run_in_executor(
            None, lambda: run_scapy_scan(target_mac, interface, subnets=subnets)
        )
    else:  # "arp-scan" (the only other method we ship)
        found_ip, output, error = await loop.run_in_executor(
            None, lambda: run_arp_scan(subnets=subnets)
        )
        if not error:
            found_ip = _match_mac_in_output(target_mac, output, subnets=subnets)

    return {
        "method": method,
        "found_ip": found_ip,
        "found_via": method if found_ip else None,
        "output": output,
        "error": error,
    }


def _match_mac_in_output(target_mac: str, output: str, subnets: Optional[list[str]] = None) -> Optional[str]:
    """Return the IP for ``target_mac`` in an arp-scan table, or ``None``.

    When ``subnets`` is given, only responders whose IP falls inside one of the
    CIDRs are considered — this keeps a multi-subnet sweep from matching a
    device with the same MAC on a different network.
    """
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2 and normalize_mac(parts[1]) == target_mac:
            if subnets is None or ip_in_subnets(parts[0], subnets):
                return parts[0]
    return None


def run_arp_scan(subnets: Optional[list[str]] = None) -> tuple[Optional[str], str, Optional[str]]:
    """Run ``arp-scan -l`` and report the raw table.

    Returns ``(found_ip, raw_output, error)`` where ``found_ip`` is ``None``
    (there is no single "the" target for a full list) and ``raw_output`` is the
    combined stdout/stderr. ``error`` is set only when the binary is missing or
    the process fails to run. Cheap, synchronous: wraps the subprocess call so
    a test can drive it from a thread pool or a TestClient without an event
    loop of its own.

    ``subnets`` (a list of CIDRs) optionally constrains the sweep to specific
    local networks via ``-i``.  For each subnet we look up the local interface
    that owns it (via :func:`get_local_ip_for_network` + :func:`get_default_subnets`);
    if a subnet has no local interface we skip it with a note in the output.
    When ``subnets`` is ``None`` we keep the historic ``-l`` (all interfaces).
    """
    interfaces: list[str] = []
    notes: list[str] = []
    if subnets:
        discovered = {d["cidr"]: d["interface"] for d in get_default_subnets()}
        for cidr in subnets:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                notes.append(f"(skipped unparseable subnet {cidr!r})")
                continue
            iface = discovered.get(str(network))
            if iface:
                if iface not in interfaces:
                    interfaces.append(iface)
            elif network.prefixlen >= 31:
                # A /32 (single host) or /31 (point-to-point) is not a network
                # we can ARP-sweep — it has no usable broadcast.  Say so rather
                # than the misleading "no local interface" (the interface usually
                # *is* local; the host is just a single address, not a subnet).
                notes.append(
                    f"(skipped {cidr}: single host, not an ARP-swept network — "
                    "add its /24 instead if you meant to scan the whole LAN)"
                )
            else:
                notes.append(f"(skipped {cidr}: no local interface)")

    cmd: list[str] = ["arp-scan", "-l", "-q", "--retry=3"]
    for iface in interfaces:
        cmd.extend(["-i", iface])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45,
        )
    except FileNotFoundError:
        return None, "", "arp-scan binary not found"
    except Exception as exc:  # noqa: BLE001
        return None, "", f"arp-scan failed: {exc}"
    output = (proc.stdout or "") + (proc.stderr or "")
    if notes:
        output = "\n".join(notes) + ("\n" + output if output.strip() else "")
    if not output.strip():
        output = "(arp-scan produced no output)"
    return None, output, None


def run_scapy_scan(
    target_mac: str,
    interface: Optional[str] = None,
    subnets: Optional[list[str]] = None,
) -> tuple[Optional[str], str, Optional[str]]:
    """ARP-sweep with scapy and find ``target_mac``.

    Sweeps ``subnets`` (a list of CIDRs) one at a time.  When ``subnets`` is
    ``None`` or empty, falls back to the historic behaviour: derive the local
    /24 from the primary IP and sweep that.  Returns
    ``(found_ip, raw_output, error)`` where ``raw_output`` lists every
    responder (IP -> MAC) so the diagnostic UI can show the full sweep.
    Importing scapy is deferred so that a machine without it (e.g. Windows dev)
    still works — ``error`` is set in that case rather than raising.
    """
    try:
        from scapy.all import ARP, Ether, srp, conf  # type: ignore
    except ImportError:
        return None, "", "scapy library not installed"

    target_mac = normalize_mac(target_mac)

    # Determine the set of CIDRs to sweep.  An explicit `subnets` list wins;
    # otherwise fall back to the local /24 (historic behaviour).
    networks: list[str] = []
    for s in (subnets or []):
        s = (s or "").strip()
        if not s:
            continue
        try:
            networks.append(str(ipaddress.ip_network(s, strict=False)))
        except ValueError:
            logger.warning(f"scapy: ignoring unparseable subnet {s!r}")
    if not networks:
        local_ip = _get_primary_ip()
        if not local_ip:
            return None, "", "could not determine local IP"
        networks.append(".".join(local_ip.split(".")[:3]) + ".0/24")

    try:
        conf.verb = 0
        # An explicit `interface` (from run_scan / a manual subnet pin) wins.
        # Deliberately NOT assigned to conf.iface here: setting the global is a
        # known scapy footgun — it leaves `conf.route.default_iface` unset, and
        # when scapy resolves a target it then does int("enp6s0"), which raises
        # ValueError and aborts the whole sweep.  Passing `iface=` per-packet
        # keeps the default resolution path intact, so a full-table sweep still
        # works even when no per-network interface matches.
        found_ip: Optional[str] = None
        lines: list[str] = []
        for network in networks:
            # Per-network egress: pick the local interface that owns this
            # network (so the sweep goes out the right NIC on multi-homed
            # boxes).  `None` lets scapy fall back to its default interface.
            egress: Optional[str] = interface
            if not egress:
                local_ip = get_local_ip_for_network(network)
                if local_ip:
                    ifaces = conf.get_if_addresses()
                    for if_name, if_ips in ifaces.items():
                        if local_ip in if_ips:
                            egress = if_name
                            break

            try:
                if egress:
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                        iface=egress, timeout=3, retry=2, verbose=0,
                    )
                else:
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                        timeout=3, retry=2, verbose=0,
                    )
            except Exception as exc:  # noqa: BLE001 - per-network isolation
                logger.warning(f"scapy: sweep of {network} failed ({exc})")
                continue

            for _, received in ans:
                mac = normalize_mac(received.hwsrc)
                ip = received.psrc
                lines.append(f"{ip}  {mac}  (via {network})")
                if mac == target_mac and found_ip is None:
                    found_ip = ip

        if found_ip:
            logger.info(f"Found {target_mac} at {found_ip} via scapy")
        output = "\n".join(lines) if lines else "(no ARP responses received)"
        return found_ip, output, None
    except Exception as exc:  # noqa: BLE001
        return None, "", f"scapy scan failed: {exc}"


async def _scan_with_arp_scan(target_mac: str, subnets: Optional[list[str]] = None) -> Optional[str]:
    """Find a single MAC via ``arp-scan`` (async wrapper over :func:`run_arp_scan`).

    ``subnets`` optionally scopes the sweep to specific CIDRs; ``None`` keeps the
    historic all-interfaces behaviour.
    """
    target_mac = normalize_mac(target_mac)

    def _work() -> Optional[str]:
        _, output, error = run_arp_scan(subnets=subnets)
        if error:
            return None
        for line in output.splitlines():
            # Typical line: 192.168.86.23  aa:bb:cc:dd:ee:ff  Some Vendor
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = normalize_mac(parts[1])
                if mac == target_mac and (subnets is None or ip_in_subnets(ip, subnets)):
                    logger.info(f"Found {target_mac} at {ip} via arp-scan")
                    return ip
        return None

    return await asyncio.get_running_loop().run_in_executor(None, _work)


async def _scan_with_scapy(target_mac: str, interface: Optional[str] = None, subnets: Optional[list[str]] = None) -> Optional[str]:
    """Find a single MAC via scapy (async wrapper over :func:`run_scapy_scan`)."""
    found_ip, _, _ = run_scapy_scan(target_mac, interface, subnets=subnets)
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


def ip_in_subnets(ip: str, subnets: list[str]) -> bool:
    """Return ``True`` if ``ip`` falls inside any of the given CIDRs.

    Used to scope the ``arp-scan`` output (which always enumerates every local
    network) to just the subnets the caller asked about.  Invalid/blank entries
    are ignored.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in subnets:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def get_local_ip_for_network(cidr: str) -> Optional[str]:
    """Return the local IPv4 src address the kernel uses to reach ``cidr``.

    Resolves via ``ip route get <network-address>`` — the most reliable signal
    for "which local interface would we use to talk to this network?".  Returns
    ``None`` when no route exists or ``ip`` is unavailable.  Used to pick the
    right scapy egress interface for a given subnet.
    """
    cidr = (cidr or "").strip()
    if not cidr:
        return None
    try:
        base = ipaddress.ip_network(cidr, strict=False).network_address
        result = subprocess.run(
            ["ip", "-4", "route", "get", str(base)],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
        if match:
            return match.group(1)
    except Exception:  # noqa: BLE001 - best-effort helper
        pass
    return None


def get_default_subnets() -> list[dict]:
    """Auto-discover locally-attached IPv4 /24 networks.

    Reads ``ip -4 addr`` and returns ``[{cidr, interface, source: "auto"}]`` for
    every primary address of prefix length 24.  Loops out ``127.0.0.0/8`` and
    other non-/24 prefixes (bridges, VPNs, etc.) — those should be added
    explicitly via the ``subnets`` table if needed.  Used as the fallback subnet
    list for monitor recovery and diagnostics when no explicit subnet is set.
    """
    import re as _re

    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:  # noqa: BLE001
        return []

    found: list[dict] = []
    seen_cidrs: set[str] = set()
    for line in (result.stdout or "").splitlines():
        if not line:
            continue
        # typical line: "2: enp6s0    inet 192.168.86.38/24 scope global enp6s0"
        match = _re.match(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/24\b", line)
        if not match:
            continue
        iface, addr = match.group(1), match.group(2)
        if iface == "lo" or addr.startswith("127."):
            continue
        try:
            cidr = str(ipaddress.ip_network(f"{addr}/24", strict=False))
        except ValueError:
            continue
        if cidr in seen_cidrs:
            continue
        seen_cidrs.add(cidr)
        found.append({"cidr": cidr, "interface": iface, "source": "auto"})
    return found


async def list_subnets(db=None) -> list[dict]:
    """Return the effective list of subnets to scan.

    Merges enabled rows from the ``subnets`` table (when ``db`` is given) with
    the auto-discovered local networks from :func:`get_default_subnets`.  Manual
    rows win for a given CIDR (their name/interface is preferred); auto rows fill
    in the rest.  Order: enabled manual rows first, then auto rows.  Called once
    per scan so a newly-plugged-in interface is picked up without a restart.
    """
    manual: list[dict] = []
    if db is not None:
        try:
            async with db.execute(
                "SELECT id, name, cidr, interface FROM subnets WHERE enabled = 1"
            ) as cursor:
                for row in await cursor.fetchall():
                    manual.append({
                        "id": row["id"], "name": row["name"], "cidr": row["cidr"],
                        "interface": row["interface"], "source": "manual",
                    })
        except Exception:  # noqa: BLE001 - a missing table etc. shouldn't abort a scan
            logger.exception("list_subnets: could not read subnets table")

    auto = get_default_subnets()
    seen = {m["cidr"] for m in manual}
    for a in auto:
        if a["cidr"] not in seen:
            manual.append(a)
            seen.add(a["cidr"])
    return manual


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