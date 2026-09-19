"""mDNS / avahi hostname discovery.

ARP sweeps (``arp-scan``, scapy) only yield IP + MAC — they carry no hostname.
On a typical home/office LAN reverse DNS (PTR) is useless (no PTR records), so
we query **mDNS** instead (zeroconf also surfaces the SSDP-workstation subset).
Run inside the app container (host networking) this hears every device on the
reachable LAN that advertises ``.local`` service records — Apple TVs, printers,
NAS boxes, SSDP workstations, etc.

The result is a pair of best-effort maps, ``{ip: hostname}`` and
``{mac: hostname}``, that the caller merges onto the swept host list.  Every
path here degrades to empty maps rather than aborting the scan: the ``zeroconf``
import is deferred, and any failure (library missing, no multicast, a flaky
device) is swallowed.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Optional

logger = logging.getLogger("healer.mdns")

# Service types to browse.  These are the ones that actually advertise a
# human-readable hostname on a typical home/office LAN.  Kept intentionally
# modest — each is a background browser thread, and every extra one adds a
# little mDNS chatter for diminishing returns.
_SERVICE_TYPES: tuple[str, ...] = (
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_ippPrint._tcp.local.",
    "_print._tcp.local.",
    "_smb._tcp.local.",
    "_ssh._tcp.local.",
    "_workstation._tcp.local.",  # SSDP workstations (MAC embedded in the name)
    "_raspberryPi._tcp.local.",
    "_raspberry-pi._tcp.local.",
    "_plex._tcp.local.",
    "_discord._tcp.local.",
    "_googlecast._tcp.local.",
    "_pulseaudio._tcp.local.",
)

# Default mDNS listen window (seconds).  An advertising device's initial
# multicast burst lands within a couple of seconds, but devices re-announce on
# their own cadence, so a longer window lets zeroconf fire a couple of browse
# queries and catches a bigger, steadier set.  It runs concurrently with the
# (usually longer) ARP sweep, so it adds little end-to-end latency; and anything
# missed is captured by the persistent per-MAC name cache (scanner).
MDNS_DISCOVERY_TIMEOUT = 8.0

# Some devices prefix the instance name with their MAC (``0469F88FEE99@...``)
# or embed it in brackets (``flash [dc:a6:32:02:59:63]``); both let us join to
# a swept host by MAC even when the advertised IP doesn't match.
_HEX12 = re.compile(r"\b([0-9a-fA-F]{12})\b")
_MAC_COLON = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_MAC_PREFIX = re.compile(r"^([0-9a-fA-F]{12})@(.*)$")


def instance_display_name(fqdn: str) -> str:
    """The human name from a service instance FQDN.

    ``0469F88FEE99@Living Room Apple TV._raop._tcp.local.`` ->
    ``Living Room Apple TV`` (the ``<MAC>@`` prefix is stripped); a plain
    ``WDMyCloud._http._tcp.local.`` -> ``WDMyCloud``.
    """
    inst = fqdn.rstrip(".").split(".", 1)[0]
    m = _MAC_PREFIX.match(inst)
    cleaned = m.group(2).strip() if m else inst
    return cleaned or inst


def instance_mac(fqdn: str) -> Optional[str]:
    """Best-effort MAC (lowercase, colon-separated) parsed from an instance name.

    Handles both the ``<12-hex>@`` prefix and a ``aa:bb:cc:dd:ee:ff`` form.
    Returns ``None`` when no MAC is embedded.
    """
    inst = fqdn.rstrip(".").split(".", 1)[0]
    m = _MAC_PREFIX.match(inst) or _HEX12.search(inst)
    if m:
        hexs = m.group(1).lower()
    else:
        m = _MAC_COLON.search(inst)
        hexs = m.group(0).replace(":", "").lower() if m else None
    if not hexs:
        return None
    return ":".join(hexs[i : i + 2] for i in range(0, 12, 2))


def _discover_sync(timeout: float) -> tuple[dict[str, str], dict[str, str]]:
    """Blocking mDNS browse (run in a worker thread).

    Returns ``({ip: hostname}, {mac: hostname})``.  Both maps are empty when
    ``zeroconf`` is not installed or discovery fails for any reason.
    """
    try:
        from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf
    except ImportError:
        logger.warning("mDNS hostname discovery skipped: zeroconf is not installed")
        return {}, {}

    ip_map: dict[str, str] = {}
    mac_map: dict[str, str] = {}

    def _on_add(zeroconf, service_type, name, state_change):
        if state_change != ServiceStateChange.Added:
            return
        display = instance_display_name(name)
        mac = instance_mac(name)
        if mac:
            mac_map[mac] = display
        try:
            info = zeroconf.get_service_info(service_type, name)
        except Exception:  # noqa: BLE001 - one slow/odd device shouldn't break the rest
            info = None
        if info is not None:
            try:
                for addr in info.parsed_addresses():  # all versions -> list[str]
                    if addr:
                        ip_map[addr] = display
            except Exception:  # noqa: BLE001
                pass

    zc = Zeroconf()
    try:
        for st in _SERVICE_TYPES:
            try:
                ServiceBrowser(zc, st, [_on_add])
            except Exception:  # noqa: BLE001 - a bad type shouldn't abort the others
                logger.debug("mDNS: could not start browser for %s", st)
        time.sleep(timeout)
    finally:
        try:
            zc.close()
        except Exception:  # noqa: BLE001
            pass
    return ip_map, mac_map


async def discover_hostnames(
    timeout: float = MDNS_DISCOVERY_TIMEOUT,
) -> tuple[dict[str, str], dict[str, str]]:
    """Discover ``{ip: hostname}`` and ``{mac: hostname}`` maps via mDNS.

    Runs :func:`_discover_sync` in a worker thread (via ``asyncio.to_thread``)
    so the blocking multicast window never stalls the event loop.  Best-effort:
    returns empty maps on any failure so a scan is never blocked by discovery.
    """
    try:
        return await asyncio.to_thread(_discover_sync, timeout)
    except Exception as exc:  # noqa: BLE001 - discovery must never abort a scan
        logger.warning("mDNS discovery failed: %s", exc)
        return {}, {}
