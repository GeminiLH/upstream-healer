"""
LAN scanner – finds devices by MAC address.
Uses arp-scan when available, falls back to scapy.
Designed to be quiet on Windows (local development).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import subprocess
from typing import Optional

from app.config import current_time
from app.services import diag_log

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
    diag_log.emit("run_scan", f"method={method}", f"target={target_mac}", f"subnets={subnets}")
    loop = asyncio.get_running_loop()

    if method == "scapy":
        found_ip, output, error = await loop.run_in_executor(
            None, lambda: run_scapy_scan(target_mac, interface, subnets=subnets)
        )
    elif method == "nmap":
        found_ip, output, error = await loop.run_in_executor(
            None,
            lambda: run_nmap_scan(subnets=subnets, target_mac=target_mac, interface=interface),
        )
    else:  # "arp-scan" (the default)
        found_ip, output, error = await loop.run_in_executor(
            None, lambda: run_arp_scan(subnets=subnets)
        )
        if not error:
            found_ip = _match_mac_in_output(target_mac, output, subnets=subnets)

    result = {
        "method": method,
        "found_ip": found_ip,
        "found_via": method if found_ip else None,
        "output": output,
        "error": error,
        # Structured view of the sweep for the UI (IP / MAC / hostname).
        "hosts": await resolve_hostnames(_parse_scan_output(output, subnets=subnets)),
    }
    return result


def _parse_scan_output(output: str, subnets: Optional[list[str]] = None) -> list[dict]:
    """Parse responder lines into ``[{ip, mac, detail}]`` (deduped, subnet-scoped).

    Both scanner output shapes share the same first two columns (IP, MAC):
    arp-scan's ``ip  mac  vendor`` and scapy's synthetic ``ip  mac  (via net)``.
    ``detail`` keeps whatever trailing columns exist.  When ``subnets`` is
    given, responders outside them are dropped (same rule as the raw filter).
    """
    hosts: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            continue  # banner / summary / note line
        if subnets and not ip_in_subnets(parts[0], subnets):
            continue
        # A routed/tunnel host has no locally-visible source MAC; we emit "--".
        raw_mac = parts[1]
        mac = None if raw_mac == "--" else normalize_mac(raw_mac)
        key = (parts[0], mac or "")
        if key in seen:
            continue
        seen.add(key)
        hosts.append({"ip": parts[0], "mac": mac, "detail": " ".join(parts[2:])})
    return hosts


async def resolve_hostnames(hosts: list[dict], limit: int = 256) -> list[dict]:
    """Best-effort reverse lookups so the UI can show ``hostname`` per host.

    Mirrors what ``ip neigh`` does: NSS resolution (files, then DNS/PTR).
    Runs in the thread pool — a slow or wedged resolver must not stall the
    event loop; failures simply leave ``hostname`` as ``None``.
    """
    import socket

    async def _one(host: dict) -> None:
        try:
            host["hostname"] = (await asyncio.to_thread(socket.gethostbyaddr, host["ip"])).hostname
        except Exception:  # noqa: BLE001 - best-effort; display falls back to IP
            host["hostname"] = None

    if hosts:
        await asyncio.gather(*(_one(h) for h in hosts[:limit]))
    for h in hosts:
        h.setdefault("hostname", None)
    return hosts


async def load_known_hostnames(db) -> dict[str, str]:
    """Map ``normalized_mac -> name`` for every monitored host in the DB.

    These are the names the user curated on the hosts page.  They take priority
    over auto-discovered (mDNS / reverse-DNS) names so a saved name like
    ``vault`` is never silently replaced by a generic advertised one.  A
    ``None`` ``db`` (a bare worker thread with no connection) yields ``{}``.
    """
    if db is None:
        return {}
    out: dict[str, str] = {}
    try:
        async with db.execute("SELECT name, mac_address FROM hosts") as cursor:
            for row in await cursor.fetchall():
                mac = normalize_mac(row["mac_address"] or "")
                name = (row["name"] or "").strip()
                if mac and name:
                    out[mac] = name
    except Exception:  # noqa: BLE001 - a missing/odd table shouldn't abort a scan
        return {}
    return out


async def remember_mdns_names(db, mac_map: dict[str, str]) -> None:
    """Persist freshly-seen mDNS names (``{mac: hostname}``) for future scans.

    mDNS is racy — a device re-announces on its own cadence, so any single
    discovery window catches only a subset.  By caching each name by MAC we
    make the table deterministic after the first sighting: a device stays named
    on later scans even when it happens not to re-announce that instant.  Live
    discoveries overwrite a stale cached name (and curated DB names always win
    at apply time, see :func:`apply_hostnames`).  A ``None`` ``db`` is a no-op
    (a bare worker thread with no connection).
    """
    if db is None or not mac_map:
        return
    now = current_time().isoformat()
    for mac, name in mac_map.items():
        mac = normalize_mac(mac or "")
        name = (name or "").strip()
        if not mac or not name:
            continue
        try:
            await db.execute(
                """
                INSERT INTO mdns_names (mac, hostname, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    hostname = excluded.hostname,
                    updated_at = excluded.updated_at
                """,
                (mac, name, now),
            )
        except Exception as exc:  # noqa: BLE001 - caching must never fail a scan
            logger.debug("remember_mdns_names: could not store %s: %s", mac, exc)
    try:
        await db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.debug("remember_mdns_names: commit failed: %s", exc)


async def load_mdns_names(db) -> dict[str, str]:
    """Map ``normalized_mac -> hostname`` from the mDNS cache.

    The accumulated set of names learned on prior scans (see
    :func:`remember_mdns_names`).  A ``None`` ``db`` or a missing/odd table
    yields ``{}``.
    """
    if db is None:
        return {}
    out: dict[str, str] = {}
    try:
        async with db.execute("SELECT mac, hostname FROM mdns_names") as cursor:
            for row in await cursor.fetchall():
                mac = normalize_mac(row["mac"] or "")
                name = (row["hostname"] or "").strip()
                if mac and name:
                    out[mac] = name
    except Exception:  # noqa: BLE001 - a missing/odd table shouldn't abort a scan
        return {}
    return out


def apply_hostnames(
    hosts: list[dict],
    mdns: Optional[tuple[dict[str, str], dict[str, str]]] = None,
    known: Optional[dict[str, str]] = None,
    cached: Optional[dict[str, str]] = None,
) -> list[dict]:
    """Assign a ``hostname`` to each swept host from every available source.

    Priority (highest first): a monitored host's curated DB name (matched by
    MAC), then an mDNS/avahi name discovered *this* scan (by IP, then by MAC),
    then the persistent mDNS cache (by MAC, from prior scans), then the
    reverse-DNS value ``resolve_hostnames`` already stored on the host.  A host
    with no matching name keeps ``hostname=None`` (the UI renders ``—``).

    Returns the hosts ordered named-first, the rest in their original relative
    order — a sensible display order for the diagnostic table.
    """
    mdns_ip: dict[str, str] = {}
    mdns_mac: dict[str, str] = {}
    if mdns:
        mdns_ip = mdns[0] or {}
        mdns_mac = mdns[1] or {}
    known = known or {}
    cached = cached or {}

    for h in hosts:
        ip = (h.get("ip") or "").strip()
        mac = normalize_mac(h.get("mac") or "")
        h["hostname"] = (
            known.get(mac)
            or (mdns_ip.get(ip) if ip else None)
            or (mdns_mac.get(mac) if mac else None)
            or (cached.get(mac) if mac else None)
            or h.get("hostname")
        ) or None

    def _key(h: dict):
        try:
            # ``int()`` (not ``.int``) works across Python versions for both
            # IPv4 and IPv6 addresses; it gives a stable numeric sort order.
            ip_num = int(ipaddress.ip_address(h.get("ip") or "0.0.0.0"))
        except ValueError:
            ip_num = 0
        return (0 if h.get("hostname") else 1, ip_num)

    return sorted(hosts, key=_key)


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
    """Actively sweep the requested networks with ``arp-scan``.

    Returns ``(found_ip, raw_output, error)`` where ``found_ip`` is ``None``
    (there is no single "the" target for a full list).

    * ``subnets`` (list of CIDRs): each network with a local interface is
      swept with ``arp-scan -q --retry=3 -i <iface> <cidr>``.  Networks with
      no local interface are skipped with a note, and the output is filtered
      to responders inside the requested networks — an unselected network
      can never leak its hosts into the results (the old implicit no-``-i``
      fall-back swept the default interface and surfaced exactly that).
      When *nothing* is scannable the sweep is skipped entirely and
      ``error`` says why, instead of scanning an unselected network.
    * ``subnets=None``: every auto-discovered local /24 is swept (falling
      back to the primary IP's /24, then the historic passive
      ``arp-scan -l`` table dump if the box exposes no /24 at all).

    Cheap, synchronous: wraps the subprocess calls so a test can drive it
    from a thread pool or a TestClient without an event loop of its own.
    """
    notes: list[str] = []
    sweeps: list[tuple[str, str]] = []  # (iface, cidr)
    requested: list[str] = []

    if subnets:
        discovered = {d["cidr"]: d["interface"] for d in get_default_subnets()}
        for cidr in subnets:
            try:
                network = ipaddress.ip_network((cidr or "").strip(), strict=False)
            except ValueError:
                notes.append(f"(skipped unparseable subnet {cidr!r})")
                continue
            cidr_norm = str(network)
            if not any(cidr_norm == r for r in requested):
                requested.append(cidr_norm)
            if network.prefixlen >= 31:
                notes.append(
                    f"(skipped {cidr_norm}: single host, not an ARP-swept network — "
                    "add its /24 instead if you meant to scan the whole LAN)"
                )
                continue
            iface = discovered.get(cidr_norm)
            if not iface:
                _, iface = get_local_ip_for_network(cidr_norm)
            if iface:
                if (iface, cidr_norm) not in sweeps:
                    sweeps.append((iface, cidr_norm))
            else:
                notes.append(f"(skipped {cidr_norm}: no local interface)")

        if not sweeps:
            reasons = " ".join(
                n.strip("()").strip() for n in notes
            )
            diag_log.emit(
                "arp-scan plan",
                f"requested={requested}",
                f"discovered={discovered}",
                f"notes={notes}",
            )
            return None, "\n".join(notes).strip(), (
                "No scannable subnets to sweep"
                + (f" ({reasons})" if reasons else "")
                + ". Add a manual subnet with an egress interface to sweep a "
                "non-local network via that NIC."
            )

        chunks, error = _run_sweeps(sweeps)
        diag_log.emit("arp-scan plan", f"requested={requested}", f"sweeps={sweeps}", f"notes={notes}")
        output = _filter_and_dedupe("\n\n".join(chunks), requested)
        if not output:
            output = "(arp-scan produced no output — no hosts responded)"
        if notes:
            output = "\n".join(notes) + ("\n" + output if output else "")
        return None, output, error

    # No explicit subnets: sweep every locally-attached network.
    discovered = {d["cidr"]: d["interface"] for d in get_default_subnets()}
    auto_cidrs = list(discovered)
    if auto_cidrs:
        _plan_sweeps(auto_cidrs, discovered, notes, sweeps)
    else:
        primary = _get_primary_ip()
        if primary:
            _plan_sweeps([".".join(primary.split(".")[:3]) + ".0/24"], {}, notes, sweeps)

    if not sweeps:
        # Last resort (e.g. Windows dev box: no `ip`, no arp-scan targets):
        # the historic passive ARP-table dump of all interfaces.
        diag_log.emit("arp-scan plan", f"auto discovered={discovered}", f"notes={notes}", "mode=passive arp-scan -l")
        try:
            proc = subprocess.run(
                ["arp-scan", "-l", "-q", "--retry=3"],
                capture_output=True,
                text=True,
                timeout=45,
            )
        except FileNotFoundError:
            diag_log.emit("arp-scan", "binary not found (passive -l)")
            return None, "", "arp-scan binary not found"
        except Exception as exc:  # noqa: BLE001
            diag_log.exc("arp-scan", exc, "passive -l")
            return None, "", f"arp-scan failed: {exc}"
        diag_log.proc("arp-scan", ["arp-scan", "-l", "-q", "--retry=3"], proc)
        output = (proc.stdout or "") + (proc.stderr or "")
        if not output.strip():
            output = "(arp-scan produced no output — no hosts responded)"
        return None, output, None

    chunks, error = _run_sweeps(sweeps)
    diag_log.emit(
        "arp-scan plan",
        "mode=all-local",
        f"discovered={discovered}",
        f"sweeps={sweeps}",
        f"notes={notes}",
    )
    output = _filter_and_dedupe("\n\n".join(chunks), None)
    if not output:
        output = "(arp-scan produced no output — no hosts responded)"
    if notes:
        output = "\n".join(notes) + ("\n" + output if output else "")
    return None, output, error


def _run_sweeps(
    sweeps: list[tuple[str, str]],
) -> tuple[list[str], Optional[str]]:
    """Execute each ``(iface, cidr)`` sweep; return ``(non_empty_outputs, error)``.

    One failing sweep is recorded in ``error`` but the remaining sweeps still
    run — a wedged NIC must not hide the other networks.
    """
    chunks: list[str] = []
    error: Optional[str] = None
    for iface, cidr in sweeps:
        kind = classify_subnet(cidr, iface)["kind"]
        # arp-scan is a Layer-2 (ARP broadcast) tool: it cannot reach hosts beyond
        # a tunnel/gateway (the broadcast would hit only the tunnel peer).  For
        # such networks probe at Layer 3 instead.
        if kind in ("tunnel", "routed"):
            l3_egress = _l3_probe_egress(cidr, iface)
            diag_log.emit("arp-scan sweep", f"cidr={cidr}", f"classified={kind}", f"egress={l3_egress}", "mode=L3 (ARP broadcast cannot cross a gateway)")
            _found, l3_output, l3_err = run_l3_probe(cidr, l3_egress, timeout=3.0)
            diag_log.emit("arp-scan sweep", f"cidr={cidr}", f"l3_found={_found}", f"l3_error={l3_err}", f"l3_output={l3_output}")
            if l3_err:
                error = f"L3 probe failed: {l3_err}"
            if l3_output and l3_output.strip():
                chunks.append(l3_output.rstrip())
            continue
        cmd = ["arp-scan", "-q", "--retry=3", "-i", iface, cidr]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        except FileNotFoundError:
            diag_log.emit("arp-scan", "binary not found", "cmd=" + " ".join(cmd))
            return [], "arp-scan binary not found"
        except Exception as exc:  # noqa: BLE001 - per-sweep isolation
            diag_log.exc("arp-scan", exc, "cmd=" + " ".join(cmd))
            error = f"arp-scan failed: {exc}"
            continue
        diag_log.proc("arp-scan", cmd, proc)
        out = (proc.stdout or "") + (proc.stderr or "")
        if out.strip():
            chunks.append(out.rstrip())
    return chunks, error


def _plan_sweeps(
    cidrs: list[str],
    discovered: dict[str, str],
    notes: list[str],
    sweeps: list[tuple[str, str]],
) -> None:
    """Append scannable ``(iface, cidr)`` pairs to ``sweeps``.

    A network is scannable when a local interface owns it: either the
    auto-discovery map (``discovered``) or the kernel route
    (``get_local_ip_for_network``).  Everything else earns a note.
    """
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network((cidr or "").strip(), strict=False)
        except ValueError:
            notes.append(f"(skipped unparseable subnet {cidr!r})")
            continue
        cidr_norm = str(network)
        if network.prefixlen >= 31:
            notes.append(
                f"(skipped {cidr_norm}: single host, not an ARP-swept network — "
                "add its /24 instead if you meant to scan the whole LAN)"
            )
            continue
        iface = discovered.get(cidr_norm)
        if not iface:
            _, iface = get_local_ip_for_network(cidr_norm)
        if iface:
            if (iface, cidr_norm) not in sweeps:
                sweeps.append((iface, cidr_norm))
        else:
            notes.append(f"(skipped {cidr_norm}: no local interface)")


def _filter_and_dedupe(output: str, cidrs: Optional[list[str]]) -> str:
    """Keep only responder lines inside ``cidrs`` (when given); dedupe rows.

    A responder line is one whose first field is an IP address.  Banner,
    interface and summary lines pass through untouched.  When ``cidrs`` is
    ``None`` nothing is filtered (the all-local-networks sweep keeps all).
    """
    seen: set[str] = set()
    kept: list[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 2:
            try:
                ipaddress.ip_address(parts[0])
            except ValueError:
                kept.append(line)  # banner / summary / interface line
                continue
            if cidrs and not ip_in_subnets(parts[0], cidrs):
                continue  # off-network responder: never display unselected nets
        if line in seen:
            continue
        seen.add(line)
        kept.append(line)
    return "\n".join(kept)


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
        diag_log.emit("scapy", "library not installed — cannot sweep")
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
    diag_log.emit(
        "scapy",
        f"networks={networks}",
        f"target={target_mac}",
        f"explicit_interface={interface}",
    )

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
            #
            # CRITICAL: do NOT set ``conf.iface`` here — scapy 2.6.x mutates
            # ``conf.route.default_iface`` when ``conf.iface`` changes, and then
            # ``int("enp6s0")`` aborts the whole sweep.  Always pass ``iface=``
            # to ``srp()`` directly.
            egress: Optional[str] = interface
            if not egress:
                local_ip, iface = get_local_ip_for_network(network)
                if local_ip:
                    # Prefer the kernel-reported interface (from ``ip route``) —
                    # it is always valid and avoids the scapy
                    # ``int("enp6s0")`` route-bug entirely.
                    egress = iface
                    if not egress:
                        # Fallback: try scapy's own interface mapping.
                        ifaces = conf.get_if_addresses()
                        for if_name, if_ips in ifaces.items():
                            if local_ip in if_ips:
                                egress = if_name
                                break
            diag_log.emit(
                "scapy egress",
                f"network={network}",
                f"egress={egress or '(scapy default interface)'}",
            )

            # A tunnel/routed subnet cannot be ARP-*broadcast* swept: the
            # broadcast reaches only the one tunnel peer (so every IP would show
            # that peer's MAC).  Probe it at Layer 3 instead (ICMP/ping), which
            # finds the real live hosts.
            if classify_subnet(network, interface)["kind"] in ("tunnel", "routed"):
                l3_egress = _l3_probe_egress(network, interface)
                diag_log.emit(
                    "scapy sweep",
                    f"network={network}",
                    f"egress={l3_egress}",
                    "mode=L3 (routed/tunnel — ARP broadcast skipped)",
                )
                _found, l3_output, l3_err = run_l3_probe(
                    network, l3_egress, target_mac, timeout=3.0,
                )
                diag_log.emit(
                    "scapy sweep",
                    f"network={network}",
                    f"l3_found={_found}",
                    f"l3_error={l3_err}",
                    f"l3_output={l3_output}",
                )
                if l3_err:
                    lines.append(f"# {network}: L3 probe failed ({l3_err})")
                elif l3_output:
                    lines.extend(l3_output.splitlines())
                else:
                    lines.append(f"# {network}: no live hosts detected (L3)")
                if _found and found_ip is None:
                    found_ip = _found
                continue

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
                diag_log.exc("scapy sweep", exc, f"network={network}", f"egress={egress}")
                logger.warning(f"scapy: sweep of {network} failed ({exc})")
                continue

            diag_log.emit(
                "scapy sweep",
                f"network={network}",
                f"egress={egress}",
                f"classified={classify_subnet(network, interface)['kind']}",
                f"responses={len(ans)}",
            )
            for _, received in ans:
                mac = normalize_mac(received.hwsrc)
                ip = received.psrc
                lines.append(f"{ip}  {mac}  (via {network})")
                if mac == target_mac and found_ip is None:
                    found_ip = ip

        if found_ip:
            logger.info(f"Found {target_mac} at {found_ip} via scapy")
        output = "\n".join(lines) if lines else "(no ARP responses received)"
        diag_log.emit("scapy", f"lines={len(lines)}", f"found_ip={found_ip}", f"output={output}")
        return found_ip, output, None
    except Exception as exc:  # noqa: BLE001
        diag_log.exc("scapy", exc, f"target={target_mac}")
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


def get_local_ip_for_network(cidr: str) -> tuple[Optional[str], Optional[str]]:
    """Return ``(local_ip, interface)`` the kernel uses to reach ``cidr``.

    Resolves via ``ip route get <network-address>`` — the most reliable signal
    for "which local interface would we use to talk to this network?".  Returns
    ``(None, None)`` when no route exists or ``ip`` is unavailable.  Used to
    pick the right scapy egress interface for a given subnet.
    """
    cidr = (cidr or "").strip()
    if not cidr:
        return None, None
    try:
        base = ipaddress.ip_network(cidr, strict=False).network_address
        result = subprocess.run(
            ["ip", "-4", "route", "get", str(base)],
            capture_output=True, text=True, timeout=5,
        )
        match = re.search(r"(?:src\s+(\d+\.\d+\.\d+\.\d+).*?dev\s+(\S+))|(?:dev\s+(\S+).*?src\s+(\d+\.\d+\.\d+\.\d+))", result.stdout)
        if match:
            return match.group(1) or match.group(4), match.group(2) or match.group(3)
    except Exception:  # noqa: BLE001 - best-effort helper
        pass
    return None, None


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


def get_local_interfaces() -> list[dict]:
    """List locally-attached IPv4 interfaces as ``[{name, address, cidr}]``.

    Reads ``ip -4 -o addr`` and returns one entry per interface (deduped by name;
    the first address wins) — used to *suggest* and *validate* egress NIC names
    in the Settings subnet form.  ``lo`` is skipped.  Returns ``[]`` when ``ip``
    is unavailable (e.g. a Windows dev box), so callers fall back to "no
    validation possible" rather than failing.  Unlike :func:`get_default_subnets`
    (which keeps only /24 primaries), this lists *every* interface that has an
    IPv4 address, so a /28 VLAN NIC still shows up as a suggestion.
    """
    try:
        result = subprocess.run(
            ["ip", "-4", "-o", "addr"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:  # noqa: BLE001 - no `ip` (Windows) etc. -> no suggestions
        return []

    found: list[dict] = []
    seen: set[str] = set()
    for line in (result.stdout or "").splitlines():
        match = re.match(r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\b", line)
        if not match:
            continue
        name, addr, prefix = match.group(1), match.group(2), match.group(3)
        if name == "lo" or name in seen:
            continue
        seen.add(name)
        found.append({"name": name, "address": addr, "cidr": f"{addr}/{prefix}"})
    return found


# ───────────────────────────── Tunnel / routed discovery ─────────────────────────────
#
# An ARP *broadcast* only reaches hosts on a single Layer‑2 segment.  A subnet
# reached over a WireGuard/VPN tunnel (or a gateway) is **not** that: the tunnel
# is a Layer‑3 pipe with exactly one peer, so a broadcast ARP hits only the
# gateway (the flash) and every IP in the sweep shows the *gateway's* MAC.  For
# such subnets we must probe at Layer 3 (ICMP echo / ``nmap -sn`` / ``ping``),
# which reveals the real alive hosts (by IP + hostname) — even though the true
# source MAC of a host behind the tunnel is never visible from this side.

# Name prefixes of point‑to‑point / tunnel interfaces (L3, no L2 broadcast).
# ``tap*`` is deliberately excluded: a tap is an Ethernet (L2) interface and *can*
# be ARP‑swept. Used only as a fallback when the kernel's own flags are unreadable.
_TUNNEL_IFACE_PREFIXES = (
    "wg", "wgi", "wpan", "tun", "ipip", "ipip6", "gre", "gre6", "ip6gre",
    "erspan", "erspan6", "sit", "ip6tnl",
)


def get_interface_flags(iface: Optional[str]) -> Optional[str]:
    """Return the kernel flags inside ``<...>`` for ``iface`` (e.g.
    ``"BROADCAST,MULTICAST,UP"``) via ``ip -o link``, or ``None`` when it cannot
    be read (no ``ip``/iproute2, or the name is unknown)."""
    if not iface:
        return None
    try:
        proc = subprocess.run(
            ["ip", "-o", "link", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    m = re.search(r"<([^>]*)>", proc.stdout)
    return m.group(1) if m else None


def is_tunnel_interface(iface: Optional[str], flags: Optional[str] = None) -> bool:
    """True when ``iface`` is a Layer‑3 point‑to‑point/tunnel interface
    (WireGuard, ``tun*``, ``gre*``, …) — i.e. **not** a Layer‑2 broadcast medium.

    Detection is authoritative when possible (a real NIC carries the ``BROADCAST``
    flag; a tunnel does not, and has ``POINTOPOINT``/``NOARP``).  When the kernel
    flags are unreadable (e.g. the Windows dev box, where ``ip`` is absent) we fall
    back to an interface‑name heuristic.

    ``flags`` may be passed in (from :func:`get_interface_flags`) to avoid a
    second ``ip -o link`` round‑trip when the caller already has them.
    """
    if not iface:
        return False
    if flags is None:
        flags = get_interface_flags(iface)
    if flags is not None:
        if "BROADCAST" in flags:
            return False
        if "POINTOPOINT" in flags or "NOARP" in flags:
            return True
    # Flags unreadable or unrecognised → fall back to the name heuristic.
    name = iface.lower()
    return any(name.startswith(prefix) for prefix in _TUNNEL_IFACE_PREFIXES)


def interface_has_address_in(iface: str, cidr: str) -> bool:
    """True if ``iface`` holds an IPv4 address inside ``cidr`` (i.e. the network is
    directly attached to it, not reached only via a gateway)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    try:
        proc = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", iface],
            capture_output=True, text=True, timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False
    if proc.returncode != 0:
        return False
    for tok in proc.stdout.split():
        if "/" in tok:
            try:
                if ipaddress.ip_interface(tok) in net:
                    return True
            except ValueError:
                continue
    return False


def classify_subnet(cidr: str, explicit_iface: Optional[str] = None) -> dict:
    """Decide how a subnet must be swept.

    Returns ``{"cidr", "egress", "kind", "flags"}`` where ``kind`` is:

    * ``"broadcast"`` — directly attached to a real L2 NIC → an ARP *broadcast*
      sweep reaches the hosts and returns their true MACs (the normal case).
    * ``"tunnel"``    — egress is a point‑to‑point/tunnel (WireGuard, …) → a
      broadcast cannot cross; probe at Layer 3.
    * ``"routed"``    — reached via a gateway, not directly attached → probe at
      Layer 3.
    * ``"unknown"``   — no egress could be resolved → default to the historic
      broadcast behaviour.
    """
    local_ip, iface = get_local_ip_for_network(cidr)
    if explicit_iface:
        iface = explicit_iface
    flags = get_interface_flags(iface)
    if is_tunnel_interface(iface, flags):
        kind = "tunnel"
    elif flags is None:
        # ``ip`` unavailable (Windows dev box) → rely on the name heuristic.
        kind = "tunnel" if is_tunnel_interface(iface, flags) else "unknown"
    elif "BROADCAST" in flags:
        kind = "broadcast" if interface_has_address_in(iface, cidr) else "routed"
    else:
        kind = "routed"
    return {"cidr": cidr, "egress": iface, "kind": kind, "flags": flags}


def subnet_is_l3_only(cidr: str, explicit_iface: Optional[str] = None) -> bool:
    """True when the subnet must be probed at Layer 3 (tunnel or routed): an ARP
    *broadcast* cannot reach the hosts inside it."""
    return classify_subnet(cidr, explicit_iface)["kind"] in ("tunnel", "routed")


def _usable_hosts(cidr: str) -> list[str]:
    """Host addresses in a CIDR, refusing to sweep an unreasonably large range."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        raise ValueError(f"invalid network {cidr!r}")
    if net.num_addresses > 4096:
        raise ValueError(f"subnet {cidr} is too large to sweep one host at a time")
    return [str(h) for h in net.hosts()]


def _l3_probe_egress(cidr: str, iface: Optional[str] = None) -> Optional[str]:
    """Egress interface for a Layer‑3 probe of ``cidr``.

    A user‑named interface wins; otherwise the kernel's *routed* egress (``ip
    route get``) is used — which correctly resolves to the tunnel (e.g. ``wg0``) for
    a routed/tunnel subnet instead of collapsing "auto"/blank to the default NIC.
    """
    if iface and iface != "auto":
        return iface
    _, dev = get_local_ip_for_network(cidr)
    return dev or None


def _l3_alive_scapy(hosts: list[str], egress: Optional[str], timeout: float) -> Optional[set]:
    """ICMP‑echo sweep via scapy.  Returns the set of live IPs, or ``None`` when
    scapy is unavailable or the send fails (so the caller can fall back)."""
    if not hosts:
        return set()
    try:
        from scapy.all import ICMP, IP
        from scapy.sendrecv import sr
    except Exception:  # noqa: BLE001 - scapy missing/failed to import
        diag_log.emit("l3-scapy", "import failed", f"hosts={len(hosts)}")
        return None
    try:
        packets = [IP(dst=h) / ICMP() for h in hosts]
        answered, _ = sr(packets, iface=egress, timeout=timeout, retry=1, verbose=0)
    except Exception as exc:  # noqa: BLE001 - can't open a socket on the iface, etc.
        diag_log.exc("l3-scapy", exc, f"hosts={len(hosts)}", f"egress={egress}", f"timeout={timeout}")
        return None
    alive = set()
    for reply in answered:
        if ICMP in reply and IP in reply and reply[ICMP].type == 0:
            alive.add(reply[IP].psrc)
    diag_log.emit("l3-scapy", f"hosts={len(hosts)}", f"egress={egress}", f"alive={sorted(alive)}")
    return alive


def _l3_alive_nmap(cidr: str, egress: Optional[str]) -> Optional[set]:
    """Host discovery via ``nmap -sn`` (robust: ICMP + TCP/UDP probes).  Returns the
    set of live IPs, or ``None`` when ``nmap`` is absent or the run fails.

    Runs ``nmap -sn -oG -`` (grepable output to stdout) and parses the
    ``Host: <ip> (…) Status: up`` lines — the stable machine-readable format, which
    is far more reliable than scraping nmap's human-readable banner.
    """
    try:
        cmd = ["nmap", "-sn", "-oG", "-", "--host-timeout", "5s"]
        if egress:
            cmd += ["-e", egress]
        cmd.append(cidr)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        diag_log.emit("l3-nmap", f"failed: {exc!r}", "cmd=" + " ".join(cmd))
        return None
    diag_log.proc("l3-nmap", cmd, proc)
    if proc.returncode != 0:
        diag_log.emit("l3-nmap", f"non-zero rc={proc.returncode}")
        return None
    alive = set()
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] != "Host:" or "Status:" not in parts:
            continue
        i = parts.index("Status:")
        if i + 1 >= len(parts) or parts[i + 1].lower() != "up":
            continue
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[1]):
            alive.add(parts[1])
    return alive


def _l3_alive_ping(hosts: list[str], egress: Optional[str], concurrency: int = 32) -> set:
    """Last‑resort Layer‑3 sweep using the ``ping`` binary (iputils‑ping, already in
    the image), fanned out across a small thread pool."""
    import concurrent.futures

    def _one(host: str) -> Optional[str]:
        try:
            cmd = ["ping", "-c", "1", "-W", "1"]
            if egress:
                cmd += ["-I", egress]
            cmd.append(host)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            return host if proc.returncode == 0 else None
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return None

    alive = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        for hit in pool.map(_one, hosts):
            if hit:
                alive.add(hit)
    return alive


def _host_line(ip: str, mac: str, routed: bool, egress: Optional[str], via: str) -> str:
    """Format one discovered host as a parseable scanner line:
    ``<ip>  <mac-or---->  (<tag>)``.  ``--`` means "no locally‑resolvable MAC"."""
    tag = f"routed via {egress or 'L3'}" if routed else f"on {egress or 'local'}"
    return f"{ip}  {mac or '--'}  ({tag}, {via})"


def run_l3_probe(
    cidr: str,
    egress: Optional[str] = None,
    target_mac: Optional[str] = None,
    timeout: float = 3.0,
) -> tuple[Optional[str], str, Optional[str]]:
    """Discover live hosts in a routed/tunnel subnet with a Layer‑3 probe.

    An ARP *broadcast* cannot reach hosts behind a tunnel or gateway, so sweep with
    unicast ICMP echo requests instead.  Tries scapy first, then ``nmap -sn``, then
    a parallel ``ping`` sweep.  Returns ``(found_ip, output, error)`` where
    ``output`` is one :func:`_host_line` per live host.
    """
    try:
        hosts = _usable_hosts(cidr)
    except ValueError as exc:
        diag_log.emit("l3", f"cidr={cidr}", f"unusable: {exc}")
        return None, "", f"invalid subnet {cidr}: {exc}"
    if not hosts:
        return None, "", None
    diag_log.emit("l3", f"cidr={cidr}", f"egress={egress}", f"usable_hosts={len(hosts)}")

    alive = _l3_alive_scapy(hosts, egress, timeout)
    via = "scapy ICMP"
    if alive is None:
        alive = _l3_alive_nmap(cidr, egress)
        via = "nmap -sn"
    if alive is None:
        alive = _l3_alive_ping(hosts, egress)
        via = "ping"
    diag_log.emit("l3", f"cidr={cidr}", f"method={via}", f"alive={sorted(alive)}")
    if not alive:
        return None, "", None

    # L3 hosts have no locally‑visible source MAC — the real one sits on the far
    # side of the tunnel/gateway.  Emit "--" rather than the misleading gateway MAC.
    lines = [
        _host_line(ip, "--", True, egress, via)
        for ip in sorted(alive)
    ]
    output = "\n".join(lines)
    found_ip = _match_mac_in_output(target_mac, output, subnets=[cidr]) if target_mac else None
    return found_ip, output, None


def run_nmap_scan(
    subnets: Optional[list[str]] = None,
    target_mac: Optional[str] = None,
    interface: Optional[str] = None,
) -> tuple[Optional[str], str, Optional[str]]:
    """Host discovery via ``nmap -sn`` — a diagnostic aid, **not** the recovery path.

    ``nmap -sn`` uses ARP for locally‑attached networks and ICMP/ping probes for
    routed/tunnel ones, so it shows real hosts on *both* without the tunnel
    returning only the gateway.  Returns ``(found_ip, output, error)``.
    """
    if subnets is None:
        subnets = [s["cidr"] for s in get_default_subnets()]
    if not subnets:
        return None, "", None
    diag_log.emit("nmap", f"subnets={subnets}", f"interface={interface}", f"target={target_mac}")
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        diag_log.emit("nmap", "binary not installed")
        return None, "", "nmap is not installed in this container; rebuild the image with the nmap dependency to use this diagnostic."

    lines: list[str] = []
    for cidr in subnets:
        cls = classify_subnet(cidr, interface)
        alive = _l3_alive_nmap(cidr, cls["egress"])
        diag_log.emit(
            "nmap",
            f"cidr={cidr}",
            f"classified={cls['kind']}",
            f"egress={cls['egress']}",
            f"alive={sorted(alive) if alive is not None else '(run failed)'}",
        )
        if alive is None:
            return None, "", f"nmap failed on {cidr}"
        if not alive:
            continue
        routed = cls["kind"] in ("tunnel", "routed")
        for ip in sorted(alive):
            lines.append(_host_line(ip, "--", routed, cls["egress"], "nmap -sn"))
    output = "\n".join(line for line in lines if line)
    found_ip = _match_mac_in_output(target_mac, output, subnets=subnets) if target_mac else None
    return found_ip, output, None


async def load_suppressed_subnets(db=None) -> list[str]:
    """Return auto-subnet CIDRs the user has deleted via the settings page.

    Stored as a JSON list under the ``suppressed_subnets`` settings key.
    Suppressed auto subnets are excluded from scans (see
    :func:`list_subnets`) but can be re-included with "rescan".
    """
    if db is None:
        return []
    try:
        async with db.execute(
            "SELECT value FROM settings WHERE key = 'suppressed_subnets'"
        ) as cursor:
            rows = await cursor.fetchall()
    except Exception:  # noqa: BLE001 - missing table etc. shouldn't abort scans
        return []
    if not rows:
        return []
    try:
        return [str(c) for c in json.loads(rows[0]["value"] or "[]")]
    except (ValueError, TypeError):
        return []


async def save_suppressed_subnets(db, cidrs: list[str]) -> None:
    """Persist the suppressed auto-subnet CIDRs (idempotent upsert)."""
    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('suppressed_subnets', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (json.dumps(sorted(set(cidrs))),),
    )
    await db.commit()


async def list_subnets(db=None, include_suppressed: bool = False) -> list[dict]:
    """Return the effective list of subnets to scan.

    Merges enabled rows from the ``subnets`` table (when ``db`` is given) with
    the auto-discovered local networks from :func:`get_default_subnets`.  Manual
    rows win for a given CIDR (their name/interface is preferred); auto rows fill
    in the rest.  Order: enabled manual rows first, then auto rows.  Called once
    per scan so a newly-plugged-in interface is picked up without a restart.

    Auto subnets the user deleted on the settings page (the
    ``suppressed_subnets`` setting) are excluded unless
    ``include_suppressed`` is set.  Manual rows are never suppressed.
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

    suppressed = set(await load_suppressed_subnets(db))
    auto = get_default_subnets()
    seen = {m["cidr"] for m in manual}
    for a in auto:
        if a["cidr"] in seen:
            continue
        if a["cidr"] in suppressed and not include_suppressed:
            continue
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