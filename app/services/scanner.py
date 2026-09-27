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
import socket
import subprocess
import xml.etree.ElementTree as ET
from typing import Optional

from app.config import current_time
from app.services import diag_log
from app.services.mdns import discover_hostnames

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
    scan_ports: bool = False,
) -> dict:
    """Run one scanner and return a JSON-ready dict for the diagnostic UI.

    The scanner work is dispatched to a thread pool (``asyncio.to_thread``) so the
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
    # Dispatch each sweep with ``asyncio.to_thread`` (NOT a bare
    # ``loop.run_in_executor``): ``to_thread`` copies the running context, so the
    # active-scan diag_log ContextVar reaches the worker thread and the sweep's
    # per-scan log lines actually land.  A bare ``run_in_executor`` drops the
    # context on Python 3.12 (the dev image) → the worker silently logs nothing.
    if method == "scapy":
        found_ip, output, error = await asyncio.to_thread(
            run_scapy_scan, target_mac, interface, subnets=subnets
        )
    elif method == "nmap":
        found_ip, output, error = await asyncio.to_thread(
            run_nmap_scan, subnets=subnets, target_mac=target_mac, interface=interface
        )
    else:  # "arp-scan" (the default)
        found_ip, output, error = await asyncio.to_thread(run_arp_scan, subnets=subnets)
        if not error:
            found_ip = _match_mac_in_output(target_mac, output, subnets=subnets)

    hosts = await resolve_hostnames(_parse_scan_output(output, subnets=subnets))
    ports_error: Optional[str] = None
    if scan_ports and hosts:
        port_map, ports_error = await asyncio.to_thread(
            run_port_scan, [h["ip"] for h in hosts]
        )
        for h in hosts:
            h["ports"] = port_map.get(h["ip"], [])
    result = {
        "method": method,
        "found_ip": found_ip,
        "found_via": method if found_ip else None,
        "output": output,
        "error": error,
        # Structured view of the sweep for the UI (IP / MAC / hostname / ports).
        "hosts": hosts,
    }
    if ports_error:
        result["ports_error"] = ports_error
    return result


def _parse_scan_output(output: str, subnets: Optional[list[str]] = None) -> list[dict]:
    """Parse responder lines into ``[{ip, mac, detail}]`` (deduped, subnet-scoped).

    Both scanner output shapes share the same first two columns (IP, MAC):
    arp-scan's ``ip  mac  vendor`` and scapy's synthetic ``ip  mac  (via net)``.
    ``detail`` keeps whatever trailing columns exist.  An optional trailing
    ``hostname:<name>`` token (emitted by :func:`_host_line` when the sweep
    itself resolved a name, e.g. ``nmap -sn`` reverse DNS) is moved into the
    host's ``hostname`` field and stripped from ``detail``.  When ``subnets`` is
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
        detail_parts = list(parts[2:])
        hostname = None
        for i, tok in enumerate(detail_parts):
            if tok.startswith("hostname:"):
                val = tok.split("hostname:", 1)[1]
                if i + 1 < len(detail_parts):
                    # The name may contain spaces — take everything after the token.
                    val = f"{val} " + " ".join(detail_parts[i + 1 :])
                if val:
                    hostname = val
                detail_parts = detail_parts[:i]
                break
        hosts.append(
            {"ip": parts[0], "mac": mac, "detail": " ".join(detail_parts), "hostname": hostname}
        )
    return hosts


async def resolve_hostnames(hosts: list[dict], limit: int = 256) -> list[dict]:
    """Best-effort reverse lookups so the UI can show ``hostname`` per host.

    Mirrors what ``ip neigh`` does: NSS resolution (files, then DNS/PTR).
    Runs in the thread pool — a slow or wedged resolver must not stall the
    event loop; failures simply leave ``hostname`` as ``None``.  This is the
    *last-resort* naming source: a host that already carries a name parsed from
    the scanner output (e.g. ``nmap -sn``'s reverse DNS in its grepable
    ``Host:`` lines) keeps it — reverse DNS from this machine is the
    lowest-confidence source.
    """
    import socket

    attempted = 0
    resolved = 0

    async def _one(host: dict) -> None:
        nonlocal attempted, resolved
        if host.get("hostname"):
            return  # already named — reverse DNS is only the fallback
        attempted += 1
        try:
            # gethostbyaddr returns a (hostname, aliases, addrlist) *tuple* —
            # the first element is the name (NOT an object with .hostname).
            name = (await asyncio.to_thread(socket.gethostbyaddr, host["ip"]))[0]
            host["hostname"] = name
            resolved += 1
        except Exception:  # noqa: BLE001 - best-effort; display falls back to IP
            host["hostname"] = None

    if hosts:
        await asyncio.gather(*(_one(h) for h in hosts[:limit]))
    for h in hosts:
        h.setdefault("hostname", None)
    diag_log.emit("reverse-dns", f"attempted={attempted}", f"resolved={resolved}")
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


async def load_known_hostnames_by_ip(db) -> dict[str, str]:
    """Map ``current_ip -> name`` for every monitored host that has a stored IP.

    An IP is a weaker identity than a MAC (an address can be reassigned), so the
    caller should prefer the MAC-keyed lookup (:func:`load_known_hostnames`).
    This exists so a swept host whose source MAC is not visible from this side —
    the routed/tunnel hosts that show ``--`` — can still be labelled with the
    user's curated name when it answers at its last known address.  A ``None``
    ``db`` (a bare worker thread with no connection) yields ``{}``.
    """
    if db is None:
        return {}
    out: dict[str, str] = {}
    try:
        async with db.execute("SELECT name, current_ip FROM hosts") as cursor:
            for row in await cursor.fetchall():
                ip = (row["current_ip"] or "").strip()
                name = (row["name"] or "").strip()
                if ip and name:
                    out[ip] = name
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
    known_by_ip: Optional[dict[str, str]] = None,
) -> list[dict]:
    """Assign a ``hostname`` to each swept host from every available source.

    Priority (highest first): a monitored host's curated DB name (matched by
    MAC), then that same curated name matched by ``current_ip`` (so routed/
    tunnel hosts with no visible MAC are still labelled), then an mDNS/avahi
    name discovered *this* scan (by IP, then by MAC), then the persistent mDNS
    cache (by MAC, from prior scans), then the scanner-provided / reverse-DNS
    value already stored on the host.  A host with no matching name keeps
    ``hostname=None`` (the UI renders ``—``).

    Returns the hosts ordered named-first, the rest in their original relative
    order — a sensible display order for the diagnostic table.
    """
    mdns_ip: dict[str, str] = {}
    mdns_mac: dict[str, str] = {}
    if mdns:
        mdns_ip = mdns[0] or {}
        mdns_mac = mdns[1] or {}
    known = known or {}
    known_by_ip = known_by_ip or {}
    cached = cached or {}

    for h in hosts:
        ip = (h.get("ip") or "").strip()
        mac = normalize_mac(h.get("mac") or "")
        h["hostname"] = (
            known.get(mac)
            or (known_by_ip.get(ip) if ip else None)
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
      swept with ``arp-scan -q --retry=3 --interface=<iface> <cidr>``.  Networks with
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
        # arp-scan 1.10's option letters are case-sensitive and differ from older
        # releases: ``-I``/``--interface`` selects the NIC (a string) while
        # ``-i``/``--interval`` is a *numeric* retry interval.  The old code passed
        # the NIC name to ``-i``, so arp-scan tried ``strtoul("enp6s0")``, printed
        # ``"enp6s0" is not a valid numeric value`` and exited 1 with zero hosts —
        # which is why full arp-scan lists came back empty.  Bind the NIC with the
        # long ``--interface=<nic>`` form (the man-page canonical spelling) so the
        # name can never be re-read as a number.
        cmd = ["arp-scan", "-q", "--retry=3", f"--interface={iface}", cidr]
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
        if proc.returncode != 0:
            # arp-scan aborts on a bad argument / unusable NIC (non-zero exit)
            # rather than returning a partial list, so a failed sweep must not
            # have its error banner mistaken for host output: record it and keep
            # sweeping the remaining networks.
            stderr_tail = (proc.stderr or "").strip().splitlines()
            detail = stderr_tail[-1][:160] if stderr_tail else f"rc={proc.returncode}"
            error = f"arp-scan failed on {cidr} ({detail})"
            continue
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


# Wall-clock caps for ``nmap -sn``.  A directly-attached (broadcast/ARP) sweep of a
# real LAN is slow but *finishes* (≈45s for a /24), so leave headroom.  A routed or
# tunnel sweep on a dead gateway instead stalls per host — every unresponsive host
# burns its full probe+retry window (3 retries by default) — so a blackholed /24
# would hang the whole sweep near the cap.  Routed/tunnel subnets therefore sweep a
# single probe round (``--max-retries 0``) under a tight wall cap and *finish fast*
# (usually with zero hosts) rather than timing out and flagging an alarming error.
_NMAP_TIMEOUT_LOCAL = 120
_NMAP_TIMEOUT_L3 = 30


def _l3_alive_nmap(
    cidr: str, egress: Optional[str], kind: Optional[str] = None,
) -> Optional[dict[str, dict[str, Optional[str]]]]:
    """Host discovery via ``nmap -sn`` (robust: ICMP + TCP/UDP probes).  Returns a
    mapping of live IP → ``{"mac": …, "hostname": …}`` — ``mac`` is ``None`` when
    nmap reports no MAC (e.g. a routed/tunnel host) and ``hostname`` is the
    reverse-DNS name nmap resolved (``None`` when it had none) — or ``None``
    when ``nmap`` is absent or the run fails.

    Runs ``nmap -sn -oG -`` (grepable output to stdout) and parses the
    ``Host: <ip> (…) Status: up`` lines — the stable machine-readable format, which
    is far more reliable than scraping nmap's human-readable banner.  ``nmap -sn``
    performs reverse DNS by default, so the parenthesised part of that line
    carries the host's name (``Host: 192.168.1.5 (frick)``); when no name exists
    nmap simply echoes the IP back, which we treat as "no hostname".

    ``kind`` is the :func:`classify_subnet` result for ``cidr``; when omitted it is
    re-derived.  Routed/tunnel subnets (``kind`` in tunnel/routed) sweep a single
    probe round under a tight per-host/wall timeout so a blackholed gateway resolves
    quickly instead of hanging the whole sweep (see the timeout caps above).
    """
    if kind is None:
        try:
            kind = classify_subnet(cidr)["kind"]
        except Exception:  # noqa: BLE001 - classification is best-effort here
            kind = "unknown"
    l3 = kind in ("tunnel", "routed")
    try:
        cmd = ["nmap", "-sn", "-oG", "-"]
        if l3:
            cmd += ["--host-timeout", "3s", "--max-retries", "0"]
            wall = _NMAP_TIMEOUT_L3
        else:
            cmd += ["--host-timeout", "5s"]
            wall = _NMAP_TIMEOUT_LOCAL
        if egress:
            cmd += ["-e", egress]
        cmd.append(cidr)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=wall)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        diag_log.emit("l3-nmap", f"failed: {exc!r}", f"kind={kind}", "cmd=" + " ".join(cmd))
        return None
    diag_log.proc("l3-nmap", cmd, proc)
    if proc.returncode != 0:
        diag_log.emit(
            "l3-nmap",
            f"non-zero rc={proc.returncode}",
            "stderr=" + (proc.stderr or "").strip()[:800],
        )
        return None
    alive: dict[str, dict[str, Optional[str]]] = {}
    pending_ip: Optional[str] = None
    for line in proc.stdout.splitlines():
        s = line.strip()
        if s.startswith("Host:"):
            parts = s.split()
            ip = parts[1].split("(", 1)[0].strip() if len(parts) > 1 else ""
            up = False
            if "Status:" in parts:
                i = parts.index("Status:")
                up = i + 1 < len(parts) and parts[i + 1].lower() == "up"
            if up and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
                # Reverse-DNS name from the ``Host: <ip> (<name>)`` line.  When
                # nmap has no name it echoes the IP itself — keep that as None.
                # The name (e.g. ``My PC``) may contain spaces, hence the regex
                # over the raw line rather than the split columns.
                hostname = None
                name_m = re.search(r"\(([^()]+)\)", s)
                if name_m:
                    cand = name_m.group(1).strip()
                    if cand and cand != ip:
                        hostname = cand
                alive[ip] = {"mac": None, "hostname": hostname}
                pending_ip = ip
                continue
            pending_ip = None
            continue
        # The ``MAC Address:`` line follows its ``Host:`` line for a locally
        # attached (ARP-visible) host; attach it to that IP so the diagnostic
        # can do MAC-keyed hostname lookup.  Routed/tunnel hosts have none.
        if (
            s.startswith("MAC Address:")
            and pending_ip is not None
            and alive.get(pending_ip, {}).get("mac") is None
        ):
            mparts = s.split()
            if len(mparts) >= 3 and re.fullmatch(
                r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", mparts[2].lower()
            ):
                alive[pending_ip]["mac"] = normalize_mac(mparts[2])
        pending_ip = None
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


def _host_line(ip: str, mac: str, routed: bool, egress: Optional[str], via: str, hostname: Optional[str] = None) -> str:
    """Format one discovered host as a parseable scanner line:
    ``<ip>  <mac-or---->  (<tag>)`` — optionally suffixed `` hostname:<name>``
    when the sweep itself learned a name for the host (``nmap -sn`` reverse
    DNS).  ``--`` means "no locally‑resolvable MAC"."""
    tag = f"routed via {egress or 'L3'}" if routed else f"on {egress or 'local'}"
    line = f"{ip}  {mac or '--'}  ({tag}, {via})"
    if hostname:
        line += f"  hostname:{hostname}"
    return line


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
    # Only the nmap probe learns hostnames (reverse DNS); scapy/ping sweeps do not.
    lines = [
        _host_line(
            ip,
            "--",
            True,
            egress,
            via,
            hostname=(alive.get(ip) or {}).get("hostname") if type(alive) is dict else None,
        )
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
    returning only the gateway.  Locally-attached hosts carry their source MAC
    (so the UI's MAC-keyed hostname lookup works); routed/tunnel hosts have no
    visible MAC and emit ``--``.  Returns ``(found_ip, output, error)``.

    A probe failure on *one* subnet no longer aborts the whole scan: the failed
    CIDR is noted and the remaining subnets are still swept.  ``error`` is set
    when every requested subnet failed (nmap unusable) or some failed (a partial
    sweep is returned alongside the note); it is ``None`` when all succeeded.
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
    failures: list[str] = []
    for cidr in subnets:
        cls = classify_subnet(cidr, interface)
        alive = _l3_alive_nmap(cidr, cls["egress"], kind=cls["kind"])
        diag_log.emit(
            "nmap",
            f"cidr={cidr}",
            f"classified={cls['kind']}",
            f"egress={cls['egress']}",
            f"alive={sorted(alive) if alive is not None else '(failed)'}",
        )
        if alive is None:
            # One unreachable / unroutable subnet must not poison the whole
            # sweep: note it, log it, and keep going.  The old behaviour (return
            # immediately) dropped every other subnet's results, so a single bad
            # CIDR reported zero hosts even with ~20 alive elsewhere.
            failures.append(f"nmap failed on {cidr}")
            diag_log.emit(
                "nmap", f"cidr={cidr}", "probe failed — skipping this subnet, continuing"
            )
            continue
        if not alive:
            continue
        routed = cls["kind"] in ("tunnel", "routed")
        for ip in sorted(alive):
            entry = alive.get(ip) or {}
            lines.append(
                _host_line(
                    ip,
                    entry.get("mac"),
                    routed,
                    cls["egress"],
                    "nmap -sn",
                    hostname=entry.get("hostname"),
                )
            )
    output = "\n".join(line for line in lines if line)
    found_ip = _match_mac_in_output(target_mac, output, subnets=subnets) if target_mac else None
    if failures and not lines:
        # Every requested subnet's probe failed — nothing to salvage, so surface
        # it as a hard error (preserves the "nmap itself is broken" signal).
        return None, "", "; ".join(failures)
    if failures:
        # Partial success: keep the good results, but name the failed subnet(s)
        # so the UI can warn instead of trusting an incomplete sweep silently.
        return found_ip, output, "; ".join(failures)
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


# ─────────────────────────────────────────────────────────────────────
# Host validation — the "Validate" action on the host *edit* screen
#
# The edit screen's Validate button confirms, from the network's point of
# view, whether the entered values for a host are still correct:
#
#   * given a MAC, one ARP sweep resolves the IP it currently answers on
#     (the same sweep's rows are re-used for the IP→MAC direction),
#   * the hostname comes from the same layered chain as the scan page
#     (curated DB name → live mDNS → mDNS cache → reverse DNS),
#   * a short nmap port/service probe reports what the host actually
#     serves (open ports + service names/versions).
#
# It is deliberately log-only: it never mutates the host record — the
# operator reads the results popup and corrects the form by hand.

# Ports the nmap probe always checks.  A deliberately small, service-heavy
# list keeps a single-host probe quick (nmap *version* detection is the slow
# part) while covering what proxy hosts actually run.  The host's configured
# port is merged in on top of this list (see :func:`run_service_scan`).
DEFAULT_PROBE_TCP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465, 587,
    631, 636, 873, 993, 995, 1080, 1194, 1433, 1521, 1723, 2049,
    2375, 2376, 3000, 3001, 3306, 3389, 3390, 5000, 5001, 5432,
    5666, 5672, 5984, 5985, 6379, 8000, 8080, 8081, 8086, 8443,
    8554, 8888, 9000, 9090, 9117, 9418, 9999, 10000, 15672,
)
DEFAULT_PROBE_UDP_PORTS: tuple[int, ...] = (53, 67, 68, 137, 138, 161)


def build_port_spec(tcp_ports: list[int], udp_ports: list[int]) -> str:
    """Build an nmap ``-p`` port spec (``"T:22,80,U:53"``) from two lists."""
    parts: list[str] = []
    if tcp_ports:
        parts.append("T:" + ",".join(str(p) for p in tcp_ports))
    if udp_ports:
        parts.append("U:" + ",".join(str(p) for p in udp_ports))
    return ",".join(parts)


def parse_nmap_services_json(raw: str) -> list[dict]:
    """Parse ``nmap -oJ`` output into a flat list of per-port dicts.

    Newer nmap emits ``service`` as an object (``{"name", "product",
    "version", "extrainfo", ...}``); older builds emit a plain string.  Both
    reduce to one dict per reported port:
    ``{"port", "protocol", "state", "service", "product", "version",
    "extrainfo"}``.  Unparseable/empty output yields ``[]`` — a bad JSON doc
    must never surface as an exception up the chain.
    """
    if not raw or not raw.strip().startswith("{"):
        return []
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return []
    ports: list[dict] = []
    for host in doc.get("hosts", []):
        for entry in host.get("ports", []):
            svc = entry.get("service")
            service = product = version = extrainfo = None
            if isinstance(svc, dict):
                service = svc.get("name")
                product = svc.get("product")
                version = svc.get("version")
                extrainfo = svc.get("extrainfo")
            elif isinstance(svc, str) and svc:
                service = svc
            ports.append({
                # real nmap -oJ uses "id" for the port number; accept "port"
                # too so hand-rolled fakes in tests keep working
                "port": entry.get("id", entry.get("port")),
                "protocol": entry.get("protocol"),
                "state": entry.get("state"),
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
            })
    return ports


def parse_nmap_services_xml(raw: str) -> list[dict]:
    """Parse ``nmap -oX`` (XML) output into a flat list of per-port dicts.

    ``-oX`` — not ``-oJ`` — is used deliberately: nmap 7.93 (Debian trixie /
    the Docker image) has no JSON output, and a bare ``-oJ`` element silently
    re-parses as the *deprecated* ``-o`` flag with filename "J", dropping the
    intended file argument into the *target* list (see run_service_scan).
    Both new and older nmap builds emit the same XML shape:
    ``host/ports/port[@protocol @portid]/state[@state]/service[@name ...]``.
    Unparseable/empty output yields ``[]`` — never raises.
    """
    if not raw or "<nmaprun" not in raw:
        return []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []
    ports: list[dict] = []
    for host in root.iter("host"):
        for port in host.iter("port"):
            state_el = port.find("state")
            svc_el = port.find("service")
            portid = port.get("portid") or ""
            ports.append({
                "port": int(portid) if portid.isdigit() else None,
                "protocol": port.get("protocol"),
                "state": state_el.get("state") if state_el is not None else None,
                "service": svc_el.get("name") if svc_el is not None and svc_el.get("name") else None,
                "product": svc_el.get("product") if svc_el is not None else None,
                "version": svc_el.get("version") if svc_el is not None else None,
                "extrainfo": svc_el.get("extrainfo") if svc_el is not None else None,
            })
    return ports


def parse_nmap_services_by_host(raw: str) -> dict[str, list[dict]]:
    """Group ``nmap -oX`` ports by their host IPv4 address.

    Returns ``{ip: [{"port", "protocol", "state", "service"}]}`` for every host
    that reported an IPv4 address and at least one port.  Mirrors
    :func:`parse_nmap_services_xml` but keeps the per-host grouping the diagnostic
    multi-host port scan needs (that helper is for single-host probes).  Only
    hosts with ports are included — with ``--open`` nmap reports open ports only,
    so these are exactly the open ports.  Unparseable/empty input yields ``{}``.
    """
    if not raw or "<nmaprun" not in raw:
        return {}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {}
    out: dict[str, list[dict]] = {}
    for host in root.iter("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        addr = addr_el.get("addr") if addr_el is not None else None
        if not addr:
            continue
        ports: list[dict] = []
        for port in host.iter("port"):
            state_el = port.find("state")
            svc_el = port.find("service")
            portid = port.get("portid") or ""
            ports.append({
                "port": int(portid) if portid.isdigit() else None,
                "protocol": port.get("protocol"),
                "state": state_el.get("state") if state_el is not None else None,
                "service": svc_el.get("name") if svc_el is not None and svc_el.get("name") else None,
            })
        if ports:
            out[addr] = ports
    return out


def run_service_scan(
    ip: str,
    tcp_ports: Optional[list[int]] = None,
    udp_ports: Optional[list[int]] = None,
    timeout: float = 120.0,
) -> tuple[list[dict], Optional[str]]:
    """Blocking nmap port+service scan of one host (run via ``asyncio.to_thread``).

    Probes ``DEFAULT_PROBE_TCP/UDP_PORTS`` merged with ``tcp_ports``/``udp_ports``
    (the host's configured port) using
    ``nmap -Pn -sT -sU -sV -T4 --open -p <spec> -oX - <ip>`` and parses the XML
    from stdout.  Returns ``(services, error)``: every port nmap reported
    (any state) plus a human-facing error string when the probe could not run
    at all (missing binary, timeout, unusable output).

    Command shape notes (each fixed after a live batcave failure, 2026-09-21/22):
    * an explicit TCP scan type is REQUIRED — with only ``-sU`` present and
      ``T:…`` in the port spec, nmap warns "ports include T: but you haven't
      specified any TCP scan type" and scans UDP only;
    * ``-oX -`` mirrors the long-standing ``-oG -`` (grepable → stdout) idiom
      that the L3 sweeps already use — verified to parse in nmap 7.93.  A
      ``-oJ`` element must never be used: in nmap 7.93 there is no JSON output
      and the element re-parses as deprecated ``-o`` + filename "J", which
      shoves the intended output argument into the *target* list.
    """
    tcp = sorted({p for p in (tcp_ports or []) if 0 < p < 65536} | set(DEFAULT_PROBE_TCP_PORTS))
    udp = sorted({p for p in (udp_ports or []) if 0 < p < 65536} | set(DEFAULT_PROBE_UDP_PORTS))
    spec = build_port_spec(tcp, udp)
    cmd = ["nmap", "-Pn", "-sT", "-sU", "-sV", "-T4", "--open", "-p", spec, "-oX", "-", ip]
    diag_log.emit("run_service_scan", f"target={ip}", f"ports: {len(tcp)} tcp, {len(udp)} udp")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return [], "nmap binary not found"
    except subprocess.TimeoutExpired:
        return [], f"service scan timed out after {int(timeout)}s"
    except OSError as exc:
        return [], f"service scan failed: {exc}"
    diag_log.proc("nmap", cmd, proc, f"ports: {len(tcp)} tcp, {len(udp)} udp")
    services = parse_nmap_services_xml(proc.stdout or "")
    if not services:
        detail = (proc.stderr or "").strip()
        return [], f"nmap produced no results (rc={proc.returncode})" + (f": {detail[:300]}" if detail else "")
    diag_log.emit("run_service_scan", f"target={ip}", f"rc={proc.returncode}", f"ports={len(services)}")
    return services, None


def run_port_scan(
    hosts: list[str], timeout: Optional[float] = None,
) -> tuple[dict[str, list[dict]], Optional[str]]:
    """Connect-scan ALL TCP ports of the given live hosts → ``{ip: [open ports]}``.

    Diagnostic aid (the /diagnostic "scan open ports" option), NOT a recovery
    path.  Runs ``nmap -Pn -sT --open -p- …`` over the already-discovered hosts —
    no version detection, so a full 65535-port connect scan stays quick enough to
    fan out over many hosts at once — and parses the XML grouped by host.  A
    failure (missing binary, timeout, unusable output) degrades to an empty map
    plus an error string; it never raises and never runs past its bounded timeout.
    """
    hosts = [h for h in (hosts or []) if h]
    if not hosts:
        return {}, None
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {}, "nmap is not installed; open ports could not be scanned."
    if timeout is None:
        # Bound the wall clock: a fixed floor plus headroom per host, capped so a
        # crowded subnet can't hang the request for minutes on end.
        timeout = min(1800, 120 * len(hosts) + 30)
    cmd = [
        "nmap", "-Pn", "-sT", "-sV", "--open", "-p-",
        "-T4", "--max-retries", "1", "--host-timeout", "120s",
        "-oX", "-", *hosts,
    ]
    diag_log.emit("port-scan", f"hosts={len(hosts)}", f"timeout={int(timeout)}s")
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return {}, "nmap binary not found"
    except subprocess.TimeoutExpired:
        return {}, f"port scan timed out after {int(timeout)}s"
    except OSError as exc:
        return {}, f"port scan failed: {exc}"
    diag_log.proc("port-scan", cmd, proc)
    by_host = parse_nmap_services_by_host(proc.stdout or "")
    diag_log.emit(
        "port-scan", f"rc={proc.returncode}", f"hosts_with_open_ports={len(by_host)}"
    )
    return by_host, None


async def run_port_scan_incremental(
    hosts: list[str],
    callback: Optional[callable] = None,
    timeout: Optional[float] = None,
) -> tuple[dict[str, list[dict]], Optional[str]]:
    """Scan hosts one at a time, invoking ``callback(host_result)`` after each.

    Unlike :func:`run_port_scan` which batches all targets into a single nmap
    invocation, this variant scans hosts sequentially so the caller can surface
    partial results to the UI as soon as each host is done.

    ``callback`` receives a ``dict`` keyed by the host IP (same shape as the
    return value of :func:`run_port_scan`, but for one host only).

    Returns the full aggregated ``{ip: [ports]}`` mapping and any error string.
    """
    # Quick sanity: verify nmap is available before we start
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return {}, "nmap is not installed; open ports could not be scanned."

    by_host: dict[str, list[dict]] = {}

    for i, ip in enumerate(hosts):
        cmd = [
            "nmap", "-Pn", "-sT", "-sV", "--open", "-p-",
            "-T4", "--max-retries", "1", "--host-timeout", "120s",
            "-oX", "-", ip,
        ]
        host_timeout = timeout or 120
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=host_timeout)
        except FileNotFoundError:
            return by_host, "nmap binary not found"
        except subprocess.TimeoutExpired:
            return by_host, f"port scan timed out after {int(host_timeout)}s on {ip}"
        except OSError as exc:
            return by_host, f"port scan failed: {exc}"

        diag_log.proc("port-scan", cmd, proc)
        partial = parse_nmap_services_by_host(proc.stdout or "")
        by_host.update(partial)

        if callback:
            try:
                await callback({**partial, "_index": i, "_total": len(hosts)})
            except Exception:  # noqa: BLE001
                pass  # callback failure must not abort the scan

        diag_log.emit(
            "port-scan",
            f"host={ip}",
            f"open_ports={sum(len(v) for v in partial.values())}",
            f"progress={i+1}/{len(hosts)}",
        )

    return by_host, None


async def probe_services(
    ip: str,
    tcp_ports: Optional[list[int]] = None,
    udp_ports: Optional[list[int]] = None,
    timeout: float = 60.0,
) -> dict:
    """Async wrapper around :func:`run_service_scan`.

    Returns ``{"ok": bool, "error": str|None, "services": [...]}`` so a
    failed probe degrades to an empty result instead of aborting the caller.
    """
    try:
        services, error = await asyncio.to_thread(
            run_service_scan, ip, tcp_ports, udp_ports, timeout
        )
    except Exception as exc:  # noqa: BLE001 - a probe error is a result, not a crash
        return {"ok": False, "error": f"service scan failed: {exc}", "services": []}
    return {"ok": error is None, "error": error, "services": services}


def _arp_sweep_rows(subnets: Optional[list[str]]) -> tuple[list[dict], Optional[str]]:
    """One full ARP sweep → every responder as ``[{ip, mac, detail}]``.

    arp-scan first; if it produced nothing *and* reported an error (missing
    binary, no routable sweep) we retry via the scapy fallback.  Both
    directions of validation (MAC→IP *and* IP→MAC) read off this one run,
    and tunnel subnets are probed at L3 inside :func:`run_arp_scan` — whose
    synthetic rows carry ``mac=None`` (the ``--`` marker).
    """
    _, output, error = run_arp_scan(subnets=subnets)
    rows = _parse_scan_output(output, subnets)
    if rows or not error:
        return rows, error
    _, output, error = run_scapy_scan("00:00:00:00:00:00", None, subnets=subnets)
    rows = _parse_scan_output(output, subnets)
    return rows, (error if not rows else None)


async def sweep_responder_hosts(subnets: Optional[list[str]] = None) -> tuple[list[dict], Optional[str]]:
    """Async wrapper around :func:`_arp_sweep_rows` (blocking work off the loop)."""
    return await asyncio.to_thread(_arp_sweep_rows, subnets)


async def resolve_hostname(
    ip: Optional[str] = None,
    mac: Optional[str] = None,
    db=None,
    mdns: Optional[tuple[dict[str, str], dict[str, str]]] = None,
) -> Optional[str]:
    """Best-effort hostname for one host, via the same layered chain as the scan page.

    ``ip`` and/or ``mac`` may be supplied; ``mdns`` is an optional pre-fetched
    ``(ip_map, mac_map)`` pair — pass one shared mDNS browse when resolving
    several hosts (a fresh 8 s window otherwise).  Priority mirrors
    :func:`apply_hostnames`: curated DB name (by MAC) → live mDNS (by IP,
    then by MAC) → mDNS cache (by MAC) → reverse DNS.
    """
    ip = (ip or "").strip() or None
    mac = normalize_mac(mac) if (mac or "").strip() else None
    if mdns is None:
        mdns = await discover_hostnames()
    mdns_ip_map, mdns_mac_map = mdns
    known: dict[str, str] = {}
    cached: dict[str, str] = {}
    if db is not None:
        known = await load_known_hostnames(db)
        cached = await load_mdns_names(db)
    name = None
    if mac:
        name = known.get(mac) or mdns_mac_map.get(mac) or cached.get(mac)
    if name is None and ip:
        name = mdns_ip_map.get(ip)
    if name is None and ip:
        try:
            # gethostbyaddr returns a (hostname, aliases, addrlist) tuple.
            name = (await asyncio.to_thread(socket.gethostbyaddr, ip))[0]
        except OSError:
            name = None
    return name or None


async def validate_host_record(
    db,
    *,
    name: str,
    mac: str,
    ip: str,
    port: int,
    subnet_cidrs: Optional[list[str]] = None,
) -> dict:
    """Run the edit screen's *Validate* check for one host; returns UI JSON.

    One ARP sweep (matched in both directions), one mDNS browse (shared by
    every hostname resolution), one nmap port/service probe per distinct IP
    of interest (the entered IP and/or the IP the entered MAC answers on).
    Returns ``{"sweep": {...}, "mac": {...}|None, "ip": {...}|None}``.
    Log-only: never mutates the host record.
    """
    mac = normalize_mac(mac) if (mac or "").strip() else None
    ip = (ip or "").strip() or None
    port = int(port or 0) or None
    diag_log.emit(
        "validate_host", f"host={name}", f"mac={mac}", f"ip={ip}",
        f"port={port}", f"subnets={subnet_cidrs}",
    )

    rows, sweep_error = await sweep_responder_hosts(subnet_cidrs)

    try:
        mdns = await discover_hostnames()
        if db is not None:
            await remember_mdns_names(db, mdns[1])
    except Exception:  # noqa: BLE001 - discovery must never fail the validation
        mdns = ({}, {})

    mac_row = None
    ip_row = None
    if mac:
        mac_row = next((r for r in rows if r.get("mac") and normalize_mac(r["mac"]) == mac), None)
    if ip:
        ip_row = next((r for r in rows if (r.get("ip") or "") == ip), None)

    found_ip = (mac_row or {}).get("ip") if mac_row else None
    found_mac = (ip_row or {}).get("mac") if ip_row else None  # None when L3-routed

    # One probe per distinct IP, in parallel. Always include the host's own
    # monitored port so its state is derivable even when it is not a default
    # service-scan port (e.g. 8787/8181/11000) — ``run_service_scan`` merges
    # ``tcp_ports`` into the defaults. With ``--open`` an absent port is
    # closed/filtered, so the host port's state is derivable below.
    probe_targets = sorted({t for t in (ip, found_ip) if t})
    probe_tcp = [port] if port else None
    probes: dict[str, dict] = dict(
        zip(
            probe_targets,
            await asyncio.gather(*[probe_services(t, tcp_ports=probe_tcp) for t in probe_targets]),
        )
    ) if probe_targets else {}
    hostnames: dict[str, str] = {}
    for target in probe_targets:
        row_mac = normalize_mac(found_mac) if (found_mac and target in (ip, found_ip)) else None
        hostnames[target] = await resolve_hostname(ip=target, mac=row_mac, db=db, mdns=mdns)

    result: dict = {
        "sweep": {
            "subnets": subnet_cidrs or None,
            "responders": len(rows),
            "error": sweep_error,
        },
        "mac": None,
        "ip": None,
    }
    if mac:
        mac_probe = probes.get(found_ip) or {}
        result["mac"] = {
            "target": mac,
            "found": bool(mac_row),
            "ip": found_ip,
            "hostname": hostnames.get(found_ip) if found_ip else None,
            "services": mac_probe.get("services", []) if found_ip else [],
            "services_error": mac_probe.get("error") if found_ip else None,
        }
    if ip:
        ip_probe = probes.get(ip) or {}
        services = ip_probe.get("services", [])
        port_state = None
        if port:
            matching = [s for s in services if s.get("protocol") == "tcp" and s.get("port") == port]
            port_state = matching[0].get("state") if matching else "closed"
        result["ip"] = {
            "target": ip,
            "mac": found_mac,
            "mac_routed": bool(ip_row and not ip_row.get("mac") and "routed" in (ip_row.get("detail") or "")),
            "hostname": hostnames.get(ip),
            "port": port,
            "port_state": port_state,
            "services": services,
            "services_error": ip_probe.get("error"),
        }
    diag_log.emit(
        "validate_host", f"host={name}", "done",
        f"mac_found={bool(result['mac'] and result['mac']['found'])}",
        f"ip_mac={result['ip']['mac'] if result['ip'] else None}",
    )
    return result