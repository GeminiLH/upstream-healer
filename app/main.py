import asyncio
import ipaddress
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import aiosqlite
import json

from app.config import current_time, format_timestamp, settings, time_ago
from app.database import init_db
from app.services.monitor import monitor
from app.services import diag_log
from app.services.npm import NPMClient
from app.services.notifications import send_event
from app.services.mdns import discover_hostnames
from app.services.scanner import (
    apply_hostnames,
    check_host_reachable,
    find_ip_by_mac,
    get_default_subnets,
    get_local_interfaces,
    list_subnets,
    load_known_hostnames,
    load_known_hostnames_by_ip,
    load_mdns_names,
    load_suppressed_subnets,
    normalize_mac,
    remember_mdns_names,
    run_port_scan_incremental,
    run_scan,
    save_suppressed_subnets,
    validate_host_record,
)

# Global dictionary to track scan progress by request ID
scan_progress = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("healer")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await monitor.start()
    logger.info("Upstream Healer started")
    yield
    await monitor.stop()


app = FastAPI(title="Upstream Healer", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


async def get_db():
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()


# ───────────────────────────── Dashboard ─────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        """SELECT h.*, s.status, s.last_seen_at, s.unreachable_since, s.last_check_at, s.last_ip,
                 sn.name AS subnet_name
            FROM hosts h
            LEFT JOIN host_state s ON s.host_id = h.id
            LEFT JOIN subnets sn ON sn.id = h.subnet_id
            ORDER BY h.name, h.port"""
    ) as cursor:
        hosts = [dict(r) for r in await cursor.fetchall()]
    # A box can be watched on several ports via several records that share one
    # MAC. Count the other records per MAC so each card can flag the device it
    # belongs to — transparent multi-port monitoring at a glance.
    mac_counts: dict[str, int] = {}
    for host in hosts:
        key = (host.get("mac_address") or "").strip().lower()
        if key:
            mac_counts[key] = mac_counts.get(key, 0) + 1
    for host in hosts:
        key = (host.get("mac_address") or "").strip().lower()
        host["device_peer_count"] = max(0, mac_counts.get(key, 0) - 1)
    for host in hosts:
        if host["last_check_at"]:
            host["last_check_display"] = format_timestamp(host["last_check_at"])
            host["last_check_age"] = time_ago(host["last_check_at"])

    monitored_hosts = [host for host in hosts if host["enabled"]]
    healthy_hosts = [host for host in monitored_hosts if host["status"] == "healthy"]
    if not monitored_hosts:
        overall_status = "unknown"
        overall_status_label = "No hosts monitored"
    elif len(healthy_hosts) == len(monitored_hosts):
        overall_status = "healthy"
        overall_status_label = "All hosts reachable"
    elif len(healthy_hosts) == 0:
        overall_status = "down"
        overall_status_label = "All hosts unreachable"
    else:
        overall_status = "degraded"
        overall_status_label = "Some hosts unreachable"

    async with db.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 20"
    ) as cursor:
        events = [dict(r) for r in await cursor.fetchall()]
    for event in events:
        if event["created_at"]:
            event["created_at_display"] = format_timestamp(event["created_at"])

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "hosts": hosts,
            "events": events,
            "now": current_time(),
            "overall_status": overall_status,
            "overall_status_label": overall_status_label,
        },
    )


@app.get("/hosts/{host_id}/events", response_class=HTMLResponse)
async def host_events(host_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT id, name FROM hosts WHERE id = ?", (host_id,)) as cursor:
        host = await cursor.fetchone()
    if not host:
        raise HTTPException(404)

    async with db.execute(
        "SELECT * FROM events WHERE host_id = ? ORDER BY id DESC", (host_id,)
    ) as cursor:
        events = [dict(row) for row in await cursor.fetchall()]
    for event in events:
        if event["created_at"]:
            event["created_at_display"] = format_timestamp(event["created_at"])

    return templates.TemplateResponse(
        request,
        "host_events.html",
        {"host": dict(host), "events": events},
    )


@app.post("/events/clear")
async def clear_events(db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM events")
    await db.commit()
    return RedirectResponse("/", status_code=303)


# ───────────────────────────── Hosts ─────────────────────────────

@app.get("/hosts/add", response_class=HTMLResponse)
async def add_host_form(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    return await _render_host_form(request, db, "Add Host", None)


def _first_domain(domain_names):
    """NPM stores ``domain_names`` as a JSON array (as text). Return the first
    domain for display, or '' when absent/unparseable."""
    if isinstance(domain_names, (list, tuple)):
        return domain_names[0] if domain_names else ""
    if isinstance(domain_names, str) and domain_names.strip():
        text = domain_names.strip()
        if text.startswith("["):
            try:
                parsed = json.loads(text)
                if isinstance(parsed, list) and parsed:
                    return parsed[0]
            except (ValueError, TypeError):
                pass
        return text
    return ""


def _subnet_for_ip(host, subnets):
    """Best-effort subnet CIDR for a proxy host's forward address, offered when
    the user picks an NPM proxy host in the form. Prefers the first *known*
    subnet that contains the address (so VLANs wider/narrower than /24 resolve
    correctly); falls back to the address's own /24. Returns ``None`` when the
    forward address is not an IPv4 (e.g. an upstream domain) so no subnet is
    offered.
    """
    if not host:
        return None
    try:
        addr = ipaddress.ip_address(str(host).strip())
    except ValueError:
        return None
    if addr.version != 4:
        return None
    for s in subnets:
        try:
            if addr in ipaddress.ip_network(s.get("cidr"), strict=False):
                return s.get("cidr")
        except (ValueError, TypeError):
            continue
    # strict=False so a host address (e.g. 192.168.86.249) is normalised to its
    # /24 network address instead of raising "has host bits set".
    return str(ipaddress.ip_network((str(addr), 24), strict=False))


def _npm_forward_for(npm_id):
    """Return the linked NPM proxy host's ``forward_host:forward_port`` (plus
    the first domain label) so the add/edit form can warn when the record the
    user is entering does not match where NPM actually points. ``None`` when
    there is no linked ID, NPM is unreachable, or the row is missing."""
    if not npm_id:
        return None
    npm = NPMClient()
    try:
        ph = npm.get_proxy_host(npm_id)
    except Exception:  # noqa: BLE001 - NPM down must not block the form
        ph = None
    if not ph or not ph.get("forward_host"):
        return None
    return {
        "id": npm_id,
        "domain": _first_domain(ph.get("domain_names")),
        "forward_host": ph["forward_host"],
        "forward_port": ph.get("forward_port") or 80,
    }


def _resolve_selected_subnet(subnets, host):
    """The CIDR to preselect in the subnet dropdown. Auto-detected subnets have
    no DB id, so a pin may live in ``subnet_cidr`` (auto) or ``subnet_id``
    (manual) — normalise both to a CIDR."""
    if not host:
        return None
    cidr = host.get("subnet_cidr")
    if not cidr and host.get("subnet_id"):
        for s in subnets:
            if s.get("id") == host["subnet_id"]:
                cidr = s.get("cidr")
                break
    return cidr or None


def _parse_subnet_form(subnet_id: str):
    """The subnet dropdown's value is the network's CIDR (auto-detected
    subnets have no DB id; manual rows are also posted as CIDR). A lone number
    is treated as a manual row id for backwards compatibility. Returns
    ``(subnet_id, subnet_cidr)``."""
    value = (subnet_id or "").strip()
    if not value:
        return None, None
    if value.isdigit():
        return int(value), None
    return None, value


async def _render_host_form(
    request: Request,
    db: aiosqlite.Connection,
    title: str,
    host,
    error=None,
    npm_mismatch=None,
):
    """Render host_form.html with the live proxy-host + subnet lists. ``host``
    is the row (or a repopulated dict) carrying the submitted values; ``error``
    is a red banner (e.g. a MAC+port conflict) and ``npm_mismatch`` drives the
    amber NPM mismatch warning with its 3 resolution buttons."""
    npm = NPMClient()
    try:
        proxy_hosts = npm.list_proxy_hosts()
    except Exception:  # noqa: BLE001
        proxy_hosts = []
    subnets = await list_subnets(db)
    for ph in proxy_hosts:
        ph["domain"] = _first_domain(ph.get("domain_names"))
        ph["subnet"] = _subnet_for_ip(ph.get("forward_host"), subnets)
    return templates.TemplateResponse(
        request,
        "host_form.html",
        {
            "host": host,
            "proxy_hosts": proxy_hosts,
            "subnets": subnets,
            "selected_subnet": _resolve_selected_subnet(subnets, host),
            "title": title,
            "error": error,
            "npm_mismatch": npm_mismatch,
        },
    )


async def _render_host_form_conflict(
    request: Request,
    db: aiosqlite.Connection,
    title: str,
    conflict_name: str,
    mac: str,
    port: int,
    form: dict,
):
    """Re-render the host form with an error banner when the submitted
    (mac_address, port) collides with another host. ``form`` carries the
    submitted values (plus the existing row's ``id`` on edit) so the user
    can correct the conflicting fields in place instead of losing the form.
    """
    return await _render_host_form(
        request,
        db,
        title,
        form,
        error=(
            f"MAC {mac} on port {port} is already used by host '{conflict_name}' — "
            f"every host needs a unique MAC + port combination."
        ),
    )


@app.post("/hosts/add")
async def add_host(
    request: Request,
    name: str = Form(...),
    local_device_name: str = Form(""),
    quiet_enabled: str = Form("off"),
    quiet_start: str = Form(""),
    quiet_end: str = Form(""),
    quiet_mode: str = Form("suppress"),
    domain: str = Form(""),
    mac_address: str = Form(...),
    current_ip: str = Form(""),
    port: int = Form(80),
    npm_proxy_host_id: str = Form(""),
    subnet_id: str = Form(""),
    npm_action: str = Form(""),
    grace_minutes: int = Form(10),
    notes: str = Form(""),
    db: aiosqlite.Connection = Depends(get_db),
):
    mac = normalize_mac(mac_address)
    npm_id = int(npm_proxy_host_id) if npm_proxy_host_id.strip() else None
    subnet, subnet_cidr = _parse_subnet_form(subnet_id)
    if not 1 <= port <= 65535:
        raise HTTPException(400, "Port must be between 1 and 65535")

    quiet_mode = quiet_mode if quiet_mode in ("suppress", "delete") else "suppress"
    repopulated = {
        "name": name,
        "local_device_name": local_device_name or None,
        "quiet_enabled": quiet_enabled == "on",
        "quiet_start": quiet_start or None,
        "quiet_end": quiet_end or None,
        "quiet_mode": quiet_mode,
        "domain": domain,
        "mac_address": mac,
        "current_ip": current_ip or None,
        "npm_proxy_host_id": npm_id,
        "subnet_id": subnet,
        "subnet_cidr": subnet_cidr,
        "port": port,
        "grace_minutes": grace_minutes,
        "notes": notes,
        "enabled": 1,
    }

    # The user just picked a linked NPM host. If the record they are entering
    # does not match where NPM points, stop and offer 3 resolutions; the chosen
    # button re-posts with ``npm_action`` set (match / link / cancel).
    fwd = _npm_forward_for(npm_id)
    eff_ip = current_ip or ""
    eff_port = port
    eff_npm_id = npm_id
    if npm_action == "match" and fwd:
        eff_ip, eff_port = fwd["forward_host"], fwd["forward_port"]
    elif npm_action == "cancel":
        eff_npm_id = None
    # "link" (keep the entered IP:port) skips the mismatch prompt below — the
    # user already resolved it; only the initial selection (empty npm_action)
    # still stops to offer the 3 resolutions.
    elif npm_action != "link" and fwd and (fwd["forward_host"] != eff_ip or fwd["forward_port"] != eff_port):
        return await _render_host_form(request, db, "Add Host", repopulated, npm_mismatch=fwd)

    # (mac_address, port) is UNIQUE — check before the INSERT so a collision
    # returns a clear error naming the other host instead of a 500 from the
    # constraint.
    async with db.execute(
        "SELECT id, name FROM hosts WHERE mac_address = ? AND port = ?", (mac, eff_port)
    ) as cur:
        conflict = await cur.fetchone()
    if conflict:
        conflict_form = dict(repopulated)
        conflict_form.update(
            {"current_ip": eff_ip or None, "npm_proxy_host_id": eff_npm_id, "port": eff_port}
        )
        return await _render_host_form_conflict(
            request, db, "Add Host", conflict["name"], mac, eff_port, conflict_form,
        )

    await db.execute(
            """INSERT INTO hosts (name, local_device_name, quiet_enabled, quiet_start, quiet_end, quiet_mode,
                domain, mac_address, current_ip, npm_proxy_host_id, subnet_id, subnet_cidr, port, grace_minutes, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, local_device_name or None, quiet_enabled == "on", quiet_start or None, quiet_end or None,
             quiet_mode, domain, mac, eff_ip or None,
             eff_npm_id, subnet, subnet_cidr, eff_port, grace_minutes, notes,
            current_time().isoformat(), current_time().isoformat()),
    )
    await db.commit()

    # Create state row
    async with db.execute("SELECT last_insert_rowid()") as cur:
        host_id = (await cur.fetchone())[0]
    await db.execute(
        "INSERT INTO host_state (host_id, status, last_ip) VALUES (?, 'unknown', ?)",
        (host_id, eff_ip or None),
    )
    await db.commit()

    return RedirectResponse("/", status_code=303)


@app.get("/hosts/{host_id}/edit", response_class=HTMLResponse)
async def edit_host_form(host_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)) as cur:
        host = await cur.fetchone()
    if not host:
        raise HTTPException(404)
    return await _render_host_form(request, db, "Edit Host", dict(host))


@app.post("/hosts/{host_id}/edit")
async def edit_host(
    request: Request,
    host_id: int,
    name: str = Form(...),
    local_device_name: str = Form(""),
    quiet_enabled: str = Form("off"),
    quiet_start: str = Form(""),
    quiet_end: str = Form(""),
    quiet_mode: str = Form("suppress"),
    domain: str = Form(""),
    mac_address: str = Form(...),
    current_ip: str = Form(""),
    port: int = Form(80),
    npm_proxy_host_id: str = Form(""),
    subnet_id: str = Form(""),
    npm_action: str = Form(""),
    grace_minutes: int = Form(10),
    notes: str = Form(""),
    enabled: str = Form("off"),
    db: aiosqlite.Connection = Depends(get_db),
):
    mac = normalize_mac(mac_address)
    npm_id = int(npm_proxy_host_id) if npm_proxy_host_id.strip() else None
    subnet, subnet_cidr = _parse_subnet_form(subnet_id)
    is_enabled = 1 if enabled == "on" else 0
    if not 1 <= port <= 65535:
        raise HTTPException(400, "Port must be between 1 and 65535")

    async with db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)) as cur:
        existing = await cur.fetchone()
    if not existing:
        raise HTTPException(404, f"Host {host_id} not found")

    quiet_mode = quiet_mode if quiet_mode in ("suppress", "delete") else "suppress"
    original_npm_id = existing["npm_proxy_host_id"]
    # Effective (mac/port/ip) + link the host will be saved with, honouring the
    # NPM mismatch resolution the user just chose (empty = initial selection).
    eff_ip = current_ip or ""
    eff_port = port
    eff_npm_id = npm_id

    # The user just picked a linked NPM host. If the record they are entering
    # does not match where NPM points, stop and offer 3 resolutions; the chosen
    # button re-posts with ``npm_action`` set (match / link / cancel).
    fwd = _npm_forward_for(npm_id)
    if npm_action == "match" and fwd:
        eff_ip, eff_port = fwd["forward_host"], fwd["forward_port"]
    elif npm_action == "cancel":
        eff_npm_id = original_npm_id
    # "link" keeps the entered IP:port — once the user resolved the mismatch by
    # choosing to link anyway, skip the prompt and save with the entered values.
    elif npm_action != "link" and fwd and (fwd["forward_host"] != eff_ip or fwd["forward_port"] != eff_port):
        repopulated = dict(existing)
        repopulated.update(
            {
                "name": name,
                "local_device_name": local_device_name or None,
                "quiet_enabled": quiet_enabled == "on",
                "quiet_start": quiet_start or None,
                "quiet_end": quiet_end or None,
                "quiet_mode": quiet_mode,
                "domain": domain,
                "mac_address": mac,
                "current_ip": current_ip or None,
                "npm_proxy_host_id": npm_id,
                "subnet_id": subnet,
                "subnet_cidr": subnet_cidr,
                "port": port,
                "grace_minutes": grace_minutes,
                "notes": notes,
                "enabled": is_enabled,
            }
        )
        return await _render_host_form(request, db, "Edit Host", repopulated, npm_mismatch=fwd)

    # (mac_address, port) is UNIQUE — check before the UPDATE so a collision
    # with another host returns a clear error naming it instead of a 500
    # from the constraint. Saving the host's own MAC + port is fine.
    if (mac, eff_port) != (existing["mac_address"], existing["port"]):
        async with db.execute(
            "SELECT id, name FROM hosts WHERE mac_address = ? AND port = ? AND id != ?",
            (mac, eff_port, host_id),
        ) as cur:
            conflict = await cur.fetchone()
        if conflict:
            repopulated = dict(existing)
            repopulated.update(
                {
                    "name": name,
                    "local_device_name": local_device_name or None,
                    "quiet_enabled": quiet_enabled == "on",
                    "quiet_start": quiet_start or None,
                    "quiet_end": quiet_end or None,
                    "quiet_mode": quiet_mode,
                    "domain": domain,
                    "mac_address": mac,
                    "current_ip": eff_ip or None,
                    "npm_proxy_host_id": eff_npm_id,
                    "subnet_id": subnet,
                    "subnet_cidr": subnet_cidr,
                    "port": eff_port,
                    "grace_minutes": grace_minutes,
                    "notes": notes,
                    "enabled": is_enabled,
                }
            )
            return await _render_host_form_conflict(
                request, db, "Edit Host", conflict["name"], mac, eff_port, repopulated,
            )

    await db.execute(
        """UPDATE hosts SET
            name = ?, local_device_name = ?, quiet_enabled = ?, quiet_start = ?, quiet_end = ?, quiet_mode = ?,
            domain = ?, mac_address = ?, current_ip = ?,
            npm_proxy_host_id = ?, subnet_id = ?, subnet_cidr = ?, port = ?, grace_minutes = ?, notes = ?, enabled = ?,
                updated_at = ?
            WHERE id = ?""",
            (name, local_device_name or None, quiet_enabled == "on", quiet_start or None, quiet_end or None,
             quiet_mode, domain, mac, eff_ip or None,
             eff_npm_id, subnet, subnet_cidr, eff_port, grace_minutes, notes, is_enabled,
            current_time().isoformat(), host_id),
    )
    await db.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/hosts/{host_id}/delete")
async def delete_host(host_id: int, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
    await db.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/hosts/{host_id}/force-scan")
async def force_scan(host_id: int, db: aiosqlite.Connection = Depends(get_db)):
    """Run an immediate IP/port + MAC check for a host. If the ARP sweep finds
    the host at a *new* address, adopt it (``hosts.current_ip``) and — when the
    host is linked — point the matching NPM proxy host at the new address too.
    The event records the old→new IP and whether the NPM record was updated and
    what it was changed from/to."""
    async with db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)) as cur:
        host = await cur.fetchone()
    if not host:
        raise HTTPException(404)

    name = host["name"]
    old_ip = host["current_ip"]
    port = host["port"] or 80
    recorded_mac = normalize_mac(host["mac_address"])
    checked_at = current_time().isoformat()
    npm_id = host["npm_proxy_host_id"]

    ip_port_ok = bool(old_ip) and await check_host_reachable(old_ip, port=port)
    mac_ip = await find_ip_by_mac(recorded_mac)
    mac_ok = mac_ip is not None

    # The ARP sweep is the authoritative view of where this MAC answers now.
    # If it differs from the stored IP, adopt it and — when the host is linked
    # — update the NPM proxy host, recording what the forward used to be.
    ip_changed = bool(mac_ip) and mac_ip != old_ip
    npm_note = None
    if npm_id and ip_changed:
        npm = NPMClient()
        old_fwd = None
        ph = None
        try:
            ph = npm.get_proxy_host(npm_id)
            old_fwd = ph.get("forward_host") if ph else None
        except Exception:  # noqa: BLE001 - NPM down must not abort the scan
            ph = None
        if old_fwd and old_fwd != mac_ip:
            updated = npm.update_forward_host(npm_id, mac_ip)
            reloaded = npm.reload_nginx() if updated else False
            npm_note = (
                f"NPM proxy host #{npm_id} forward updated {old_fwd} → {mac_ip}; "
                f"nginx reload {'OK' if reloaded else 'FAILED'}"
                if updated
                else f"NPM proxy host #{npm_id} update failed (was {old_fwd})"
            )
        elif ph is None:
            npm_note = f"NPM proxy host #{npm_id} not found — not updated"

    if ip_changed:
        await db.execute(
            "UPDATE hosts SET current_ip = ?, updated_at = ? WHERE id = ?",
            (mac_ip, checked_at, host_id),
        )

    reached = ip_port_ok or mac_ok
    await db.execute(
        "INSERT OR IGNORE INTO host_state (host_id, status) VALUES (?, 'unknown')",
        (host_id,),
    )
    await db.execute(
        """UPDATE host_state SET
            status = ?,
            unreachable_since = CASE WHEN ? THEN NULL ELSE unreachable_since END,
            last_check_at = ?,
            last_seen_at = CASE WHEN ? THEN ? ELSE last_seen_at END,
            last_ip = COALESCE(?, last_ip)
            WHERE host_id = ?""",
        ("healthy" if reached else "unreachable", reached, checked_at,
         reached, checked_at, mac_ip, host_id),
    )
    await db.commit()

    logger.info(
        "force_scan %s (id=%s, port=%s): ip/port=%s mac_verified=%s reached=%s%s",
        name, host_id, port,
        "ok" if ip_port_ok else "fail",
        "ok" if mac_ok else "fail",
        "yes" if reached else "no",
        f" ip {old_ip} -> {mac_ip}" if ip_changed else "",
    )
    npm_summary = f"configured (ID {npm_id})" if npm_id else "not configured"
    details = (
        f"IP/port check: {'SUCCESS' if ip_port_ok else 'FAILURE'}; "
        f"current IP: {old_ip or 'none'}; port: {port}; "
        f"MAC verification: {'SUCCESS' if mac_ok else 'FAILURE'}; "
        f"recorded MAC: {recorded_mac}; MAC-discovered IP: {mac_ip or 'none'}; "
        + (f"IP changed: {old_ip} → {mac_ip}; " if ip_changed else "")
        + (f"{npm_note}; " if npm_note else "")
        + f"NPM host ID: {npm_summary}; last check reset: {checked_at}"
    )
    message = (
        f"🔎 Force scan for {name}: IP/port {'passed' if ip_port_ok else 'failed'}, "
        f"MAC {'verified' if mac_ok else 'not verified'}"
    )
    if ip_changed:
        message += f", IP updated {old_ip} → {mac_ip}"
    await send_event(
        db,
        "manual",
        message + ".",
        details=details,
        host_id=host_id,
        notify=False,
    )
    return RedirectResponse("/", status_code=303)


class ValidateHostRequest(BaseModel):
    """Values *currently in the edit form*.

    Validate tests what the user has typed so far — any empty field falls
    back to the saved host row, so it works mid-edit.
    """

    mac: str = ""
    ip: str = ""
    port: int = Field(0, ge=0, le=65535)
    subnet_id: int = Field(0, ge=0)
    subnet_cidr: str = ""


class ValidateNewHostRequest(BaseModel):
    """Values *currently in the add form* — the host is not saved yet, so there
    is no stored row to fall back to and no host_id to attach the results to.
    ``name`` is the (not-yet-unique) label the operator is typing, used only
    for logging. At least one of ``mac``/``ip`` must be present to sweep."""

    name: str = ""
    mac: str = ""
    ip: str = ""
    port: int = Field(0, ge=0, le=65535)
    subnet_cidr: str = ""


@app.post("/hosts/validate")
async def validate_new_host(body: ValidateNewHostRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Validate a *not-yet-saved* host's entered MAC/IP (log-only) so the
    operator can populate the add-host record from the results: for the entered
    MAC, the IP it answers on + hostname + open ports; for the entered IP, its
    MAC, hostname and open ports. Returns the same UI JSON as the edit screen's
    validate. Never mutates anything and attaches to no saved host (none exists
    yet), so the logged event has no host_id.
    """
    mac = (body.mac or "").strip()
    ip = (body.ip or "").strip()
    if not mac and not ip:
        raise HTTPException(status_code=400, detail="Nothing to validate: enter a MAC address or an IP first")
    port = body.port or 80

    # Sweep scope: the add form's subnet dropdown (a CIDR) → every enabled subnet.
    import ipaddress as _ip

    subnets = None
    if body.subnet_cidr:
        try:
            _ip.ip_network(body.subnet_cidr, strict=False)
            subnets = [body.subnet_cidr]
        except ValueError:
            subnets = None
    if subnets is None:
        subnets = [s["cidr"] for s in await list_subnets(db) if s.get("enabled", 1)]

    name = (body.name or "").strip() or "new host"
    with diag_log.scan_context(
        target_mac=mac or "none", method="validate", subnets=subnets
    ):
        result = await validate_host_record(
            db, name=name, mac=mac, ip=ip, port=port, subnet_cidrs=subnets or None
        )

    mac_res = result.get("mac") or {}
    ip_res = result.get("ip") or {}
    summary = []
    if mac_res:
        summary.append(
            f"MAC {mac_res.get('target')} found at {mac_res.get('ip')}"
            if mac_res.get("found")
            else f"MAC {mac} not found on swept networks"
        )
    if ip_res:
        summary.append(f"{ip} answers as {ip_res.get('mac') or 'no MAC (routed)'}")
    message = f"Validation for {name} (port {port}): " + ("; ".join(summary) if summary else "no results")
    await send_event(
        db, "manual", message.strip() or f"Validation for {name}",
        details=(
            f"requested: mac={mac or 'none'}, ip={ip or 'none'}, port={port}; "
            f"found: mac.ip={mac_res.get('ip') or 'none'}, ip.mac={ip_res.get('mac') or 'none'}; "
            f"hostname: {ip_res.get('hostname') or mac_res.get('hostname') or 'none'}"
        ),
        host_id=None,
        notify=False,
    )
    return result


@app.post("/hosts/{host_id}/validate")
async def validate_host(host_id: int, body: ValidateHostRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Validate a host's entered details against the live network (log-only).

    The edit screen's *Validate* button posts the form's current values.
    Returns what the network actually shows — for the entered MAC: the IP it
    answers on, hostname and open ports; for the entered IP: its MAC,
    hostname and open ports — so the operator can correct the record from
    the results popup.  Never mutates anything.
    """
    async with db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)) as cur:
        row = await cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Host {host_id} not found")
    host = dict(row)
    mac = (body.mac or host.get("mac_address") or "").strip()
    ip = (body.ip or host.get("current_ip") or "").strip()
    if not mac and not ip:
        raise HTTPException(status_code=400, detail="Nothing to validate: this host has no MAC address and no IP")
    port = body.port or host.get("port") or 80

    # Sweep scope, CIDR-first (auto-detected subnets have no DB id): the form's
    # subnet dropdown → the saved pin (subnet_cidr, else numeric subnet_id) →
    # every known subnet.
    import ipaddress as _ip

    subnets = None
    for candidate in (body.subnet_cidr, host.get("subnet_cidr")):
        if not candidate:
            continue
        try:
            _ip.ip_network(candidate, strict=False)
        except ValueError:
            subnets = None
            break
        subnets = [candidate]
        break
    if subnets is None:
        subnet_id = body.subnet_id or host.get("subnet_id") or 0
        if subnet_id:
            async with db.execute(
                "SELECT cidr FROM subnets WHERE id = ? AND enabled = 1", (subnet_id,)
            ) as cur:
                subnet_row = await cur.fetchone()
            if subnet_row:
                subnets = [subnet_row["cidr"]]
    if subnets is None:
        subnets = [s["cidr"] for s in await list_subnets(db) if s.get("enabled", 1)]

    # Same per-run diag log the diagnostic scan writes (dev-only: the prod
    # compose leaves UPSTREAM_HEALER_DEBUG_LOG_DIR unset → all no-ops).  Gives
    # the exact nmap command + raw stderr in /logs for post-hoc review.
    with diag_log.scan_context(
        target_mac=mac or "none", method="validate", subnets=subnets
    ):
        result = await validate_host_record(
            db, name=host["name"], mac=mac, ip=ip, port=port, subnet_cidrs=subnets or None
        )

    mac_res = result.get("mac") or {}
    ip_res = result.get("ip") or {}
    summary = []
    if mac_res:
        summary.append(
            f"MAC {mac_res.get('target')} found at {mac_res.get('ip')}"
            if mac_res.get("found")
            else f"MAC {mac} not found on swept networks"
        )
    if ip_res:
        summary.append(f"{ip} answers as {ip_res.get('mac') or 'no MAC (routed)'}")
    message = f"Validation for {host['name']} (port {port}): " + ("; ".join(summary) if summary else "no results")
    await send_event(
        db, "manual", message.strip() or f"Validation for {host['name']}",
        details=(
            f"requested: mac={mac or 'none'}, ip={ip or 'none'}, port={port}; "
            f"found: mac.ip={mac_res.get('ip') or 'none'}, ip.mac={ip_res.get('mac') or 'none'}; "
            f"hostname: {ip_res.get('hostname') or mac_res.get('hostname') or 'none'}"
        ),
        host_id=host_id,
        notify=False,
    )
    return result


# ───────────────────────────── Notifications ─────────────────────────────

@app.get("/notifications", response_class=HTMLResponse)
async def notifications_page(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM notification_channels ORDER BY id") as cur:
        channels = [dict(r) for r in await cur.fetchall()]

    # Attach rules
    for ch in channels:
        ch["config"] = json.loads(ch["config"])
        async with db.execute(
            "SELECT event_type, enabled FROM notification_rules WHERE channel_id = ?",
            (ch["id"],),
        ) as cur:
            ch["rules"] = {r["event_type"]: r["enabled"] for r in await cur.fetchall()}

    return templates.TemplateResponse(
        request,
        "notifications.html",
        {
            "channels": channels,
            "event_types": [
                "unreachable", "scan_started", "ip_found", "updated", "recovered", "failed", "manual"
            ],
        },
    )


@app.get("/notifications/add/telegram", response_class=HTMLResponse)
async def add_telegram_form(request: Request):
    return templates.TemplateResponse(
        request,
        "channel_telegram.html",
        {"channel": None},
    )


@app.get("/notifications/channel/{channel_id}/edit", response_class=HTMLResponse)
async def edit_telegram_form(
    channel_id: int,
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
):
    async with db.execute(
        "SELECT * FROM notification_channels WHERE id = ? AND type = 'telegram'",
        (channel_id,),
    ) as cur:
        channel = await cur.fetchone()
    if not channel:
        raise HTTPException(404)

    channel = dict(channel)
    channel["config"] = json.loads(channel["config"])
    return templates.TemplateResponse(
        request,
        "channel_telegram.html",
        {"channel": channel},
    )


@app.post("/notifications/add/telegram")
async def add_telegram(
    name: str = Form("Telegram"),
    bot_token: str = Form(...),
    chat_ids: str = Form(...),  # comma-separated
    db: aiosqlite.Connection = Depends(get_db),
):
    ids = [x.strip() for x in chat_ids.split(",") if x.strip()]
    config = json.dumps({"bot_token": bot_token.strip(), "chat_ids": ids})

    await db.execute(
        "INSERT INTO notification_channels (type, name, config, created_at) VALUES ('telegram', ?, ?, ?)",
        (name, config, current_time().isoformat()),
    )
    await db.commit()
    async with db.execute("SELECT last_insert_rowid()") as cur:
        channel_id = (await cur.fetchone())[0]

    # Default: enable important events
    for event in ["unreachable", "ip_found", "updated", "recovered", "failed"]:
        await db.execute(
            "INSERT INTO notification_rules (event_type, channel_id, enabled) VALUES (?, ?, 1)",
            (event, channel_id),
        )
    await db.commit()
    return RedirectResponse("/notifications", status_code=303)


@app.post("/notifications/channel/{channel_id}/edit")
async def edit_telegram(
    channel_id: int,
    name: str = Form("Telegram"),
    bot_token: str = Form(""),
    chat_ids: str = Form(...),
    db: aiosqlite.Connection = Depends(get_db),
):
    async with db.execute(
        "SELECT config FROM notification_channels WHERE id = ? AND type = 'telegram'",
        (channel_id,),
    ) as cur:
        channel = await cur.fetchone()
    if not channel:
        raise HTTPException(404)

    existing_config = json.loads(channel["config"])
    config = json.dumps({
        "bot_token": bot_token.strip() or existing_config.get("bot_token", ""),
        "chat_ids": [x.strip() for x in chat_ids.split(",") if x.strip()],
    })
    await db.execute(
        "UPDATE notification_channels SET name = ?, config = ? WHERE id = ?",
        (name.strip() or "Telegram", config, channel_id),
    )
    await db.commit()
    return RedirectResponse("/notifications", status_code=303)


@app.get("/notifications/add/email", response_class=HTMLResponse)
async def add_email_form(request: Request):
    return templates.TemplateResponse(
        request,
        "channel_email.html",
        {"channel": None},
    )


@app.post("/notifications/add/email")
async def add_email(
    name: str = Form("Email"),
    smtp_host: str = Form(...),
    smtp_port: int = Form(587),
    username: str = Form(...),
    password: str = Form(...),
    from_addr: str = Form(""),
    to_addrs: str = Form(...),  # comma-separated
    db: aiosqlite.Connection = Depends(get_db),
):
    addrs = [x.strip() for x in to_addrs.split(",") if x.strip()]
    config = {
        "smtp_host": smtp_host.strip(),
        "smtp_port": smtp_port,
        "username": username.strip(),
        "password": password,
        "from_addr": from_addr.strip() or username.strip(),
        "to_addrs": addrs,
    }
    await db.execute(
        "INSERT INTO notification_channels (type, name, config, created_at) VALUES ('email', ?, ?, ?)",
        (name, json.dumps(config), current_time().isoformat()),
    )
    await db.commit()
    async with db.execute("SELECT last_insert_rowid()") as cur:
        channel_id = (await cur.fetchone())[0]

    for event in ["unreachable", "ip_found", "updated", "recovered", "failed"]:
        await db.execute(
            "INSERT INTO notification_rules (event_type, channel_id, enabled) VALUES (?, ?, 1)",
            (event, channel_id),
        )
    await db.commit()
    return RedirectResponse("/notifications", status_code=303)


@app.post("/notifications/channel/{channel_id}/toggle")
async def toggle_channel(channel_id: int, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute(
        "UPDATE notification_channels SET enabled = 1 - enabled WHERE id = ?",
        (channel_id,),
    )
    await db.commit()
    return RedirectResponse("/notifications", status_code=303)


@app.post("/notifications/rule/{channel_id}/{event_type}/toggle")
async def toggle_rule(channel_id: int, event_type: str, db: aiosqlite.Connection = Depends(get_db)):
    # Upsert
    async with db.execute(
        "SELECT id, enabled FROM notification_rules WHERE channel_id = ? AND event_type = ?",
        (channel_id, event_type),
    ) as cur:
        row = await cur.fetchone()
    if row:
        await db.execute(
            "UPDATE notification_rules SET enabled = 1 - enabled WHERE id = ?",
            (row["id"],),
        )
    else:
        await db.execute(
            "INSERT INTO notification_rules (event_type, channel_id, enabled) VALUES (?, ?, 1)",
            (event_type, channel_id),
        )
    await db.commit()
    return RedirectResponse("/notifications", status_code=303)


@app.post("/notifications/channel/{channel_id}/delete")
async def delete_channel(channel_id: int, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM notification_channels WHERE id = ?", (channel_id,))
    await db.commit()
    return RedirectResponse("/notifications", status_code=303)


# ───────────────────────────── Settings / Health ─────────────────────────────

@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT key, value FROM settings") as cur:
        conf = {r["key"]: r["value"] for r in await cur.fetchall()}
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cur:
        subnets = [dict(r) for r in await cur.fetchall()]
    # Auto-detected local /24s are not DB rows — merge them in (manual rows win
    # per CIDR) so the settings page can manage them: delete (suppress) and
    # rescan (re-include).  Suppressed ones still render, dimmed.
    suppressed = await load_suppressed_subnets(db)
    for s in subnets:
        s["source"] = "manual"
        s["suppressed"] = False
    seen = {s["cidr"] for s in subnets}
    for a in get_default_subnets():
        if a["cidr"] in seen:
            continue
        subnets.append({
            "id": None,
            "name": "(auto)",
            "cidr": a["cidr"],
            "interface": a["interface"],
            "enabled": 0 if a["cidr"] in suppressed else 1,
            "source": "auto",
            "suppressed": a["cidr"] in suppressed,
        })
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "conf": conf,
            "subnets": subnets,
            "interfaces": get_local_interfaces(),
        },
    )


@app.post("/settings/subnets")
async def add_subnet(
    name: str = Form(...),
    cidr: str = Form(...),
    interface: str = Form(""),
    enabled: str = Form("on"),
    db: aiosqlite.Connection = Depends(get_db),
):
    cidr = cidr.strip()
    if not cidr or not name.strip():
        raise HTTPException(400, "Subnet name and CIDR are required")
    try:
        import ipaddress as _ip
        network = _ip.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(400, f"Invalid CIDR: {cidr!r}")
    if network.prefixlen >= 31:
        raise HTTPException(
            400,
            f"{cidr!r} is a single link/host ({network.prefixlen}), not a network that can be swept. "
            "Enter the whole network, e.g. 192.168.10.0/24.",
        )

    # Interface: blank / "auto" = let the scanner pick; otherwise it must name a
    # real local NIC (catches the old `interface="auto"` trap + typos).
    iface = interface.strip()
    if iface.lower() in ("", "auto", "any", "default"):
        iface = ""
    if iface:
        local_ifaces = get_local_interfaces()
        if local_ifaces:  # only validate when we can actually see the NICs
            if iface not in {i["name"] for i in local_ifaces}:
                available = ", ".join(f"{i['name']} ({i['address']})" for i in local_ifaces)
                raise HTTPException(
                    400,
                    f"Interface {iface!r} not found on this host. Available: {available}. "
                    "Leave the field blank to auto-detect.",
                )

    is_enabled = 1 if enabled == "on" else 0
    await db.execute(
        "INSERT INTO subnets (name, cidr, interface, enabled) VALUES (?, ?, ?, ?)",
        (name.strip(), str(network), iface or None, is_enabled),
    )
    await db.commit()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/subnets/{subnet_id}/toggle")
async def toggle_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("UPDATE subnets SET enabled = 1 - enabled WHERE id = ?", (subnet_id,))
    await db.commit()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/subnets/{subnet_id}/delete")
async def delete_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(get_db)):
    # hosts.subnet_id is ON DELETE SET NULL, so pinning references become NULL.
    await db.execute("DELETE FROM subnets WHERE id = ?", (subnet_id,))
    await db.commit()
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/subnets/suppress")
async def suppress_subnet(cidr: str = Form(...), db: aiosqlite.Connection = Depends(get_db)):
    """Delete an *auto-detected* subnet: suppress it from all scans.

    Auto subnets are not DB rows, so "delete" records the CIDR in the
    ``suppressed_subnets`` setting (excluded by ``list_subnets``).  The row
    stays on the page, dimmed, with a rescan button to bring it back.
    """
    import ipaddress as _ip

    try:
        cidr = str(_ip.ip_network(cidr.strip(), strict=False))
    except ValueError:
        raise HTTPException(400, f"Invalid CIDR: {cidr!r}")
    current = await load_suppressed_subnets(db)
    if cidr not in current:
        current.append(cidr)
    await save_suppressed_subnets(db, current)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/subnets/rescan")
async def rescan_subnet(cidr: str = Form(...), db: aiosqlite.Connection = Depends(get_db)):
    """Re-include a deleted auto subnet; detection re-runs on the re-render.

    ``get_default_subnets()`` is live (read from ``ip -4 addr`` on every
    request), so un-suppressing + redirecting *is* the rescan — if the
    interface is still attached the subnet reappears as enabled.
    """
    import ipaddress as _ip

    try:
        cidr = str(_ip.ip_network(cidr.strip(), strict=False))
    except ValueError:
        raise HTTPException(400, f"Invalid CIDR: {cidr!r}")
    current = [c for c in await load_suppressed_subnets(db) if c != cidr]
    await save_suppressed_subnets(db, current)
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings/subnets/rescan-all")
async def rescan_all_subnets(db: aiosqlite.Connection = Depends(get_db)):
    """Global "Rescan networks": re-include every auto-detected /24.

    Auto subnets are re-discovered live on every render (``get_default_subnets``),
    so the only persistent state is the suppression list — clearing it brings back
    everything that is attached again.  Manual subnets are never touched.  This is
    the "rescan" the help text promises when there is no specific stale row left to
    act on (e.g. the user deleted every auto network).
    """
    await save_suppressed_subnets(db, [])
    return RedirectResponse("/settings", status_code=303)


@app.post("/settings")
async def save_settings(
    check_interval_seconds: int = Form(...),
    event_retention_days: int = Form(...),
    db: aiosqlite.Connection = Depends(get_db),
):
    if check_interval_seconds < 1:
        raise HTTPException(400, "Check interval must be at least 1 second")
    if event_retention_days < 1:
        raise HTTPException(400, "Event retention must be at least 1 day")

    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('check_interval_seconds', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(check_interval_seconds),),
    )
    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('event_retention_days', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(event_retention_days),),
    )
    await db.commit()
    return RedirectResponse("/settings", status_code=303)


# ───────────────────────────── Diagnostic ─────────────────────────────


class ScanRequest(BaseModel):
    """Body for ``POST /api/diagnostic/scan`` — run one scanner on demand."""

    target_mac: str = Field("", description="MAC address to look for; empty = sweep and list every host")
    method: str = Field("arp-scan", description="'arp-scan', 'scapy' or 'nmap'")
    subnet_id: int = Field(0, description="Optional subnet id to scope the scan; 0 = all known subnets")
    subnet_cidr: str = Field("", description="Optional CIDR for auto-detected subnets (they have no DB id)")
    scan_ports: bool = Field(False, description="Also scan every discovered host's open ports")


@app.get("/diagnostic", response_class=HTMLResponse)
async def diagnostic_page(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    logger.info("diagnostic_page: starting")
    npm = NPMClient()
    logger.info(f"diagnostic_page: npm.available = {npm.available}")
    npm_hosts = npm.get_all_hosts()
    logger.info(f"diagnostic_page: npm_hosts count = {len(npm_hosts)}")

    scan_types = NPMClient.scan_types()

    # Also check SQLite DB hosts for comparison
    async with db.execute(
        "SELECT name, domain, mac_address, current_ip, port, enabled FROM hosts"
    ) as cursor:
        sqlite_hosts = await cursor.fetchall()
    logger.info(f"diagnostic_page: SQLite hosts count = {len(sqlite_hosts)}")
    for h in sqlite_hosts:
        logger.info(f"  SQLite: name={h['name']} domain={h['domain']} mac={h['mac_address']}")
    hosts = [
        {
            "name": r["name"],
            "domain": r["domain"],
            "mac_address": r["mac_address"],
            "current_ip": r["current_ip"],
            "port": r["port"],
            "enabled": bool(r["enabled"]),
        }
        for r in sqlite_hosts
    ]

    return templates.TemplateResponse(
        request,
        "diagnostic.html",
        {
            "npm_hosts": npm_hosts,
            "npm_available": npm.available,
            "scan_types": scan_types,
            "hosts": hosts,
            "subnets": await list_subnets(db),
        },
    )


@app.get("/api/diagnostic")
async def diagnostic_api(db: aiosqlite.Connection = Depends(get_db)):
    logger.info("diagnostic_api: starting")
    npm = NPMClient()
    logger.info(f"diagnostic_api: npm.available = {npm.available}")
    npm_hosts = npm.get_all_hosts()
    logger.info(f"diagnostic_api: npm_hosts count = {len(npm_hosts)}")

    # SQLite hosts give the UI a list of MACs to prefill the scan form with.
    async with db.execute(
        "SELECT name, domain, mac_address, current_ip, port, enabled FROM hosts"
    ) as cursor:
        rows = await cursor.fetchall()
    hosts = [
        {
            "name": r["name"],
            "domain": r["domain"],
            "mac_address": r["mac_address"],
            "current_ip": r["current_ip"],
            "port": r["port"],
            "enabled": bool(r["enabled"]),
        }
        for r in rows
    ]

    return {
        "npm_hosts": npm_hosts,
        "npm_available": npm.available,
        "scan_types": NPMClient.scan_types(),
        "hosts": hosts,
    }


@app.post("/api/diagnostic/scan")
async def diagnostic_scan(body: ScanRequest, db: aiosqlite.Connection = Depends(get_db)):
    """Run an ARP, scapy or nmap scan on demand and return the raw output.

    Returns immediately with a ``scan_id``.  The scan runs in the background and
    publishes incremental results into ``scan_progress`` — the frontend polls
    ``/api/diagnostic/scan-progress/{scan_id}`` to track progress and retrieve
    partial hosts as the port scan completes host by host.
    """
    method = body.method.strip().lower()
    if method not in ("arp-scan", "scapy", "nmap"):
        raise HTTPException(status_code=400, detail=f"Unknown scanner method: {body.method!r}")
    subnet_ids: list[str] = []
    if body.subnet_id:
        async with db.execute("SELECT cidr FROM subnets WHERE id = ?", (body.subnet_id,)) as cur:
            row = await cur.fetchone()
            if row:
                subnet_ids = [row["cidr"]]
    if not subnet_ids and body.subnet_cidr.strip():
        try:
            import ipaddress as _ip

            subnet_ids = [str(_ip.ip_network(body.subnet_cidr.strip(), strict=False))]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid subnet CIDR: {body.subnet_cidr!r}")
    if not subnet_ids:
        subnet_ids = [s["cidr"] for s in await list_subnets(db)]

    # Generate scan ID before we start — the client uses this to poll.
    import uuid

    scan_id = str(uuid.uuid4())

    # ── Inline background task ─────────────────────────────────────────
    async def _do_scan():
        with diag_log.scan_context(
            target_mac=body.target_mac, method=method, subnets=subnet_ids
        ):
            mdns_task = asyncio.create_task(discover_hostnames())
            result = await run_scan(
                body.target_mac, method, subnets=subnet_ids or None, scan_ports=False
            )
            result["subnets"] = subnet_ids
            logger.info(
                f"diagnostic_scan: method={method} target={normalize_mac(body.target_mac) or '(sweep)'} "
                f"subnets={subnet_ids} scan_ports={body.scan_ports} "
                f"found_ip={result['found_ip']} error={result['error']}"
            )
            try:
                mdns_names = await mdns_task
            except Exception:  # noqa: BLE001
                mdns_names = ({}, {})
            try:
                await remember_mdns_names(db, mdns_names[1] or {})
            except Exception:  # noqa: BLE001
                pass
            try:
                known_names = await load_known_hostnames(db)
            except Exception:  # noqa: BLE001
                known_names = {}
            try:
                known_by_ip = await load_known_hostnames_by_ip(db)
            except Exception:  # noqa: BLE001
                known_by_ip = {}
            try:
                cached_names = await load_mdns_names(db)
            except Exception:  # noqa: BLE001
                cached_names = {}
            hosts = result.get("hosts") or []
            hosts = apply_hostnames(
                hosts, mdns=mdns_names, known=known_names, cached=cached_names,
                known_by_ip=known_by_ip,
            )
            diag_log.emit(
                "hostnames",
                f"known_names={known_names}",
                f"known_by_ip={known_by_ip}",
                f"mdns_live={mdns_names[0]}",
                f"mdns_cached_source={mdns_names[1]}",
                f"cached_names={cached_names}",
                f"hosts={[(h.get('ip'), h.get('mac'), h.get('hostname')) for h in hosts]}",
            )
            diag_log.emit(
                "result",
                f"found_ip={result.get('found_ip')}",
                f"found_via={result.get('found_via')}",
                f"error={result.get('error')}",
                f"hosts={len(hosts)}",
            )
            # Publish discovery results immediately
            host_ips = [h["ip"] for h in hosts]
            scan_progress[scan_id] = {
                "start_time": time.time(),
                "status": "discovered",
                "hosts": hosts,
                "output": result.get("output", ""),
                "error": result.get("error"),
                "found_ip": result.get("found_ip"),
                "found_via": result.get("found_via"),
                "total_hosts": len(hosts),
                "hosts_scanned": 0,
                "scan_ports": body.scan_ports,
            }
            # Incremental port scan if requested
            if body.scan_ports and host_ips:
                scan_progress[scan_id]["status"] = "scanning_ports"

                async def _on_host_done(partial_result: dict):
                    idx = partial_result.pop("_index", 0)
                    progress = scan_progress.get(scan_id, {})
                    current_hosts = list(progress.get("hosts", []))
                    for h in current_hosts:
                        for ip, ports in partial_result.items():
                            if h["ip"] == ip:
                                h["ports"] = ports
                    progress["hosts"] = current_hosts
                    progress["hosts_scanned"] = idx + 1

                port_map, ports_error = await run_port_scan_incremental(
                    host_ips, callback=_on_host_done
                )
                current_hosts = scan_progress.get(scan_id, {}).get("hosts", [])
                for h in current_hosts:
                    h["ports"] = port_map.get(h["ip"], [])
                scan_progress[scan_id]["hosts"] = current_hosts
                scan_progress[scan_id]["ports_error"] = ports_error
            # Finalise
            progress = scan_progress[scan_id]
            hosts = progress.get("hosts", [])
            result["hosts"] = hosts
            result["scan_id"] = scan_id
            if progress.get("ports_error"):
                result["ports_error"] = progress["ports_error"]
            progress["status"] = "complete"
            progress["result"] = result

    asyncio.create_task(_do_scan())
    scan_progress[scan_id] = {"start_time": time.time(), "status": "starting"}
    return {"scan_id": scan_id, "status": "starting"}


@app.get("/api/diagnostic/scan-progress/{scan_id}")
async def get_scan_progress(scan_id: str):
    """Get progress information for a running scan.

    Returns timing info plus partial hosts (with ports) as soon as they are
    discovered during port scanning.  When the scan is complete, ``result`` is
    populated with the full result dict.
    """
    if scan_id not in scan_progress:
        return {"error": "Scan not found"}

    progress = scan_progress[scan_id]
    current_time = time.time()
    elapsed_time = current_time - progress["start_time"]

    estimated_completion = None
    if progress.get("estimated_duration"):
        estimated_completion = progress["start_time"] + progress["estimated_duration"]

    resp = {
        "elapsed_time": round(elapsed_time, 2),
        "estimated_completion": estimated_completion,
        "estimated_remaining": (
            progress.get("estimated_duration", 0) - elapsed_time
            if progress.get("estimated_duration")
            else None
        ),
        "status": progress.get("status", "starting"),
        "hosts": progress.get("hosts", []),
        "hosts_scanned": progress.get("hosts_scanned", 0),
        "total_hosts": progress.get("total_hosts", 0),
        "output": progress.get("output", ""),
        "error": progress.get("error"),
        "ports_error": progress.get("ports_error"),
    }
    # When complete, include the full result for the frontend to consume
    if progress.get("status") == "complete" and "result" in progress:
        resp["result"] = progress["result"]

    return resp


@app.get("/api/diagnostic/scan-log")
async def diagnostic_scan_log(limit: int = 10):
    """Serve the per-scan debug logs (dev-only).

    Every diagnostic scan appends a detailed log — exact tool commands, their
    full raw output, the hostname maps, the reverse-DNS summary, the final
    result — when ``UPSTREAM_HEALER_DEBUG_LOG_DIR`` is set (the dev stack
    only; see ``app/services/diag_log.py``).  This endpoint returns the newest
    log's full text plus a list of recent ones, so "why is this host unnamed
    or MAC-less" is answerable from the scan page itself without box access.

    Mirrors ``/api/diagnostic/debug``: with the variable unset (test and
    production) it 404s, so nothing sensitive is exposed there.
    """
    directory = diag_log.log_dir()
    if directory is None:
        raise HTTPException(
            status_code=404,
            detail="scan debug logging is disabled on this instance "
            "(UPSTREAM_HEALER_DEBUG_LOG_DIR is set on the dev stack only)",
        )
    files = diag_log.recent_scans(min(max(limit, 1), 50))
    if not files:
        return {"files": [], "latest": None}
    latest = dict(files[0])
    try:
        latest["content"] = (Path(directory) / latest["name"]).read_text(
            encoding="utf-8", errors="replace"
        )
    except Exception:  # noqa: BLE001 - unreadable file: still serve the file list
        latest["content"] = "(could not read log file)"
    return {"files": files, "latest": latest}


@app.get("/api/diagnostic/debug")
async def diagnostic_debug():
    """Raw debugging view of the NPM integration — prints everything it knows
    (effective DB credentials, the exact pymysql attempt, raw connection
    introspection) so a ``curl`` can diagnose without reading container logs.

    Dev/debug aid: runs unauthenticated like the rest of /diagnostic, and it
    reveals the effective DB user/host/password — it does not exist in the
    production image (Dockerfile) and must stay out of it.
    """
    import os

    import pymysql

    import pymysql.cursors  # registers pymysql.cursors.DictCursor

    npm = NPMClient()
    result: dict = {
        "npm_available": npm.available,
        "settings": {
            "npm_container": settings.npm_container,
            "npm_db_host": settings.npm_db_host,
            "npm_db_port": settings.npm_db_port,
            "npm_db_user": settings.npm_db_user or "(empty)",
            "npm_db_password": "set" if settings.npm_db_password else "(empty)",
            "npm_db_name": settings.npm_db_name,
            "db_path": settings.db_path,
        },
        "npm_env": {
            k: v
            for k, v in sorted(os.environ.items())
            if k.startswith("NPM_") or k.startswith("DB_MYSQL_")
        },
    }

    # Effective credentials: what the client actually uses to connect
    # (container env if discoverable, else settings fallback).
    creds = dict(getattr(npm, "_db_creds", None) or {})
    result["effective_creds"] = {
        k: (f"{v[:3]}***" if len(v) > 3 else "***") if k.endswith("PASSWORD") else v
        for k, v in creds.items()
    }

    try:
        conn = pymysql.connect(
            host=creds.get("DB_MYSQL_HOST") or settings.npm_db_host,
            port=int(creds.get("DB_MYSQL_PORT") or settings.npm_db_port),
            user=creds.get("DB_MYSQL_USER") or settings.npm_db_user,
            password=creds.get("DB_MYSQL_PASSWORD") or settings.npm_db_password,
            database=creds.get("DB_MYSQL_NAME") or settings.npm_db_name,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
        )
    except Exception as exc:  # noqa: BLE001
        result["connection"] = f"FAILED: {type(exc).__name__}: {exc}"
        return result

    try:
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION() AS v, DATABASE() AS db, USER() AS who")
            version, database, user = cur.fetchone().values()
            result["connection"] = "OK"
            result["server"] = {"version": version, "database": database, "user": user}
            cur.execute("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = %s", (database,))
            result["tables"] = [r["TABLE_NAME"] for r in cur.fetchall()]
            cur.execute(
                "SELECT id, domain_names, forward_host, forward_port, "
                "owner_user_id, access_list_id, certificate_id, enabled, is_deleted "
                "FROM proxy_host ORDER BY id"
            )
            result["proxy_host_rows"] = [dict(r) for r in cur.fetchall()]
    except Exception as exc:  # noqa: BLE001
        result["query"] = f"FAILED: {type(exc).__name__}: {exc}"
    finally:
        conn.close()
    return result


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "upstream-healer"}
