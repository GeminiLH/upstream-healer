import logging
from contextlib import asynccontextmanager
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
from app.services.npm import NPMClient
from app.services.notifications import send_event
from app.services.scanner import (
    check_host_reachable,
    find_ip_by_mac,
    get_default_subnets,
    list_subnets,
    load_suppressed_subnets,
    normalize_mac,
    run_scan,
    save_suppressed_subnets,
)

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
        """SELECT h.*, s.status, s.last_seen_at, s.unreachable_since, s.last_check_at, s.last_ip
            FROM hosts h
            LEFT JOIN host_state s ON s.host_id = h.id
            ORDER BY h.name"""
    ) as cursor:
        hosts = [dict(r) for r in await cursor.fetchall()]
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
    npm = NPMClient()
    try:
        proxy_hosts = npm.list_proxy_hosts()
    except Exception:
        proxy_hosts = []
    async with db.execute("SELECT id, name, cidr, interface FROM subnets WHERE enabled = 1 ORDER BY name") as cur:
        subnets = [dict(r) for r in await cur.fetchall()]
    return templates.TemplateResponse(
        request,
        "host_form.html",
        {
            "host": None,
            "proxy_hosts": proxy_hosts,
            "subnets": subnets,
            "title": "Add Host",
        },
    )


@app.post("/hosts/add")
async def add_host(
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
    grace_minutes: int = Form(10),
    notes: str = Form(""),
    db: aiosqlite.Connection = Depends(get_db),
):
    mac = normalize_mac(mac_address)
    npm_id = int(npm_proxy_host_id) if npm_proxy_host_id.strip() else None
    subnet = int(subnet_id) if subnet_id.strip() else None
    if not 1 <= port <= 65535:
        raise HTTPException(400, "Port must be between 1 and 65535")

    await db.execute(
            """INSERT INTO hosts (name, local_device_name, quiet_enabled, quiet_start, quiet_end, quiet_mode,
                domain, mac_address, current_ip, npm_proxy_host_id, subnet_id, port, grace_minutes, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, local_device_name or None, quiet_enabled == "on", quiet_start or None, quiet_end or None,
             quiet_mode if quiet_mode in ("suppress", "delete") else "suppress", domain, mac, current_ip or None,
             npm_id, subnet, port, grace_minutes, notes,
            current_time().isoformat(), current_time().isoformat()),
    )
    await db.commit()

    # Create state row
    async with db.execute("SELECT last_insert_rowid()") as cur:
        host_id = (await cur.fetchone())[0]
    await db.execute(
        "INSERT INTO host_state (host_id, status, last_ip) VALUES (?, 'unknown', ?)",
        (host_id, current_ip or None),
    )
    await db.commit()

    return RedirectResponse("/", status_code=303)


@app.get("/hosts/{host_id}/edit", response_class=HTMLResponse)
async def edit_host_form(host_id: int, request: Request, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)) as cur:
        host = await cur.fetchone()
    if not host:
        raise HTTPException(404)
    npm = NPMClient()
    try:
        proxy_hosts = npm.list_proxy_hosts()
    except Exception:
        proxy_hosts = []
    async with db.execute("SELECT id, name, cidr, interface FROM subnets WHERE enabled = 1 ORDER BY name") as cur:
        subnets = [dict(r) for r in await cur.fetchall()]
    return templates.TemplateResponse(
        request,
        "host_form.html",
        {
            "host": dict(host),
            "proxy_hosts": proxy_hosts,
            "subnets": subnets,
            "title": "Edit Host",
        },
    )


@app.post("/hosts/{host_id}/edit")
async def edit_host(
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
    grace_minutes: int = Form(10),
    notes: str = Form(""),
    enabled: str = Form("off"),
    db: aiosqlite.Connection = Depends(get_db),
):
    mac = normalize_mac(mac_address)
    npm_id = int(npm_proxy_host_id) if npm_proxy_host_id.strip() else None
    subnet = int(subnet_id) if subnet_id.strip() else None
    is_enabled = 1 if enabled == "on" else 0
    if not 1 <= port <= 65535:
        raise HTTPException(400, "Port must be between 1 and 65535")

    await db.execute(
        """UPDATE hosts SET
            name = ?, local_device_name = ?, quiet_enabled = ?, quiet_start = ?, quiet_end = ?, quiet_mode = ?,
            domain = ?, mac_address = ?, current_ip = ?,
            npm_proxy_host_id = ?, subnet_id = ?, port = ?, grace_minutes = ?, notes = ?, enabled = ?,
                updated_at = ?
            WHERE id = ?""",
            (name, local_device_name or None, quiet_enabled == "on", quiet_start or None, quiet_end or None,
             quiet_mode if quiet_mode in ("suppress", "delete") else "suppress", domain, mac, current_ip or None,
             npm_id, subnet, port, grace_minutes, notes, is_enabled,
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
    """Run an immediate log-only IP/port and MAC verification for a host."""
    async with db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)) as cur:
        host = await cur.fetchone()
    if not host:
        raise HTTPException(404)

    name = host["name"]
    current_ip = host["current_ip"]
    port = host["port"] or 80
    recorded_mac = normalize_mac(host["mac_address"])
    checked_at = current_time().isoformat()
    ip_port_ok = bool(current_ip) and await check_host_reachable(current_ip, port=port)
    mac_ip = await find_ip_by_mac(recorded_mac)
    mac_ok = mac_ip is not None
    npm_id = host["npm_proxy_host_id"]

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
        ("healthy" if ip_port_ok else "unreachable", ip_port_ok, checked_at,
         ip_port_ok, checked_at, mac_ip, host_id),
    )
    await db.commit()

    npm_summary = f"configured (ID {npm_id})" if npm_id else "not configured"
    details = (
        f"IP/port check: {'SUCCESS' if ip_port_ok else 'FAILURE'}; "
        f"current IP: {current_ip or 'none'}; port: {port}; "
        f"MAC verification: {'SUCCESS' if mac_ok else 'FAILURE'}; "
        f"recorded MAC: {recorded_mac}; MAC-discovered IP: {mac_ip or 'none'}; "
        f"NPM host ID: {npm_summary}; last check reset: {checked_at}"
    )
    await send_event(
        db,
        "manual",
        f"🔎 Force scan for {name}: IP/port {'passed' if ip_port_ok else 'failed'}, "
        f"MAC {'verified' if mac_ok else 'not verified'}.",
        details=details,
        host_id=host_id,
        notify=False,
    )
    return RedirectResponse("/", status_code=303)


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
        {"conf": conf, "subnets": subnets},
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
        _ip.ip_network(cidr, strict=False)
    except ValueError:
        raise HTTPException(400, f"Invalid CIDR: {cidr!r}")
    is_enabled = 1 if enabled == "on" else 0
    await db.execute(
        "INSERT INTO subnets (name, cidr, interface, enabled) VALUES (?, ?, ?, ?)",
        (name.strip(), str(_ip.ip_network(cidr, strict=False)), interface.strip() or None, is_enabled),
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

    target_mac: str = Field(..., description="MAC address to look for (normalised server-side)")
    method: str = Field("arp-scan", description="'arp-scan' or 'scapy'")
    subnet_id: int = Field(0, description="Optional subnet id to scope the scan; 0 = all known subnets")
    subnet_cidr: str = Field("", description="Optional CIDR for auto-detected subnets (they have no DB id)")


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
    """Run an ARP or scapy scan on demand and return the raw output.

    The scanner work is executed in a thread pool (see ``run_scan``) so a slow
    ``arp-scan`` never blocks the event loop. Returns the found IP (if any), the
    scanner that produced it, the full raw output, and any error string.

    ``body.subnet_id`` optionally scopes the sweep to a single subnet (e.g. a
    host is pinned to a specific network).  When 0, the scan covers every
    effective subnet (manual rows + auto-discovered local networks).
    """
    method = body.method.strip().lower()
    if method not in ("arp-scan", "scapy"):
        raise HTTPException(status_code=400, detail=f"Unknown scanner method: {body.method!r}")
    if not body.target_mac.strip():
        raise HTTPException(status_code=400, detail="target_mac is required")

    subnet_ids: list[str] = []
    if body.subnet_id:
        async with db.execute("SELECT cidr FROM subnets WHERE id = ?", (body.subnet_id,)) as cur:
            row = await cur.fetchone()
            if row:
                subnet_ids = [row["cidr"]]
    if not subnet_ids and body.subnet_cidr.strip():
        # Auto-detected subnets have no DB id — the UI targets them by CIDR.
        try:
            import ipaddress as _ip

            subnet_ids = [str(_ip.ip_network(body.subnet_cidr.strip(), strict=False))]
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid subnet CIDR: {body.subnet_cidr!r}")
    if not subnet_ids:
        subnet_ids = [s["cidr"] for s in await list_subnets(db)]

    result = await run_scan(body.target_mac, method, subnets=subnet_ids or None)
    result["subnets"] = subnet_ids
    logger.info(
        f"diagnostic_scan: method={method} target={normalize_mac(body.target_mac)} "
        f"subnets={subnet_ids} found_ip={result['found_ip']} error={result['error']}"
    )
    return result


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
