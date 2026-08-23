import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Form, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import aiosqlite
import json
from datetime import timedelta

from app.config import current_time, format_timestamp, settings, time_ago
from app.database import init_db
from app.services.monitor import monitor
from app.services.npm import NPMClient
from app.services.scanner import normalize_mac

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

    async with db.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT 20"
    ) as cursor:
        events = [dict(r) for r in await cursor.fetchall()]
    for event in events:
        if event["created_at"]:
            event["created_at_display"] = format_timestamp(event["created_at"])

    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "hosts": hosts, "events": events, "now": current_time()},
    )


@app.post("/events/clear")
async def clear_events(db: aiosqlite.Connection = Depends(get_db)):
    await db.execute("DELETE FROM events")
    await db.commit()
    return RedirectResponse("/", status_code=303)


# ───────────────────────────── Hosts ─────────────────────────────

@app.get("/hosts/add", response_class=HTMLResponse)
async def add_host_form(request: Request):
    npm = NPMClient()
    try:
        proxy_hosts = npm.list_proxy_hosts()
    except Exception:
        proxy_hosts = []
    return templates.TemplateResponse(
        "host_form.html",
        {"request": request, "host": None, "proxy_hosts": proxy_hosts, "title": "Add Host"},
    )


@app.post("/hosts/add")
async def add_host(
    name: str = Form(...),
    domain: str = Form(""),
    mac_address: str = Form(...),
    current_ip: str = Form(""),
    port: int = Form(80),
    npm_proxy_host_id: str = Form(""),
    grace_minutes: int = Form(10),
    notes: str = Form(""),
    db: aiosqlite.Connection = Depends(get_db),
):
    mac = normalize_mac(mac_address)
    npm_id = int(npm_proxy_host_id) if npm_proxy_host_id.strip() else None
    if not 1 <= port <= 65535:
        raise HTTPException(400, "Port must be between 1 and 65535")

    await db.execute(
            """INSERT INTO hosts (name, domain, mac_address, current_ip, npm_proxy_host_id, port, grace_minutes, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, domain, mac, current_ip or None, npm_id, port, grace_minutes, notes,
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
    return templates.TemplateResponse(
        "host_form.html",
        {"request": request, "host": dict(host), "proxy_hosts": proxy_hosts, "title": "Edit Host"},
    )


@app.post("/hosts/{host_id}/edit")
async def edit_host(
    host_id: int,
    name: str = Form(...),
    domain: str = Form(""),
    mac_address: str = Form(...),
    current_ip: str = Form(""),
    port: int = Form(80),
    npm_proxy_host_id: str = Form(""),
    grace_minutes: int = Form(10),
    notes: str = Form(""),
    enabled: str = Form("off"),
    db: aiosqlite.Connection = Depends(get_db),
):
    mac = normalize_mac(mac_address)
    npm_id = int(npm_proxy_host_id) if npm_proxy_host_id.strip() else None
    is_enabled = 1 if enabled == "on" else 0
    if not 1 <= port <= 65535:
        raise HTTPException(400, "Port must be between 1 and 65535")

    await db.execute(
        """UPDATE hosts SET
            name = ?, domain = ?, mac_address = ?, current_ip = ?,
            npm_proxy_host_id = ?, port = ?, grace_minutes = ?, notes = ?, enabled = ?,
                updated_at = ?
            WHERE id = ?""",
            (name, domain, mac, current_ip or None, npm_id, port, grace_minutes, notes, is_enabled,
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
    """Manually trigger recovery for a host."""
    async with db.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)) as cur:
        host = await cur.fetchone()
    if not host:
        raise HTTPException(404)

    # Force status to unreachable past grace so recovery runs
    past = (current_time()).isoformat()
    unreachable_since = (current_time() - timedelta(hours=1)).isoformat()
    await db.execute(
        """UPDATE host_state SET
            status = 'unreachable',
            unreachable_since = ?,
            last_check_at = ?
            WHERE host_id = ?""",
        (unreachable_since, past, host_id),
    )
    await db.commit()
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
        "notifications.html",
        {"request": request, "channels": channels, "event_types": [
            "unreachable", "scan_started", "ip_found", "updated", "recovered", "failed", "manual"
        ]},
    )


@app.get("/notifications/add/telegram", response_class=HTMLResponse)
async def add_telegram_form(request: Request):
    return templates.TemplateResponse(
        "channel_telegram.html",
        {"request": request, "channel": None},
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
        "channel_telegram.html",
        {"request": request, "channel": channel},
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
        "channel_email.html",
        {"request": request, "channel": None},
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
    return templates.TemplateResponse(
        "settings.html",
        {"request": request, "conf": conf},
    )


@app.post("/settings")
async def save_settings(
    check_interval_seconds: int = Form(...),
    db: aiosqlite.Connection = Depends(get_db),
):
    if check_interval_seconds < 1:
        raise HTTPException(400, "Check interval must be at least 1 second")

    await db.execute(
        "INSERT INTO settings (key, value) VALUES ('check_interval_seconds', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(check_interval_seconds),),
    )
    await db.commit()
    return RedirectResponse("/settings", status_code=303)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "upstream-healer"}
