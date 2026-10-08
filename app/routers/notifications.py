"""
Notification routes for Upstream Healer.
"""
from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import aiosqlite
import json
from app.config import current_time
from app.database import init_db
from app.services.notifications import send_event

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("/", response_class=HTMLResponse)
async def notifications_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the notification channels page.
    """
    async with db.execute("SELECT * FROM notification_channels ORDER BY type, name") as cursor:
        channels = [dict(r) for r in await cursor.fetchall()]
    
    async with db.execute("SELECT * FROM notification_rules ORDER BY channel_id, event_type") as cursor:
        rules = [dict(r) for r in await cursor.fetchall()]
    
    # Group rules by channel
    rules_by_channel = {}
    for rule in rules:
        channel_id = rule["channel_id"]
        if channel_id not in rules_by_channel:
            rules_by_channel[channel_id] = []
        rules_by_channel[channel_id].append(rule)
    
    return templates.TemplateResponse(
        "notifications.html",
        {
            "request": request,
            "channels": channels,
            "rules": rules_by_channel,
        },
    )


@router.post("/channel/add/email")
async def add_email_channel(
    name: str = Form(...),
    smtp_host: str = Form(...),
    smtp_port: int = Form(587),
    username: str = Form(...),
    password: str = Form(...),
    from_addr: str = Form(""),
    to_addrs: str = Form(""),  # comma-separated
    db: aiosqlite.Connection = Depends(init_db),
):
    """
    Add a new email notification channel.
    """
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


@router.post("/channel/{channel_id}/toggle")
async def toggle_channel(channel_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Toggle the enabled state of a notification channel.
    """
    await db.execute(
        "UPDATE notification_channels SET enabled = 1 - enabled WHERE id = ?",
        (channel_id,),
    )
    await db.commit()
    
    return RedirectResponse("/notifications", status_code=303)


@router.post("/rule/{channel_id}/{event_type}/toggle")
async def toggle_rule(channel_id: int, event_type: str, db: aiosqlite.Connection = Depends(init_db)):
    """
    Toggle a notification rule for a specific channel and event type.
    """
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


@router.post("/channel/{channel_id}/delete")
async def delete_channel(channel_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Delete a notification channel.
    """
    await db.execute("DELETE FROM notification_channels WHERE id = ?", (channel_id,))
    await db.commit()
    
    return RedirectResponse("/notifications", status_code=303)