"""
Settings and health routes for Upstream Healer.
"""
from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import aiosqlite
import json
from app.config import current_time, format_timestamp
from app.database import init_db

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/", response_class=HTMLResponse)
async def settings_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the settings page.
    """
    async with db.execute("SELECT key, value FROM settings") as cur:
        conf = {r["key"]: r["value"] for r in await cur.fetchall()}
    
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cur:
        subnets = [dict(r) for r in await cur.fetchall()]
    
    # Auto-detected local /24s are not DB rows — merge them in (manual rows win)
    # This is handled by the service layer but we'll keep it here for reference
    
    return templates.TemplateResponse(
        "settings.html",
        {
            "request": request,
            "conf": conf,
            "subnets": subnets,
        },
    )


@router.post("/save")
async def save_settings(
    db: aiosqlite.Connection = Depends(init_db),
    **kwargs  # All form fields will be passed as kwargs
):
    """
    Save settings to the database.
    """
    for key, value in kwargs.items():
        if key == "csrf_token":
            continue  # Skip CSRF token
        
        # Check if setting exists
        async with db.execute("SELECT COUNT(*) FROM settings WHERE key = ?", (key,)) as cur:
            count = await cur.fetchone()
            if count and count[0] > 0:
                # Update existing
                await db.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
            else:
                # Insert new
                await db.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))
    
    await db.commit()
    
    return RedirectResponse("/settings", status_code=303)


@router.get("/health", response_class=HTMLResponse)
async def health_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the health check page.
    """
    # Get basic system info
    async with db.execute("SELECT COUNT(*) FROM hosts") as cur:
        host_count = await cur.fetchone()
    
    async with db.execute("SELECT COUNT(*) FROM subnets") as cur:
        subnet_count = await cur.fetchone()
    
    async with db.execute("SELECT COUNT(*) FROM notification_channels") as cur:
        channel_count = await cur.fetchone()
    
    # Get last scan time
    async with db.execute("SELECT MAX(last_check_at) FROM hosts") as cur:
        last_scan = await cur.fetchone()
    
    return templates.TemplateResponse(
        "health.html",
        {
            "request": request,
            "host_count": host_count[0] if host_count else 0,
            "subnet_count": subnet_count[0] if subnet_count else 0,
            "channel_count": channel_count[0] if channel_count else 0,
            "last_scan": format_timestamp(last_scan[0]) if last_scan and last_scan[0] else "Never",
        },
    )


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the logs page.
    """
    # This would typically show recent logs from the system
    return templates.TemplateResponse(
        "logs.html",
        {
            "request": request,
        },
    )