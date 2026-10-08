"""
Settings and health routes for Upstream Healer.
"""
import aiosqlite
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.database import init_db
from app.services.scanner import (
    get_local_interfaces,
)

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
    detected = get_local_interfaces()
    for iface in detected:
        if not any(s["interface"] == iface["name"] for s in subnets):
            subnets.append({
                "id": None,
                "name": f"Auto: {iface['name']}",
                "cidr": f"{iface['address']}/24",
                "interface": iface["name"],
                "enabled": True,
            })

    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "conf": conf,
            "subnets": subnets,
        },
    )


@router.post("/")
async def save_settings(db: aiosqlite.Connection = Depends(init_db)):
    """
    Save settings.
    """
    # This is handled by the service layer but we'll keep it here for reference
    return RedirectResponse("/settings", status_code=303)


@router.get("/health", response_class=HTMLResponse)
async def health_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the health page.
    """
    async with db.execute("SELECT created_at FROM hosts ORDER BY created_at ASC LIMIT 1") as cur:
        first_host = await cur.fetchone()
    async with db.execute("SELECT last_insert_rowid()") as cur:
        last_id = (await cur.fetchone())[0]
    async with db.execute("SELECT created_at FROM scan_log ORDER BY created_at DESC LIMIT 1") as cur:
        last_scan = await cur.fetchone()

    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        request,
        "health.html",
        {
            "first_host_time": first_host["created_at"] if first_host else None,
            "host_count": last_id,
            "last_scan_time": last_scan["created_at"] if last_scan else None,
        },
    )


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """
    Render the logs page.
    """
    # This would typically show recent logs from the system
    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        request,
        "logs.html",
        {
        },
    )
