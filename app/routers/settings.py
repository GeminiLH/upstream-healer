"""
Settings and health routes for Upstream Healer.
"""
import aiosqlite
from fastapi import APIRouter, Depends, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
import json

from app.database import get_db
from app.services.scanner import (
    get_local_interfaces,
)
import ipaddress

router = APIRouter(prefix="/settings", tags=["settings"])


@router.get("/", response_class=HTMLResponse)
async def settings_page(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """
    Render the settings page.
    """
    async with db.execute("SELECT key, value FROM settings") as cur:
        conf = {r["key"]: r["value"] for r in await cur.fetchall()}
    
    # Get suppressed subnets from settings
    async with db.execute("SELECT value FROM settings WHERE key = 'suppressed_subnets'") as cur:
        suppressed_row = await cur.fetchone()
        suppressed_subnets = json.loads(suppressed_row[0]) if suppressed_row and suppressed_row[0] else []
    
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
            "suppressed_subnets": suppressed_subnets,
        },
    )


@router.post("/")
async def save_settings(db: aiosqlite.Connection = Depends(get_db)):
    """
    Save settings.
    """
    # This is handled by the service layer but we'll keep it here for reference
    return RedirectResponse("/settings", status_code=303)


@router.get("/health", response_class=HTMLResponse)
async def health_page(request: Request, db: aiosqlite.Connection = Depends(get_db)):
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


# ───────────────────────────── Subnet CRUD Operations ─────────────────────────────


@router.post("/subnets", response_class=RedirectResponse)
async def add_subnet(
    name: str = Form(...),
    cidr: str = Form(...),
    interface: str = Form(""),
    enabled: str = Form("off"),
    db: aiosqlite.Connection = Depends(get_db)
):
    """
    Add a new subnet.
    """
    # Validate CIDR
    try:
        ipaddress.ip_network(cidr)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet CIDR")
    
    # Reject /32 (single host) CIDRs
    try:
        ip_network = ipaddress.ip_network(cidr)
        if ip_network.prefixlen == 32:
            raise HTTPException(status_code=400, detail="A /32 (single link/host) can't be swept")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet CIDR")

    # Handle 'auto' interface - treat as blank
    if interface == "auto":
        interface = ""
    
    # Validate interface against local interfaces if not blank
    if interface:
        local_interfaces = get_local_interfaces()
        if not any(iface["name"] == interface for iface in local_interfaces):
            available_interfaces = [iface["name"] for iface in local_interfaces]
            raise HTTPException(
                status_code=400,
                detail=f"Interface '{interface}' not found on this host. Available interfaces: {', '.join(available_interfaces)}"
            )

    # Insert into database
    await db.execute(
        "INSERT INTO subnets (name, cidr, interface, enabled) VALUES (?, ?, ?, ?)",
        (name, cidr, interface if interface else None, 1 if enabled == "on" else 0)
    )
    await db.commit()
    
    # Redirect back to settings page
    return RedirectResponse("/settings", status_code=303)


@router.post("/subnets/rescan", response_class=RedirectResponse)
async def rescan_subnet(
    cidr: str = Form(...),
    db: aiosqlite.Connection = Depends(get_db)
):
    """
    Rescan a specific subnet CIDR.
    """
    # Validate CIDR
    try:
        ipaddress.ip_network(cidr)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet CIDR")
    
    # Get current suppressed subnets
    async with db.execute("SELECT value FROM settings WHERE key = 'suppressed_subnets'") as cur:
        suppressed_row = await cur.fetchone()
        suppressed_subnets = json.loads(suppressed_row[0]) if suppressed_row and suppressed_row[0] else []
    
    # Remove from suppressed list if present
    if cidr in suppressed_subnets:
        suppressed_subnets.remove(cidr)
        await db.execute(
            "UPDATE settings SET value = ? WHERE key = 'suppressed_subnets'",
            (json.dumps(suppressed_subnets),)
        )
        await db.commit()
    
    # Redirect back to settings page
    return RedirectResponse("/settings", status_code=303)


@router.post("/subnets/suppress", response_class=RedirectResponse)
async def suppress_subnet(
    cidr: str = Form(...),
    db: aiosqlite.Connection = Depends(get_db)
):
    """
    Suppress a subnet (add to suppressed list).
    """
    # Validate CIDR
    try:
        ipaddress.ip_network(cidr)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid subnet CIDR")
    
    # Get current suppressed subnets
    async with db.execute("SELECT value FROM settings WHERE key = 'suppressed_subnets'") as cur:
        suppressed_row = await cur.fetchone()
        suppressed_subnets = json.loads(suppressed_row[0]) if suppressed_row and suppressed_row[0] else []
    
    # Add to suppressed list if not already present
    if cidr not in suppressed_subnets:
        suppressed_subnets.append(cidr)
        await db.execute(
            "UPDATE settings SET value = ? WHERE key = 'suppressed_subnets'",
            (json.dumps(suppressed_subnets),)
        )
        await db.commit()
    
    # Redirect back to settings page
    return RedirectResponse("/settings", status_code=303)


@router.post("/subnets/rescan-all", response_class=RedirectResponse)
async def rescan_all_subnets(
    db: aiosqlite.Connection = Depends(get_db)
):
    """
    Rescan all networks (clear suppressed subnets).
    """
    # Clear suppressed subnets
    await db.execute(
        "UPDATE settings SET value = '[]' WHERE key = 'suppressed_subnets'"
    )
    await db.commit()
    
    # Redirect back to settings page
    return RedirectResponse("/settings", status_code=303)
