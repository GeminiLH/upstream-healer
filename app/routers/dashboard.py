"""
Dashboard routes for Upstream Healer.
"""
from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
import aiosqlite
from app.config import format_timestamp, current_time
from app.database import init_db

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/", response_class=HTMLResponse)
async def dashboard_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the main dashboard page.
    """
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
            host["last_seen_display"] = format_timestamp(host["last_seen_at"])
    
    # Get subnet info
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]
    
    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "hosts": hosts,
            "subnets": subnets,
            "current_time": current_time(),
        },
    )


@router.get("/pinned-subnet/{subnet_id}", response_class=HTMLResponse)
async def dashboard_pinned_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the main dashboard page with a specific subnet pinned.
    """
    async with db.execute(
        """SELECT h.*, s.status, s.last_seen_at, s.unreachable_since, s.last_check_at, s.last_ip,
                 sn.name AS subnet_name
            FROM hosts h
            LEFT JOIN host_state s ON s.host_id = h.id
            LEFT JOIN subnets sn ON sn.id = h.subnet_id
            WHERE h.subnet_id = ?
            ORDER BY h.name, h.port""",
        (subnet_id,),
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
            host["last_seen_display"] = format_timestamp(host["last_seen_at"])
    
    # Get subnet info
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets WHERE id = ? ORDER BY name", (subnet_id,)) as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]
    
    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "hosts": hosts,
            "subnets": subnets,
            "current_time": current_time(),
            "pinned_subnet_id": subnet_id
        },
    )