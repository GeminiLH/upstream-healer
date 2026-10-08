"""
Subnet management routes for Upstream Healer.
"""
from fastapi import APIRouter, Request, Depends, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import aiosqlite
import ipaddress
from app.database import init_db
from app.services.scanner import (
    get_default_subnets,
    normalize_mac,
)

router = APIRouter(prefix="/subnets", tags=["subnets"])


@router.get("/", response_class=HTMLResponse)
async def subnets_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the subnet management page.
    """
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]
    
    # Get default subnets
    default_subnets = get_default_subnets()
    
    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        "subnets.html",
        {
            "request": request,
            "subnets": subnets,
            "default_subnets": default_subnets,
        },
    )


@router.post("/add")
async def add_subnet(
    name: str = Form(...),
    cidr: str = Form(...),
    interface: str = Form(""),
    db: aiosqlite.Connection = Depends(init_db),
):
    """
    Add a new subnet.
    """
    try:
        ipaddress.ip_network(cidr)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {e}")
    
    await db.execute(
        "INSERT INTO subnets (name, cidr, interface, enabled) VALUES (?, ?, ?, 1)",
        (name, cidr, interface),
    )
    await db.commit()
    return RedirectResponse("/subnets", status_code=303)


@router.post("/{subnet_id}/toggle")
async def toggle_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Toggle a subnet's enabled state.
    """
    await db.execute("UPDATE subnets SET enabled = 1 - enabled WHERE id = ?", (subnet_id,))
    await db.commit()
    return RedirectResponse("/subnets", status_code=303)


@router.post("/{subnet_id}/delete")
async def delete_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Delete a subnet.
    """
    await db.execute("DELETE FROM subnets WHERE id = ?", (subnet_id,))
    await db.commit()
    return RedirectResponse("/subnets", status_code=303)


@router.get("/suppressed", response_class=HTMLResponse)
async def suppressed_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the suppressed hosts page.
    """
    async with db.execute("SELECT id, mac_address, reason FROM suppressed_hosts ORDER BY created_at DESC") as cursor:
        suppressed = [dict(r) for r in await cursor.fetchall()]
    
    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        "suppressed.html",
        {
            "request": request,
            "suppressed": suppressed,
        },
    )


@router.post("/suppressed/add")
async def add_suppressed_host(
    mac_address: str = Form(...),
    reason: str = Form(""),
    db: aiosqlite.Connection = Depends(init_db),
):
    """
    Add a host to the suppressed list.
    """
    # Normalize MAC address
    normalized_mac = normalize_mac(mac_address)
    
    await db.execute(
        "INSERT INTO suppressed_hosts (mac_address, reason) VALUES (?, ?)",
        (normalized_mac, reason),
    )
    await db.commit()
    return RedirectResponse("/subnets/suppressed", status_code=303)


@router.post("/suppressed/{host_id}/delete")
async def delete_suppressed_host(host_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Delete a suppressed host.
    """
    await db.execute("DELETE FROM suppressed_hosts WHERE id = ?", (host_id,))
    await db.commit()
    return RedirectResponse("/subnets/suppressed", status_code=303)