"""
Subnet management routes for Upstream Healer.
"""
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import aiosqlite
import json
from app.config import current_time
from app.database import init_db
from app.services.scanner import (
    get_default_subnets,
    load_known_hostnames,
    load_mdns_names,
    load_suppressed_subnets,
    apply_hostnames,
    check_host_reachable,
    find_ip_by_mac,
    list_subnets,
    run_scan,
    run_port_scan_incremental,
    validate_host_record,
    save_suppressed_subnets,
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
    name: str,
    cidr: str,
    interface: str = "",
    db: aiosqlite.Connection = Depends(init_db),
):
    """
    Add a new subnet to the database.
    """
    try:
        # Validate CIDR
        import ipaddress
        ipaddress.ip_network(cidr)
        
        await db.execute(
            "INSERT INTO subnets (name, cidr, interface, enabled, created_at) VALUES (?, ?, ?, 1, ?)",
            (name, cidr, interface, current_time().isoformat()),
        )
        await db.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {str(e)}")
    
    return RedirectResponse("/subnets", status_code=303)


@router.post("/toggle/{subnet_id}")
async def toggle_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Toggle the enabled state of a subnet.
    """
    await db.execute(
        "UPDATE subnets SET enabled = 1 - enabled WHERE id = ?",
        (subnet_id,),
    )
    await db.commit()
    return RedirectResponse("/subnets", status_code=303)


@router.post("/delete/{subnet_id}")
async def delete_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Delete a subnet from the database.
    """
    await db.execute("DELETE FROM subnets WHERE id = ?", (subnet_id,))
    await db.commit()
    return RedirectResponse("/subnets", status_code=303)


@router.get("/suppressed", response_class=HTMLResponse)
async def suppressed_subnets_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the page for managing suppressed subnets.
    """
    async with db.execute("SELECT * FROM suppressed_subnets") as cursor:
        suppressed = [dict(r) for r in await cursor.fetchall()]
    
    return templates.TemplateResponse(
        "suppressed.html",
        {
            "request": request,
            "suppressed": suppressed,
        },
    )


@router.post("/suppressed/add")
async def add_suppressed_subnet(cidr: str, db: aiosqlite.Connection = Depends(init_db)):
    """
    Add a subnet to the suppressed list.
    """
    try:
        # Validate CIDR
        import ipaddress
        ipaddress.ip_network(cidr)
        
        await db.execute(
            "INSERT INTO suppressed_subnets (cidr, created_at) VALUES (?, ?)",
            (cidr, current_time().isoformat()),
        )
        await db.commit()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {str(e)}")
    
    return RedirectResponse("/subnets/suppressed", status_code=303)


@router.post("/suppressed/delete/{subnet_id}")
async def delete_suppressed_subnet(subnet_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Delete a subnet from the suppressed list.
    """
    await db.execute("DELETE FROM suppressed_subnets WHERE id = ?", (subnet_id,))
    await db.commit()
    return RedirectResponse("/subnets/suppressed", status_code=303)