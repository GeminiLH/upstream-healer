"""
Scan routes for Upstream Healer.
"""
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
import aiosqlite
import json
import asyncio
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
from app.services.monitor import monitor

router = APIRouter(prefix="/scan", tags=["scan"])


@router.get("/", response_class=HTMLResponse)
async def scan_page(request: Request, db: aiosqlite.Connection = Depends(init_db)):
    """
    Render the scan control page.
    """
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]
    
    # Get default subnets
    default_subnets = get_default_subnets()
    
    return templates.TemplateResponse(
        "scan.html",
        {
            "request": request,
            "subnets": subnets,
            "default_subnets": default_subnets,
        },
    )


@router.post("/start")
async def start_scan(subnet_ids: str, db: aiosqlite.Connection = Depends(init_db)):
    """
    Start a scan on specified subnets.
    """
    try:
        subnet_id_list = [int(x.strip()) for x in subnet_ids.split(",") if x.strip()]
        
        # Run the scan
        await run_scan(subnet_id_list, db)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scan failed: {str(e)}")
    
    return RedirectResponse("/scan", status_code=303)


@router.post("/start-port-scan/{host_id}")
async def start_port_scan(host_id: int, db: aiosqlite.Connection = Depends(init_db)):
    """
    Start a port scan for a specific host.
    """
    try:
        # Run the port scan
        await run_port_scan_incremental(host_id, db)
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Port scan failed: {str(e)}")
    
    return RedirectResponse("/scan", status_code=303)


@router.post("/stop")
async def stop_scan():
    """
    Stop the current scan.
    """
    # Implementation to stop scan would go here
    # For now, we'll just return a success response
    return {"status": "stopped"}


@router.get("/progress/{request_id}")
async def get_scan_progress(request_id: str):
    """
    Get progress of a specific scan request.
    """
    # Implementation to get scan progress would go here
    # This is a placeholder for now
    return {"progress": 0, "status": "not implemented"}