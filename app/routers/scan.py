"""
Scan control routes for Upstream Healer.
"""
import aiosqlite
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.database import get_db
from app.services.scanner import (
    get_default_subnets,
    run_port_scan_incremental,
    run_scan,
)

router = APIRouter(prefix="/scan", tags=["scan"])


@router.get("/", response_class=HTMLResponse)
async def scan_page(request: Request, db: aiosqlite.Connection = Depends(get_db)):
    """
    Render the scan control page.
    """
    # Get all subnets
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]

    # Get default subnets
    default_subnets = get_default_subnets()

    # Import templates to avoid F821 error - use the same approach as main.py
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        request,
        "scan.html",
        {
            "subnets": subnets,
            "default_subnets": default_subnets,
        },
    )


@router.post("/run-scan")
async def run_scan_endpoint(db: aiosqlite.Connection = Depends(get_db)):
    """
    Run a full scan.
    """
    # Get all subnets
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]

    # Run the scan
    await run_scan(subnets)

    return {"status": "Scan initiated"}


@router.post("/run-port-scan")
async def run_port_scan_endpoint(db: aiosqlite.Connection = Depends(get_db)):
    """
    Run a port scan.
    """
    # Get all subnets
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]

    # Run the port scan
    await run_port_scan_incremental(subnets)

    return {"status": "Port scan initiated"}
