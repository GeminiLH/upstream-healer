"""
Hosts routes for Upstream Healer.
"""
import aiosqlite
from fastapi import APIRouter, Depends, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

from app.config import current_time, format_timestamp
from app.database import get_db
from app.services.scanner import (
    get_default_subnets,
    load_known_hostnames_by_ip,
    validate_host_record,
)
from app.services.npm import NPMClient

router = APIRouter(tags=["hosts"])


@router.get("/hosts/add", response_class=HTMLResponse)
async def add_host_page(
    request: Request,
    db: aiosqlite.Connection = Depends(get_db),
):
    """
    Render the form to add a new host.
    """
    # Get subnet info
    async with db.execute("SELECT id, name, cidr, interface, enabled FROM subnets ORDER BY name") as cursor:
        subnets = [dict(r) for r in await cursor.fetchall()]
    
    # Get default subnets for auto-detection
    default_subnets = get_default_subnets()
    
    # Import templates to avoid F821 error
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        "host_form.html",
        {
            "request": request,
            "subnets": subnets,
            "default_subnets": default_subnets,
            "current_time": current_time(),
            "editing": False,
        },
    )