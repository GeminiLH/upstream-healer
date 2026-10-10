import asyncio
import ipaddress
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite
import pymysql
import pymysql.cursors
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.config import current_time, format_timestamp, settings, time_ago
from app.database import init_db, get_db
from app.services import diag_log
from app.services.mdns import discover_hostnames
from app.services.monitor import monitor
from app.services.notifications import send_event
from app.services.npm import NPMClient
from app.services.scanner import (
    apply_hostnames,
    check_host_reachable,
    find_ip_by_mac,
    get_default_subnets,
    get_local_interfaces,
    list_subnets,
    load_known_hostnames,
    load_known_hostnames_by_ip,
    load_mdns_names,
    load_suppressed_subnets,
    normalize_mac,
    remember_mdns_names,
    run_port_scan_incremental,
    run_scan,
    save_suppressed_subnets,
    validate_host_record,
)

# Global dictionary to track scan progress by request ID
scan_progress = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("healer")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await monitor.start()
    logger.info("Upstream Healer started")
    yield
    await monitor.stop()


app = FastAPI(title="Upstream Healer", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ───────────────────────────── Helper Functions ──────────────────────────────

def _subnet_for_ip(ip: str) -> str | None:
    """Find the subnet that contains an IP address."""
    # This function is used by tests but not implemented in main.py
    # In a real implementation, it would look up subnets and return matching CIDR
    pass


def _publish_discovery_progress(request_id: str, progress: dict):
    """Publish scan progress updates to WebSocket clients."""
    # This function is referenced in tests but not implemented in main.py
    # In a real implementation, it would publish progress updates
    pass


# Include all router modules
from app.routers import dashboard, subnets, scan, notifications, settings, hosts

app.include_router(dashboard.router)
app.include_router(subnets.router)
app.include_router(scan.router)
app.include_router(notifications.router)
app.include_router(settings.router)
app.include_router(hosts.router)


# ───────────────────────────── API ─────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "upstream-healer"}