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
from app.database import init_db
from app.services import diag_log
from app.services.mdns import discover_hostnames
from app.services.monitor import monitor
from app.services.notifications import send_event
from app.services.npm import NPMClient

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


async def get_db():
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()


# Import and include all router modules
from app.routers import dashboard, subnets, scan, notifications, settings

app.include_router(dashboard.router)
app.include_router(subnets.router)
app.include_router(scan.router)
app.include_router(notifications.router)
app.include_router(settings.router)


# ───────────────────────────── API ─────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "upstream-healer"}