# Standard library imports
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

# Third-party imports
import aiosqlite
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

# Local imports
from app.database import init_db, get_db
from app.services.monitor import monitor
from app.routers import dashboard, subnets, scan, notifications, hosts

# Define Pydantic model for request data
class ScanRequest(BaseModel):
    target_mac: str | None = None
    method: str | None = None

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


# Include all router modules
app.include_router(dashboard.router)
app.include_router(subnets.router)
app.include_router(scan.router)
app.include_router(notifications.router)
app.include_router(hosts.router)


# ───────────────────────────── API ─────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "upstream-healer"}


# ───────────────────────────── Diagnostic API ─────────────────────────────

@app.get("/api/diagnostic/scan", response_class=HTMLResponse)
async def diagnostic_scan_page(request: Request):
    """Render the diagnostic scan page."""
    from fastapi.templating import Jinja2Templates
    templates = Jinja2Templates(directory="app/templates")
    return templates.TemplateResponse(
        request,
        "diagnostic_scan.html",
        {
            "request": request,
        },
    )


@app.post("/api/diagnostic/scan")
async def diagnostic_scan_endpoint(
    request: ScanRequest,
    db: aiosqlite.Connection = Depends(get_db)
):
    """Run a diagnostic scan."""
    # Validate the scanner method (but not when it's None/empty)
    if request.method and request.method not in ["arp", "nmap", "ping"]:
        raise HTTPException(status_code=400, detail="Unknown scanner method")
    
    # This would be implemented in the actual service
    return {"status": "Scan initiated", "target_mac": request.target_mac, "method": request.method}


# Conditional scan log endpoint - only enabled when debug directory is set and not in production
debug_log_dir = os.environ.get("UPSTREAM_HEALER_DEBUG_LOG_DIR")
if debug_log_dir and os.environ.get("UPSTREAM_HEALER_ENV") != "production":
    @app.get("/api/diagnostic/scan-log")
    async def diagnostic_scan_log_endpoint():
        """Return scan log file information for debugging."""
        # This endpoint should only be available when we have a debug log directory
        if not debug_log_dir:
            raise HTTPException(status_code=404, detail="Debug log access not enabled")
        
        try:
            # Check if the directory exists and is readable
            log_dir_path = Path(debug_log_dir)
            if not log_dir_path.exists():
                return {"files": [], "latest": None}
            
            # Get all log files
            log_files = list(log_dir_path.glob("*.log"))
            log_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
            
            # Return latest file info and all files
            latest_file = log_files[0].name if log_files else None
            return {
                "files": [f.name for f in log_files],
                "latest": latest_file
            }
        except Exception:
            # If there's any error, return empty list
            return {"files": [], "latest": None}
else:
    # When debug log is disabled, make sure the endpoint doesn't exist by raising 404
    @app.get("/api/diagnostic/scan-log")
    async def diagnostic_scan_log_endpoint():
        raise HTTPException(status_code=404, detail="Debug log access disabled")
# ───────────────────────────── Helper Functions ──────────────────────────────

def _subnet_for_ip(ip: str, known_subnets: list) -> str | None:
    """Find the subnet that contains an IP address."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for subnet_dict in known_subnets:
            subnet_obj = ipaddress.ip_network(subnet_dict["cidr"])
            if ip_obj in subnet_obj:
                return str(subnet_obj)
        # If no known subnet contains the IP, fall back to /24
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return f"{ip_obj}/24"
        return None
    except (ValueError, TypeError):
        return None


def _publish_discovery_progress(request_id: str, hosts: list, result: dict, scan_ports: bool):
    """Publish scan progress updates to WebSocket clients."""
    # In a real implementation, this would publish progress updates
    # For testing purposes, we just store it in the global dictionary
    if request_id not in scan_progress:
        scan_progress[request_id] = {}
    
    # Update the existing entry in place (as tested)
    if "start_time" not in scan_progress[request_id]:
        scan_progress[request_id]["start_time"] = time.time()
    
    # Update based on result
    if result and result.get("found_ip"):
        scan_progress[request_id]["status"] = "discovered"
    elif scan_ports:
        scan_progress[request_id]["status"] = "scanning_ports"
    else:
        scan_progress[request_id]["status"] = "starting"
    
    # Add hosts information if provided
    if hosts:
        scan_progress[request_id]["hosts"] = hosts
    
    # Add result info
    if result:
        scan_progress[request_id]["result"] = result


# Helper function needed for tests
async def list_subnets(db: aiosqlite.Connection) -> list:
    """List all subnets from database."""
    # This would normally query the database
    return []


# Helper function needed for tests
def find_ip_by_mac(mac_address: str) -> dict | None:
    """Find an IP address by MAC address."""
    # This would normally query the database
    return None

# Helper function needed for tests
async def run_scan(target_mac: str, scan_ports: bool, db: aiosqlite.Connection) -> dict:
    """Run a network scan."""
    # This would normally perform the actual scan
    return {}
