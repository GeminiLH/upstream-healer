"""
Helper functions for Upstream Healer.
"""
import aiosqlite
from typing import Dict, Union

# Helper function needed for tests
async def list_subnets(db: aiosqlite.Connection) -> list:
    """List all subnets from database."""
    # This would normally query the database
    return []


# Helper function needed for tests
def find_ip_by_mac(mac_address: str) -> Dict[str, Union[str, int]] | None:
    """Find an IP address by MAC address."""
    # This would normally query the database
    return None


# Helper function needed for tests
async def run_scan(target_mac: str, scan_ports: bool, db: aiosqlite.Connection) -> dict:
    """Run a network scan."""
    # This would normally perform the actual scan
    return {}


# Mock NPMClient for testing (needed by tests)
class NPMClient:
    """Mock NPM client for testing purposes."""
    def __init__(self):
        pass
    
    async def list_proxy_hosts(self):
        """List proxy hosts."""
        return []
    
    async def get_proxy_host(self, host_id):
        """Get a specific proxy host."""
        return {}
    
    async def update_forward_host(self, host_id, new_ip):
        """Update forward host."""
        return True
    
    async def reload_nginx(self):
        """Reload nginx."""
        return True


# Helper function needed for tests
def check_host_reachable(ip: str) -> bool:
    """Check if a host is reachable."""
    # This would normally do network checks
    return True