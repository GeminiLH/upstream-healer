"""
Interact with Nginx Proxy Manager via Docker + SQLite.
"""
import docker
import logging
from typing import Optional, Dict, Any
from app.config import settings

logger = logging.getLogger("healer.npm")


class NPMClient:
    def __init__(self):
        self.client = docker.from_env()
        self.container_name = settings.npm_container

    def _get_container(self):
        try:
            return self.client.containers.get(self.container_name)
        except docker.errors.NotFound:
            logger.error(f"NPM container '{self.container_name}' not found")
            raise RuntimeError(f"Container {self.container_name} not found")

    def exec(self, cmd: str) -> str:
        container = self._get_container()
        exit_code, output = container.exec_run(cmd, demux=False)
        result = output.decode(errors="ignore") if output else ""
        if exit_code != 0:
            logger.warning(f"Command failed ({exit_code}): {cmd}\n{result}")
        return result

    def get_proxy_host(self, proxy_host_id: int) -> Optional[Dict[str, Any]]:
        """Fetch a proxy host row from NPM database."""
        sql = f"SELECT id, domain_names, forward_host, forward_port, forward_scheme FROM proxy_host WHERE id = {int(proxy_host_id)};"
        output = self.exec(f'sqlite3 {settings.npm_db_path_in_container} "{sql}"')
        line = output.strip()
        if not line:
            return None
        parts = line.split("|")
        if len(parts) < 5:
            return None
        return {
            "id": int(parts[0]),
            "domain_names": parts[1],
            "forward_host": parts[2],
            "forward_port": int(parts[3]) if parts[3] else 80,
            "forward_scheme": parts[4] or "http",
        }

    def update_forward_host(self, proxy_host_id: int, new_ip: str) -> bool:
        """Update the forward_host IP for a proxy host."""
        # Escape carefully
        new_ip = new_ip.replace("'", "").replace('"', "").strip()
        sql = f"UPDATE proxy_host SET forward_host = '{new_ip}' WHERE id = {int(proxy_host_id)};"
        self.exec(f'sqlite3 {settings.npm_db_path_in_container} "{sql}"')

        # Verify
        host = self.get_proxy_host(proxy_host_id)
        if host and host["forward_host"] == new_ip:
            logger.info(f"Updated proxy_host {proxy_host_id} → {new_ip}")
            return True
        logger.error(f"Failed to update proxy_host {proxy_host_id}")
        return False

    def reload_nginx(self) -> bool:
        """Graceful reload – does not drop existing connections."""
        # First test config
        test = self.exec("nginx -t")
        if "successful" not in test.lower() and "ok" not in test.lower():
            logger.error(f"nginx -t failed:\n{test}")
            return False

        self.exec("nginx -s reload")
        logger.info("nginx gracefully reloaded")
        return True

    def list_proxy_hosts(self) -> list:
        """Return basic list of proxy hosts (for UI helper)."""
        sql = "SELECT id, domain_names, forward_host, forward_port FROM proxy_host WHERE is_deleted = 0 ORDER BY id;"
        output = self.exec(f'sqlite3 {settings.npm_db_path_in_container} "{sql}"')
        hosts = []
        for line in output.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 4:
                hosts.append(
                    {
                        "id": int(parts[0]),
                        "domain_names": parts[1],
                        "forward_host": parts[2],
                        "forward_port": parts[3],
                    }
                )
        return hosts
