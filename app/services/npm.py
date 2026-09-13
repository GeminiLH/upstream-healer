"""
Interact with Nginx Proxy Manager (MariaDB/MySQL backend).

Credentials are read at runtime from the NPM app container environment
so nothing confidential is stored in the repository or healer config. If
the container does not expose the required DB_MYSQL_* values, the connection
falls back to the NPM_DB_* settings on the healer itself (see app.config) —
those also come from the environment, never from the repository.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from app.config import settings

logger = logging.getLogger("healer.npm")


class NPMClient:
    def __init__(self) -> None:
        self._client = None
        self.container_name = settings.npm_container  # nginx-app-1
        self._docker_available: Optional[bool] = None
        self._db_creds: Optional[Dict[str, str]] = None

    # ------------------------------------------------------------------
    # Docker helpers
    # ------------------------------------------------------------------
    @property
    def client(self):
        if self._client is None:
            try:
                import docker
                self._client = docker.from_env()
                self._client.ping()
                self._docker_available = True
                logger.info("Docker connection established")
            except Exception as e:
                self._docker_available = False
                logger.warning(f"Docker not available (local development mode): {e}")
                self._client = None
        return self._client

    @property
    def available(self) -> bool:
        if self._docker_available is None:
            _ = self.client
        return bool(self._docker_available)

    def _get_container(self):
        if not self.available:
            raise RuntimeError("Docker is not available on this machine")
        try:
            return self.client.containers.get(self.container_name)
        except Exception as e:
            logger.error(f"NPM container '{self.container_name}' not found: {e}")
            raise RuntimeError(f"Container {self.container_name} not found")

    def exec(self, cmd: str) -> str:
        """Run a command inside the NPM app container."""
        container = self._get_container()
        try:
            exit_code, output = container.exec_run(cmd, demux=False)
        except Exception as e:
            logger.error(f"Command failed to run in {self.container_name}: {cmd} ({e})")
            raise RuntimeError(f"failed to run '{cmd}' in container {self.container_name}: {e}")
        result = output.decode(errors="ignore") if output else ""
        if exit_code != 0:
            logger.warning(f"Command failed ({exit_code}): {cmd}\n{result}")
        return result

    # ------------------------------------------------------------------
    # Credential discovery (never stored permanently)
    # ------------------------------------------------------------------
    def _get_db_credentials(self) -> Dict[str, str]:
        """
        Read DB_MYSQL_* environment variables from the NPM app container.
        This keeps secrets out of the healer repository and config files.
        """
        if self._db_creds is not None:
            return self._db_creds

        if not self.available:
            raise RuntimeError("Docker not available – cannot read DB credentials")

        raw = self.exec("env")
        creds: Dict[str, str] = {}
        for line in raw.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key in {
                "DB_MYSQL_HOST",
                "DB_MYSQL_PORT",
                "DB_MYSQL_USER",
                "DB_MYSQL_PASSWORD",
                "DB_MYSQL_NAME",
            }:
                creds[key] = value.strip()

        required = ["DB_MYSQL_HOST", "DB_MYSQL_USER", "DB_MYSQL_PASSWORD", "DB_MYSQL_NAME"]
        missing = [k for k in required if not creds.get(k)]
        source = "NPM container environment"
        if missing:
            logger.info(
                f"NPM container does not expose {missing}; falling back to NPM_DB_* settings"
            )
            creds = {
                "DB_MYSQL_HOST": settings.npm_db_host,
                "DB_MYSQL_PORT": str(settings.npm_db_port),
                "DB_MYSQL_USER": settings.npm_db_user,
                "DB_MYSQL_PASSWORD": settings.npm_db_password,
                "DB_MYSQL_NAME": settings.npm_db_name,
            }
            source = "NPM_DB_* settings"
            missing = [k for k in required if not creds.get(k)]
            if missing:
                raise RuntimeError(
                    f"NPM DB credentials unavailable: container missing {missing} and "
                    "NPM_DB_* settings incomplete (set NPM_DB_USER / NPM_DB_PASSWORD in the environment)"
                )

        # Defaults
        creds.setdefault("DB_MYSQL_PORT", "3306")

        self._db_creds = creds
        logger.info(
            f"Loaded DB credentials from {source} "
            f"(host={creds['DB_MYSQL_HOST']}, db={creds['DB_MYSQL_NAME']}, user={creds['DB_MYSQL_USER']})"
        )
        return creds

    def _get_connection(self):
        """Return a new pymysql connection using live credentials."""
        import pymysql

        c = self._get_db_credentials()
        return pymysql.connect(
            host=c["DB_MYSQL_HOST"],
            port=int(c["DB_MYSQL_PORT"]),
            user=c["DB_MYSQL_USER"],
            password=c["DB_MYSQL_PASSWORD"],
            database=c["DB_MYSQL_NAME"],
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
            read_timeout=10,
            write_timeout=10,
        )

    # ------------------------------------------------------------------
    # Public API (same as before)
    # ------------------------------------------------------------------
    def get_proxy_host(self, proxy_host_id: int) -> Optional[Dict[str, Any]]:
        if not self.available:
            return None
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, domain_names, forward_host, forward_port, forward_scheme
                        FROM proxy_host
                        WHERE id = %s AND is_deleted = 0
                        """,
                        (int(proxy_host_id),),
                    )
                    row = cur.fetchone()
                    return dict(row) if row else None
        except Exception as e:
            logger.error(f"get_proxy_host failed: {e}")
            return None

    def update_forward_host(self, proxy_host_id: int, new_ip: str) -> bool:
        if not self.available:
            logger.error("Cannot update NPM – Docker not available")
            return False

        new_ip = new_ip.strip()
        # Basic safety – only allow IPv4 / simple hostnames
        if not re.match(r"^[0-9a-zA-Z.\-]+$", new_ip):
            logger.error(f"Refusing suspicious IP/hostname: {new_ip}")
            return False

        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE proxy_host SET forward_host = %s WHERE id = %s AND is_deleted = 0",
                        (new_ip, int(proxy_host_id)),
                    )
                    conn.commit()
                    if cur.rowcount == 0:
                        logger.error(f"No rows updated for proxy_host id={proxy_host_id}")
                        return False

            # Verify
            host = self.get_proxy_host(proxy_host_id)
            if host and host["forward_host"] == new_ip:
                logger.info(f"Updated proxy_host {proxy_host_id} → {new_ip}")
                return True

            logger.error(f"Update verification failed for proxy_host {proxy_host_id}")
            return False
        except Exception as e:
            logger.error(f"update_forward_host failed: {e}")
            return False

    def list_proxy_hosts(self) -> List[Dict[str, Any]]:
        if not self.available:
            return []
        try:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, domain_names, forward_host, forward_port
                        FROM proxy_host
                        WHERE is_deleted = 0
                        ORDER BY id
                        """
                    )
                    return [dict(row) for row in cur.fetchall()]
        except Exception as e:
            logger.warning(f"Could not list proxy hosts: {e}")
            return []

    def reload_nginx(self) -> bool:
        """Graceful reload – does not drop existing connections."""
        if not self.available:
            return False
        test = self.exec("nginx -t")
        if "successful" not in test.lower() and "ok" not in test.lower():
            logger.error(f"nginx -t failed:\n{test}")
            return False
        self.exec("nginx -s reload")
        logger.info("nginx gracefully reloaded")
        return True