"""Tests for app.services.npm — discovery, credentials, MySQL access.

The Docker client is mocked end to end; no Docker daemon is required.
"""
from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
import pymysql

from app.config import Settings
from app.services.npm import NPMClient

ENV_OUTPUT = (
    b"DB_MYSQL_HOST=nginx-db-1\n"
    b"DB_MYSQL_PORT=3306\n"
    b"DB_MYSQL_USER=npm_user\n"
    b"DB_MYSQL_PASSWORD=s3cret\n"
    b"DB_MYSQL_NAME=proxy_manager\n"
)

ALL_CREDS = {
    "DB_MYSQL_HOST": "nginx-db-1",
    "DB_MYSQL_PORT": "3306",
    "DB_MYSQL_USER": "npm_user",
    "DB_MYSQL_PASSWORD": "s3cret",
    "DB_MYSQL_NAME": "proxy_manager",
}


def _set_env_output(client, output: bytes):
    client._container.exec_run.return_value = (0, output)


def _make_conn(fetchone=None, fetchall=None, rowcount=0):
    """A MagicMock that behaves like the ``pymysql.connect(...)`` object used
    as a context manager (``with ... as conn: with conn.cursor() as cur``)."""
    cursor = MagicMock()
    cursor.__enter__ = MagicMock(return_value=cursor)
    cursor.__exit__ = MagicMock(return_value=False)
    cursor.fetchone.return_value = fetchone
    cursor.fetchall.return_value = fetchall
    cursor.rowcount = rowcount
    inner = MagicMock()
    inner.cursor.return_value = cursor
    conn = MagicMock()
    conn.__enter__ = MagicMock(return_value=inner)
    conn.__exit__ = MagicMock(return_value=False)
    return conn


class TestAvailability:
    @patch("docker.from_env")
    def test_available_when_docker_reachable(self, mock_from_env):
        mock_from_env.return_value.ping.return_value = None
        assert NPMClient().available is True

    @patch("docker.from_env")
    def test_unavailable_when_docker_fails(self, mock_from_env):
        mock_from_env.side_effect = Exception("no docker daemon")
        assert NPMClient().available is False

    def test_container_name_from_settings(self):
        assert NPMClient().container_name == "nginx-app-1"
    def test_container_name_is_configurable(self):
        client = NPMClient()
        client.container_name = "my-nginx"
        assert client.container_name == "my-nginx"


class TestGetDbCredentials:
    def test_reads_credentials_from_container(self, npm_client):
        _set_env_output(npm_client, ENV_OUTPUT)
        assert npm_client._get_db_credentials() == ALL_CREDS

    def test_caches_credentials(self, npm_client):
        _set_env_output(npm_client, ENV_OUTPUT)
        assert npm_client._get_db_credentials() is npm_client._get_db_credentials()

    def test_container_exec_failure_raises(self, npm_client):
        npm_client._container.exec_run.side_effect = Exception("boom")
        with pytest.raises(RuntimeError, match="failed to run"):
            npm_client._get_db_credentials()

    def test_invalid_container_env_raises(self, npm_client):
        _set_env_output(npm_client, b"DB_MYSQL_HOST=nginx-db-1\n")
        with pytest.raises(RuntimeError, match="NPM DB credentials unavailable"):
            npm_client._get_db_credentials()

    def test_falls_back_to_settings_when_container_env_missing(self, npm_client, monkeypatch):
        # Container only exposes the host; the rest must come from NPM_DB_* settings
        _set_env_output(npm_client, b"DB_MYSQL_HOST=nginx-db-1\n")
        fallback = Settings(
            npm_db_host="10.1.2.3",
            npm_db_port=3307,
            npm_db_user="fallback_user",
            npm_db_password="fallback_pass",
            npm_db_name="npm_fallback",
        )
        monkeypatch.setattr("app.services.npm.settings", fallback)
        creds = npm_client._get_db_credentials()
        assert creds == {
            "DB_MYSQL_HOST": "10.1.2.3",
            "DB_MYSQL_PORT": "3307",
            "DB_MYSQL_USER": "fallback_user",
            "DB_MYSQL_PASSWORD": "fallback_pass",
            "DB_MYSQL_NAME": "npm_fallback",
        }

    def test_fallback_still_requires_user_and_password(self, npm_client, monkeypatch):
        _set_env_output(npm_client, b"DB_MYSQL_HOST=nginx-db-1\n")
        monkeypatch.setattr("app.services.npm.settings", Settings())  # user/pass empty
        with pytest.raises(RuntimeError, match="NPM_DB"):
            npm_client._get_db_credentials()


class TestGetConnection:
    def test_connection_kwargs(self, npm_client):
        npm_client._db_creds = {
            "DB_MYSQL_HOST": "db.example",
            "DB_MYSQL_PORT": "3307",
            "DB_MYSQL_USER": "u",
            "DB_MYSQL_PASSWORD": "p",
            "DB_MYSQL_NAME": "db",
        }
        with patch("pymysql.connect") as mock_connect:
            conn = npm_client._get_connection()
        mock_connect.assert_called_once_with(
            host="db.example",
            port=3307,
            user="u",
            password="p",
            database="db",
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor,
            connect_timeout=5,
            read_timeout=10,
            write_timeout=10,
        )
        assert conn is mock_connect.return_value

    def test_missing_credentials_raises(self, npm_client):
        npm_client._db_creds = None
        npm_client._container.exec_run.side_effect = Exception("boom")
        with pytest.raises(RuntimeError):
            npm_client._get_connection()


class TestDatabaseAccess:
    def test_get_proxy_host_returns_dict(self, npm_client):
        row = {"id": 5, "host": "vault.dynu.com", "status": 1}
        npm_client._db_creds = dict(ALL_CREDS)
        conn = _make_conn(fetchone=row)
        with patch("pymysql.connect", return_value=conn):
            assert npm_client.get_proxy_host(5) == row

    def test_get_proxy_host_none_when_missing(self, npm_client):
        npm_client._db_creds = dict(ALL_CREDS)
        conn = _make_conn(fetchone=None)
        with patch("pymysql.connect", return_value=conn):
            assert npm_client.get_proxy_host(99) is None

    def test_list_proxy_hosts(self, npm_client):
        rows = [{"id": 1, "host": "a.com"}, {"id": 2, "host": "b.com"}]
        npm_client._db_creds = dict(ALL_CREDS)
        conn = _make_conn(fetchall=rows)
        with patch("pymysql.connect", return_value=conn):
            assert npm_client.list_proxy_hosts() == rows

    def test_update_forward_host_no_match(self, npm_client):
        npm_client._db_creds = dict(ALL_CREDS)
        conn = _make_conn(rowcount=0)
        with patch("pymysql.connect", return_value=conn):
            assert npm_client.update_forward_host(7, "10.0.0.9") is False

    def test_update_forward_host_success(self, npm_client):
        npm_client._db_creds = dict(ALL_CREDS)
        update_conn = _make_conn(rowcount=1)
        verify_conn = _make_conn(fetchone={"id": 7, "forward_host": "10.0.0.9"})
        with patch("pymysql.connect", side_effect=[update_conn, verify_conn]):
            assert npm_client.update_forward_host(7, "10.0.0.9") is True
        inner = update_conn.__enter__.return_value
        inner.commit.assert_called_once()


class TestExec:
    def test_exec_success(self, npm_client):
        npm_client._container.exec_run.return_value = (0, b"output line")
        assert npm_client.exec("nginx -t") == "output line"

    def test_exec_failure_returns_output_and_logs(self, npm_client, caplog):
        npm_client._container.exec_run.return_value = (1, b"nginx: [emerg]")
        with caplog.at_level(logging.WARNING, logger="healer.npm"):
            result = npm_client.exec("nginx -t")
        assert result == "nginx: [emerg]"
        assert any("Command failed (1)" in r.message for r in caplog.records)


class TestReloadNginx:
    def test_reload_nginx_success(self, npm_client):
        npm_client._container.exec_run.return_value = (
            0,
            b"nginx: configuration file /etc/nginx/nginx.conf test is successful",
        )
        assert npm_client.reload_nginx() is True

    def test_reload_nginx_failure(self, npm_client):
        npm_client._container.exec_run.return_value = (1, b"nginx: [emerg] invalid")
        assert npm_client.reload_nginx() is False


class TestDockerUnavailable:
    @pytest.fixture
    def offline(self, npm_client):
        npm_client._docker_available = False
        return npm_client

    def test_get_proxy_host_returns_none(self, offline):
        assert offline.get_proxy_host(1) is None

    def test_update_forward_host_returns_false(self, offline):
        assert offline.update_forward_host("1.1.1.1", "2.2.2.2") is False

    def test_list_proxy_hosts_returns_empty(self, offline):
        assert offline.list_proxy_hosts() == []

    def test_reload_nginx_returns_false(self, offline):
        assert offline.reload_nginx() is False