"""
Shared pytest fixtures for the Upstream Healer test suite.

The suite never talks to a real Docker daemon, the NPM MySQL database,
or the network. Everything external is mocked; persistence tests use
throwaway SQLite databases in a temporary directory.
"""
from __future__ import annotations

import importlib

import pytest
from unittest.mock import MagicMock


@pytest.fixture
def temp_settings(tmp_path, monkeypatch):
    """
    A Settings instance pointing at a tmp dir, patched into every app
    module that holds its own ``settings`` reference (from ... import settings).
    """
    settings_cls = importlib.import_module("app.config").Settings
    s = settings_cls(
        data_dir=tmp_path / "data",
        db_path=tmp_path / "test.db",
    )
    for module_name in ("app.config", "app.database", "app.cli"):
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        if hasattr(module, "settings"):
            monkeypatch.setattr(module, "settings", s)
    return s


@pytest.fixture
def mock_container():
    """A mock NPM container whose exec_run succeeds with no output."""
    container = MagicMock()
    container.exec_run.return_value = (0, b"")
    return container


@pytest.fixture
def mock_docker_client(mock_container):
    """A mock Docker client that reports the NPM container is present."""
    client = MagicMock()
    client.ping.return_value = None
    client.containers.get.return_value = mock_container
    return client


@pytest.fixture
def npm_client(mock_docker_client):
    """
    An NPMClient wired to the mock Docker client so tests never touch
    the Docker daemon.
    """
    from app.services.npm import NPMClient

    client = NPMClient()
    client._client = mock_docker_client
    client._docker_available = True
    client._container = mock_docker_client.containers.get(client.container_name)
    return client