"""Tests for app.cli — argument parsing and admin commands."""
from __future__ import annotations

import asyncio
import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

import aiosqlite
import pytest

from app.cli import (
    add_host,
    add_telegram,
    build_parser,
    disable_host,
    disable_telegram,
    edit_host,
    list_events,
    list_hosts,
    list_telegram,
    main,
)
from app.config import Settings
from app.database import init_db


@pytest.fixture
async def cli_db(tmp_path, monkeypatch):
    """Temp DB (real SQLite file) with settings patched into cli + database."""
    s = Settings(data_dir=tmp_path / "data", db_path=tmp_path / "cli.db")
    monkeypatch.setattr("app.cli.settings", s)
    monkeypatch.setattr("app.database.settings", s)
    await init_db()
    db = await aiosqlite.connect(s.db_path)
    db.row_factory = aiosqlite.Row
    yield db
    await db.close()


class TestParser:
    def test_add_host_arguments(self):
        args = build_parser().parse_args([
            "add-host", "--name", "Vault", "--mac", "aa-bb-cc-dd-ee-ff",
            "--domain", "vault.dynu.com", "--port", "443", "--grace-minutes", "5",
        ])
        assert args.command == "add-host"
        assert args.name == "Vault"
        assert args.mac == "aa-bb-cc-dd-ee-ff"
        assert args.domain == "vault.dynu.com"
        assert args.port == 443
        assert args.grace_minutes == 5

    def test_list_hosts_defaults(self):
        args = build_parser().parse_args(["list-hosts"])
        assert args.command == "list-hosts"

    def test_list_events_options(self):
        args = build_parser().parse_args(["list-events", "--host-id", "3", "--days", "2", "--limit", "7"])
        assert args.host_id == 3
        assert args.days == 2
        assert args.limit == 7

    def test_disable_host_positional(self):
        args = build_parser().parse_args(["disable-host", "4"])
        assert args.host_id == 4

    def test_add_telegram_arguments(self):
        args = build_parser().parse_args([
            "add-telegram", "--name", "ops", "--bot-token", "TOKEN", "--chat-ids", "1,2,3",
        ])
        assert args.command == "add-telegram"
        assert args.chat_ids == "1,2,3"

    def test_requires_command(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])


class TestHostCommands:
    async def test_add_list_disable_host_roundtrip(self, cli_db, capsys):
        args = build_parser().parse_args(
            ["add-host", "--name", "Vault", "--mac", "aa:bb:cc:dd:ee:ff", "--port", "443"]
        )
        await add_host(args, cli_db)
        out = json.loads(capsys.readouterr().out)
        assert out == {"id": 1, "name": "Vault", "enabled": True}

        await list_hosts(cli_db)
        hosts = json.loads(capsys.readouterr().out)
        assert len(hosts) == 1
        assert hosts[0]["mac_address"] == "aa:bb:cc:dd:ee:ff"  # normalized to lowercase
        assert hosts[0]["port"] == 443
        assert hosts[0]["enabled"] == 1

        await disable_host(1, cli_db)
        out = json.loads(capsys.readouterr().out)
        assert out == {"id": 1, "enabled": False}

    async def test_add_host_validation(self, cli_db):
        with pytest.raises(ValueError, match="port"):
            await add_host(
                build_parser().parse_args(
                    ["add-host", "--name", "x", "--mac", "aa:bb:cc:dd:ee:ff", "--port", "0"]
                ),
                cli_db,
            )
        with pytest.raises(ValueError, match="grace"):
            await add_host(
                build_parser().parse_args(
                    ["add-host", "--name", "x", "--mac", "aa:bb:cc:dd:ee:ff", "--grace-minutes", "-1"]
                ),
                cli_db,
            )

    async def test_add_host_duplicate_rejected(self, cli_db):
        base = ["add-host", "--name", "x", "--mac", "aa:bb:cc:dd:ee:ff"]
        await add_host(build_parser().parse_args(base), cli_db)
        with pytest.raises(aiosqlite.IntegrityError):
            await add_host(build_parser().parse_args(base + ["--port", "80"]), cli_db)

    async def test_disable_unknown_host_raises(self, cli_db):
        with pytest.raises(ValueError, match="not found"):
            await disable_host(999, cli_db)


class TestTelegramCommands:
    async def test_add_list_disable_telegram_roundtrip(self, cli_db, capsys):
        args = build_parser().parse_args(
            ["add-telegram", "--name", "ops", "--bot-token", "T", "--chat-ids", "11, 22"]
        )
        await add_telegram(args, cli_db)
        out = json.loads(capsys.readouterr().out)
        assert out["enabled"] is True
        channel_id = out["id"]

        await list_telegram(cli_db)
        channels = json.loads(capsys.readouterr().out)
        assert len(channels) == 1
        assert channels[0]["name"] == "ops"

        await disable_telegram(channel_id, cli_db)
        out = json.loads(capsys.readouterr().out)
        assert out == {"id": channel_id, "enabled": False}

    async def test_add_telegram_requires_chat_ids(self, cli_db):
        args = build_parser().parse_args(
            ["add-telegram", "--name", "ops", "--bot-token", "T", "--chat-ids", " , "]
        )
        with pytest.raises(ValueError):
            await add_telegram(args, cli_db)

    async def test_disable_unknown_channel_raises(self, cli_db):
        with pytest.raises(ValueError, match="not found"):
            await disable_telegram(999, cli_db)


class TestEditHost:
    async def test_edit_host_updates_name(self, cli_db, capsys):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80)"
        )
        await cli_db.execute(
            "INSERT INTO host_state (host_id, status) VALUES (1, 'unknown')"
        )
        await cli_db.commit()

        args = build_parser().parse_args(["edit-host", "1", "--name", "UpdatedVault"])
        await edit_host(1, args, cli_db)

        out = json.loads(capsys.readouterr().out)
        assert out["id"] == 1
        assert out["updated"] is True

    async def test_edit_host_updates_npm_proxy_host_id(self, cli_db, capsys):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80)"
        )
        await cli_db.execute(
            "INSERT INTO host_state (host_id, status) VALUES (1, 'unknown')"
        )
        await cli_db.commit()

        args = build_parser().parse_args(["edit-host", "1", "--npm-proxy-host-id", "42"])
        await edit_host(1, args, cli_db)

        out = json.loads(capsys.readouterr().out)
        assert out["id"] == 1
        assert out["updated"] is True
        async with cli_db.execute(
            "SELECT npm_proxy_host_id FROM hosts WHERE id = 1"
        ) as cursor:
            row = await cursor.fetchone()
            assert row["npm_proxy_host_id"] == 42

    async def test_edit_host_updates_port(self, cli_db, capsys):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80)"
        )
        await cli_db.execute(
            "INSERT INTO host_state (host_id, status) VALUES (1, 'unknown')"
        )
        await cli_db.commit()

        args = build_parser().parse_args(["edit-host", "1", "--port", "443"])
        await edit_host(1, args, cli_db)

        out = json.loads(capsys.readouterr().out)
        assert out["id"] == 1
        async with cli_db.execute(
            "SELECT port FROM hosts WHERE id = 1"
        ) as cursor:
            row = await cursor.fetchone()
            assert row["port"] == 443

    async def test_edit_host_updates_ip_and_state(self, cli_db, capsys):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port, current_ip) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80, '10.0.0.1')"
        )
        await cli_db.execute(
            "INSERT INTO host_state (host_id, status, last_ip) VALUES (1, 'unknown', '10.0.0.1')"
        )
        await cli_db.commit()

        args = build_parser().parse_args(["edit-host", "1", "--ip", "10.0.0.99"])
        await edit_host(1, args, cli_db)

        out = json.loads(capsys.readouterr().out)
        assert out["id"] == 1
        async with cli_db.execute(
            "SELECT current_ip FROM hosts WHERE id = 1"
        ) as cursor:
            row = await cursor.fetchone()
            assert row["current_ip"] == "10.0.0.99"
        async with cli_db.execute(
            "SELECT last_ip FROM host_state WHERE host_id = 1"
        ) as cursor:
            row = await cursor.fetchone()
            assert row["last_ip"] == "10.0.0.99"

    async def test_edit_host_enable_disable(self, cli_db, capsys):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port, enabled) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80, 1)"
        )
        await cli_db.execute(
            "INSERT INTO host_state (host_id, status) VALUES (1, 'unknown')"
        )
        await cli_db.commit()

        # Disable
        args = build_parser().parse_args(["edit-host", "1", "--disable"])
        await edit_host(1, args, cli_db)
        async with cli_db.execute(
            "SELECT enabled FROM hosts WHERE id = 1"
        ) as cursor:
            row = await cursor.fetchone()
            assert row["enabled"] == 0

        # Enable
        args = build_parser().parse_args(["edit-host", "1", "--enable"])
        await edit_host(1, args, cli_db)
        async with cli_db.execute(
            "SELECT enabled FROM hosts WHERE id = 1"
        ) as cursor:
            row = await cursor.fetchone()
            assert row["enabled"] == 1

    async def test_edit_host_no_changes(self, cli_db, capsys):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80)"
        )
        await cli_db.execute(
            "INSERT INTO host_state (host_id, status) VALUES (1, 'unknown')"
        )
        await cli_db.commit()

        args = build_parser().parse_args(["edit-host", "1"])
        await edit_host(1, args, cli_db)

        out = capsys.readouterr().out
        assert "No changes specified" in out

    async def test_edit_host_not_found(self, cli_db):
        args = build_parser().parse_args(["edit-host", "999", "--name", "Ghost"])
        with pytest.raises(ValueError, match="not found"):
            await edit_host(999, args, cli_db)

    async def test_edit_host_invalid_port(self, cli_db):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80)"
        )
        await cli_db.commit()

        args = build_parser().parse_args(["edit-host", "1", "--port", "0"])
        with pytest.raises(ValueError, match="port"):
            await edit_host(1, args, cli_db)

    async def test_edit_host_negative_grace(self, cli_db):
        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80)"
        )
        await cli_db.commit()

        args = build_parser().parse_args(["edit-host", "1", "--grace-minutes", "-1"])
        with pytest.raises(ValueError, match="grace-minutes"):
            await edit_host(1, args, cli_db)


class TestListNpmHosts:
    @patch("app.services.npm.NPMClient")
    async def test_list_npm_hosts_returns_hosts(self, mock_npm, cli_db, capsys):
        mock_instance = MagicMock()
        mock_instance.available = True
        mock_instance.list_proxy_hosts.return_value = [
            {"id": 1, "domain_names": ["vault.hylla.us"], "forward_host": "10.0.0.1", "forward_port": 80},
            {"id": 2, "domain_names": ["jelly.hylla.us"], "forward_host": "10.0.0.2", "forward_port": 7878},
        ]
        mock_npm.return_value = mock_instance

        from app.cli import list_npm_hosts
        await list_npm_hosts(cli_db)

        out = json.loads(capsys.readouterr().out)
        assert len(out) == 2
        assert out[0]["id"] == 1
        assert out[1]["id"] == 2

    @patch("app.services.npm.NPMClient")
    async def test_list_npm_hosts_unavailable(self, mock_npm, cli_db, capsys):
        mock_instance = MagicMock()
        mock_instance.available = False
        mock_npm.return_value = mock_instance

        from app.cli import list_npm_hosts
        await list_npm_hosts(cli_db)

        out = json.loads(capsys.readouterr().out)
        assert out == []

    @patch("app.services.npm.NPMClient")
    async def test_list_npm_hosts_empty(self, mock_npm, cli_db, capsys):
        mock_instance = MagicMock()
        mock_instance.available = True
        mock_instance.list_proxy_hosts.return_value = []
        mock_npm.return_value = mock_instance

        from app.cli import list_npm_hosts
        await list_npm_hosts(cli_db)

        out = json.loads(capsys.readouterr().out)
        assert out == []


class TestListEvents:
    async def test_list_events_filters_by_days(self, cli_db, capsys):
        from app.config import current_time

        await cli_db.execute(
            "INSERT INTO hosts (name, mac_address, port) VALUES ('Vault', 'AA:BB:CC:DD:EE:FF', 80)"
        )
        await cli_db.commit()
        await cli_db.execute(
            "INSERT INTO events (host_id, event_type, message, created_at) VALUES (1, 'unreachable', 'gone', ?)",
            ((current_time() - timedelta(days=1)).isoformat(),),
        )
        await cli_db.commit()

        args = build_parser().parse_args(["list-events", "--days", "7", "--limit", "10"])
        await list_events(args, cli_db)
        events = json.loads(capsys.readouterr().out)
        assert len(events) == 1
        assert events[0]["host_name"] == "Vault"

    async def test_list_events_validates_options(self, cli_db):
        with pytest.raises(ValueError):
            await list_events(build_parser().parse_args(["list-events", "--days", "0"]), cli_db)
        with pytest.raises(ValueError):
            await list_events(build_parser().parse_args(["list-events", "--limit", "0"]), cli_db)


def test_main_reports_validation_error(monkeypatch, tmp_path, capsys):
    s = Settings(data_dir=tmp_path / "d", db_path=tmp_path / "cli.db")
    monkeypatch.setattr("app.cli.settings", s)
    monkeypatch.setattr("app.database.settings", s)
    code = main(["add-host", "--name", "x", "--mac", "aa:bb:cc:dd:ee:ff", "--port", "0"])
    assert code == 1
    assert "Error:" in capsys.readouterr().out


def test_main_list_hosts(tmp_path, monkeypatch, capsys):
    # main() uses asyncio.run(), so this must be a sync test
    s = Settings(data_dir=tmp_path / "d", db_path=tmp_path / "cli.db")
    monkeypatch.setattr("app.cli.settings", s)
    monkeypatch.setattr("app.database.settings", s)

    async def seed():
        await init_db()
        async with aiosqlite.connect(s.db_path) as db:
            await add_host(
                build_parser().parse_args(["add-host", "--name", "Vault", "--mac", "aa:bb:cc:dd:ee:ff"]),
                db,
            )

    asyncio.run(seed())
    assert main(["list-hosts"]) == 0
    assert "Vault" in capsys.readouterr().out