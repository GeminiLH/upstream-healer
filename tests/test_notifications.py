"""Tests for app.services.notifications — event log and channel dispatch."""
from __future__ import annotations
import re

import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiosqlite
import pytest

from app.config import Settings
from app.database import init_db
from app.services.notifications import (
    EVENT_TYPES,
    IP_ADDRESS,
    MAC_ADDRESS,
    _send_email,
    _send_telegram,
    send_event,
)


class TestEventTypes:
    def test_event_types(self):
        assert EVENT_TYPES == [
            "unreachable",
            "scan_started",
            "ip_found",
            "updated",
            "recovered",
            "failed",
            "manual",
        ]

    def test_regexes(self):
        assert IP_ADDRESS.pattern == r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
        assert re.search(MAC_ADDRESS, "AA:BB:CC:DD:EE:FF")
        assert re.search(MAC_ADDRESS, "aa-bb-cc-dd-ee-ff")
        assert not re.search(MAC_ADDRESS, "not a mac")

    def test_mac_and_ip_can_be_stripped(self):
        text = "Host at 192.168.1.50 with MAC AA:BB:CC:DD:EE:FF seen"
        cleaned = MAC_ADDRESS.sub("", IP_ADDRESS.sub("", text))
        assert "192.168.1.50" not in cleaned
        assert "AA:BB:CC:DD:EE:FF" not in cleaned


@pytest.fixture
async def event_db(tmp_path):
    """A real throwaway SQLite DB (schema via init_db) for persistence tests."""
    s = Settings(data_dir=tmp_path, db_path=tmp_path / "events.db")
    with patch("app.database.settings", s):
        await init_db()
    db = await aiosqlite.connect(s.db_path)
    db.row_factory = aiosqlite.Row
    yield db, s.db_path
    await db.close()


class TestSendEvent:
    async def test_inserts_row_and_commits(self, event_db):
        db, db_path = event_db
        await send_event(db, "unreachable", "Vault lost", "10.0.0.5 not responding", host_id=None, notify=False)
        async with aiosqlite.connect(db_path) as verify:  # fresh connection proves commit
            verify.row_factory = aiosqlite.Row
            async with verify.execute("SELECT event_type, message, details FROM events") as cur:
                row = await cur.fetchone()
        assert row["event_type"] == "unreachable"
        assert row["message"] == "Vault lost"
        assert row["details"] == "10.0.0.5 not responding"

    async def test_notify_without_channels_does_not_raise(self, event_db):
        db, _ = event_db
        await send_event(db, "unreachable", "msg", host_id=None, notify=True)

    async def test_dispatches_to_telegram_channel(self, event_db):
        db, _ = event_db
        await db.execute(
            "INSERT INTO notification_channels (type, name, enabled, config) "
            "VALUES ('telegram', 'ch', 1, ?)",
            (json.dumps({"bot_token": "tok", "chat_ids": ["42"]}),),
        )
        await db.execute(
            "INSERT INTO notification_rules (event_type, channel_id, enabled) VALUES ('unreachable', 1, 1)"
        )
        await db.commit()

        calls = []

        async def fake_telegram(config, message, details=""):
            calls.append((config, message, details))

        with patch("app.services.notifications._send_telegram", new=AsyncMock(side_effect=fake_telegram)):
            await send_event(db, "unreachable", "Vault down", "10.0.0.5", host_id=None, notify=True)

        assert len(calls) == 1
        config, message, details = calls[0]
        assert config["chat_ids"] == ["42"]
        assert "Vault down" in message


class TestSendTelegram:
    async def test_no_token_skips(self):
        with patch("httpx.AsyncClient") as mock_client_cls:
            await _send_telegram({"chat_ids": ["1"]}, "hello")
        mock_client_cls.assert_not_called()

    async def test_no_chat_ids_skips(self):
        with patch("httpx.AsyncClient") as mock_client_cls:
            await _send_telegram({"bot_token": "t"}, "hello")
        mock_client_cls.assert_not_called()

    async def test_posts_to_each_chat_and_strips_identifiers(self):
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = False
        mock_client.post.return_value = MagicMock(status_code=200, text="ok")
        with patch("httpx.AsyncClient", return_value=mock_client):
            await _send_telegram(
                {"bot_token": "tok", "chat_ids": ["11", "22"]},
                "Host vault at 192.168.1.50 recovered",
                "retry ok",
            )
        assert mock_client.post.call_count == 2
        for call in mock_client.post.call_args_list:
            text = call.kwargs["json"]["text"]
            assert "192.168.1.50" not in text
            assert "Upstream Healer" in text


class TestSendEmail:
    async def test_missing_config_skips(self):
        async def run(config):
            with patch("app.services.notifications.aiosmtplib.send", new=AsyncMock()) as mock_send:
                await _send_email(config, "subject")
            return mock_send

        mock_send = await run({"smtp_host": "smtp.x", "username": "u", "password": "p"})  # no to_addrs
        mock_send.assert_not_awaited()
        mock_send = await run({"username": "u", "password": "p", "to_addrs": ["a@b"]})  # no host
        mock_send.assert_not_awaited()

    async def test_sends_email(self):
        mock_send = AsyncMock()
        with patch("app.services.notifications.aiosmtplib.send", new=mock_send):
            await _send_email(
                {
                    "smtp_host": "smtp.example.com",
                    "smtp_port": 587,
                    "username": "healer@example.com",
                    "password": "pw",
                    "to_addrs": ["a@example.com", "b@example.com"],
                },
                "Host vault down",
                "192.168.1.50 timeout",
            )
        mock_send.assert_awaited_once()
        kwargs = mock_send.call_args.kwargs
        assert kwargs["hostname"] == "smtp.example.com"
        assert kwargs["port"] == 587
        msg = mock_send.call_args.args[0]
        assert "a@example.com, b@example.com" in msg["To"]
        # unlike Telegram, the email body keeps raw details
        assert "Host vault down" in msg.get_content()
        assert "192.168.1.50 timeout" in msg.get_content()