"""Tests for scripts.seed_dev — idempotent dev data seeding.

Fully hermetic: throwaway SQLite via temp_settings (the seeder's settings
reference is patched by conftest), and the NPM MariaDB is mocked or
simulated as unreachable — no Docker daemon, MySQL, or network involved.
"""
from __future__ import annotations

import aiosqlite

import scripts.seed_dev as seed


class _FakeCursor:
    """Behaves like the DictCursor the seeder uses (``with cur:``).
    Each execute() consumes the next fake insert id."""

    def __init__(self, rows, insert_ids):
        self._rows = rows
        self._insert_ids = insert_ids
        self.lastrowid = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, *args, **kwargs):
        if "INSERT" not in str(sql).upper():
            return
        self.lastrowid = self._insert_ids.pop(0) if self._insert_ids else self.lastrowid

    def fetchall(self):
        return list(self._rows)


class _FakeConn:
    """Behaves like the pymysql connection the seeder uses (cursor/commit/close)."""

    def __init__(self, rows, insert_ids):
        self._rows = rows
        self._insert_ids = insert_ids
        self.closed = False

    def cursor(self):
        return _FakeCursor(self._rows, self._insert_ids)

    def commit(self):
        pass

    def close(self):
        self.closed = True


class _RecordingCursor:
    def __init__(self, conn):
        self._conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, *args):
        self._conn.statements.append((str(sql).strip(), args))

    def fetchall(self):
        return []


class _RecordingConn:
    def __init__(self):
        self.statements = []
        self.closed = False

    def cursor(self):
        return _RecordingCursor(self)

    def commit(self):
        pass

    def close(self):
        self.closed = True


async def _connect(settings):
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row
    return db


async def _host_rows(db):
    async with db.execute(
        "SELECT id, name, mac_address, port, domain, npm_proxy_host_id FROM hosts ORDER BY id"
    ) as cursor:
        return [dict(row) for row in await cursor.fetchall()]


class TestSeedHosts:
    async def test_adds_all_seed_hosts(self, temp_settings):
        assert seed.settings.db_path == temp_settings.db_path
        await seed.init_db()
        db = await _connect(seed.settings)
        try:
            added = await seed.seed_hosts(db)
            assert added == ["vault", "jellyfin", "failtest"]
            hosts = await _host_rows(db)
            assert [h["name"] for h in hosts] == ["vault", "jellyfin", "failtest"]
            assert hosts[0]["mac_address"] == "46:dc:21:61:26:93"
            assert hosts[1]["port"] == 11000
            async with db.execute("SELECT host_id, status FROM host_state ORDER BY host_id") as cursor:
                states = [dict(r) for r in await cursor.fetchall()]
            assert len(states) == 3
            assert all(s["status"] == "unknown" for s in states)
        finally:
            await db.close()

    async def test_idempotent_on_second_run(self, temp_settings):
        await seed.init_db()
        db = await _connect(seed.settings)
        try:
            first = await seed.seed_hosts(db)
            second = await seed.seed_hosts(db)
            assert len(first) == 3
            assert second == []
            hosts = await _host_rows(db)
            assert len(hosts) == 3
        finally:
            await db.close()


class TestNpmLinks:
    async def test_mysql_unreachable_is_soft(self, temp_settings, monkeypatch):
        monkeypatch.setattr(seed, "MYSQL_WAIT_SECONDS", 0.2)

        def _raise():
            raise ConnectionError("no such host")

        monkeypatch.setattr(seed, "_mysql_connect", _raise)
        links = seed.ensure_proxy_hosts()
        assert links == {}

    async def test_creates_missing_rows_and_links(self, temp_settings, monkeypatch):
        monkeypatch.setattr(seed, "_wait_for_mysql", lambda timeout: True)
        # vault's domain already exists in NPM; the others must be created.
        existing = [{"id": 11, "domain_names": "vault.hylla.us"}]
        insert_ids = [12, 13]
        conn = _FakeConn(existing, insert_ids)
        monkeypatch.setattr(seed, "_mysql_connect", lambda: conn)

        links = seed.ensure_proxy_hosts()
        assert links == {
            "vault.hylla.us": 11,
            "jelly.hylla.us": 12,
            "none.hylla.us": 13,
        }

        # ...and the sqlite side only links rows whose link is still NULL.
        await seed.init_db()
        db = await _connect(seed.settings)
        try:
            await seed.seed_hosts(db)
            async with db.execute(
                "UPDATE hosts SET npm_proxy_host_id = 99 WHERE name = 'vault'"
            ):
                pass
            await db.commit()
            linked = await seed.apply_npm_links(db, links)
            assert linked == 2  # vault was pre-linked to 99, left untouched
            hosts = {h["name"]: h for h in await _host_rows(db)}
            assert hosts["vault"]["npm_proxy_host_id"] == 99
            assert hosts["jellyfin"]["npm_proxy_host_id"] == 12
            assert hosts["failtest"]["npm_proxy_host_id"] == 13
            # a second pass must not touch the already-linked rows
            async with db.execute(
                "UPDATE hosts SET npm_proxy_host_id = 500 WHERE name = 'jellyfin'"
            ):
                pass
            await db.commit()
            assert await seed.apply_npm_links(db, links) == 0
            hosts = {h["name"]: h for h in await _host_rows(db)}
            assert hosts["jellyfin"]["npm_proxy_host_id"] == 500
        finally:
            await db.close()


class TestTelegram:
    async def test_skipped_without_env(self, temp_settings, monkeypatch):
        monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
        monkeypatch.delenv("TELEGRAM_CHAT_IDS", raising=False)
        await seed.init_db()
        db = await _connect(seed.settings)
        try:
            assert await seed.seed_telegram_if_requested(db) is False
            async with db.execute("SELECT COUNT(*) FROM notification_channels") as cursor:
                assert (await cursor.fetchone())[0] == 0
        finally:
            await db.close()

    async def test_creates_channel_once_with_env(self, temp_settings, monkeypatch):
        monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:TEST")
        monkeypatch.setenv("TELEGRAM_CHAT_IDS", "111, 222")
        await seed.init_db()
        db = await _connect(seed.settings)
        try:
            assert await seed.seed_telegram_if_requested(db) is True
            assert await seed.seed_telegram_if_requested(db) is False
            async with db.execute(
                "SELECT COUNT(*) FROM notification_channels WHERE type = 'telegram'"
            ) as cursor:
                assert (await cursor.fetchone())[0] == 1
            async with db.execute(
                "SELECT COUNT(*) FROM notification_rules"
            ) as cursor:
                assert (await cursor.fetchone())[0] == len(seed.EVENT_TYPES)
        finally:
            await db.close()


class TestBootstrap:
    def test_noop_without_root_env(self, temp_settings, monkeypatch):
        import pymysql

        monkeypatch.delenv("NPM_DB_ROOT_USER", raising=False)
        monkeypatch.delenv("NPM_DB_ROOT_PASSWORD", raising=False)
        called = []
        monkeypatch.setattr(pymysql, "connect", lambda **kw: called.append(kw))
        seed._bootstrap_npm_schema()
        assert called == []

    def test_creates_database_user_and_grants(self, temp_settings, monkeypatch):
        import pymysql

        monkeypatch.setenv("NPM_DB_ROOT_USER", "root")
        monkeypatch.setenv("NPM_DB_ROOT_PASSWORD", "secret")
        monkeypatch.setattr(seed.settings, "npm_db_user", "proxymanager")
        monkeypatch.setattr(seed.settings, "npm_db_password", "s3cret")
        monkeypatch.setattr(seed.settings, "npm_db_name", "proxy_manager")
        conn = _RecordingConn()
        monkeypatch.setattr(pymysql, "connect", lambda **kw: conn)

        seed._bootstrap_npm_schema()

        sql = " | ".join(s.upper() for s, _ in conn.statements)
        assert "CREATE DATABASE IF NOT EXISTS" in sql
        assert "CREATE USER IF NOT EXISTS" in sql
        assert "GRANT ALL PRIVILEGES" in sql
        assert "FLUSH PRIVILEGES" in sql
        assert conn.closed

    def test_soft_fails_when_root_unreachable(self, temp_settings, monkeypatch):
        import pymysql

        def _raise(**kw):
            raise ConnectionError("root login refused")

        monkeypatch.setenv("NPM_DB_ROOT_USER", "root")
        monkeypatch.setenv("NPM_DB_ROOT_PASSWORD", "wrong")
        monkeypatch.setattr(pymysql, "connect", _raise)
        seed._bootstrap_npm_schema()  # must not raise