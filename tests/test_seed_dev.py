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
    Each execute() consumes the next fake insert id.

    ``schema`` is an optional table -> SHOW COLUMNS rows mapping, returned
    when a ``SHOW COLUMNS FROM ...`` is issued (so ``_fills_for`` can
    exercise the real introspection path in tests that opt in). When a table
    is not in ``schema``, ``SHOW COLUMNS`` returns an empty list (mid-migration
    shape), which the seeder treats as "nothing to auto-fill".
    """

    def __init__(self, rows, insert_ids, schema=None):
        self._rows = rows
        self._insert_ids = insert_ids
        self._schema = schema or {}
        self.lastrowid = None
        self._show_cols: list = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, *args, **kwargs):
        s = str(sql).upper()
        if "SHOW COLUMNS" in s:
            # extract the table name from "SHOW COLUMNS FROM `table`"
            table = s.split("FROM", 1)[-1].strip().strip("`").strip().lower()
            self._show_cols = self._schema.get(table, [])
            return
        if "INSERT" in s:
            self.lastrowid = self._insert_ids.pop(0) if self._insert_ids else self.lastrowid

    def fetchall(self):
        return list(self._show_cols) if self._show_cols else list(self._rows)


class _FakeConn:
    """Behaves like the pymysql connection the seeder uses (cursor/commit/close)."""

    def __init__(self, rows, insert_ids, schema=None):
        self._rows = rows
        self._insert_ids = insert_ids
        self._schema = schema
        self.closed = False

    def cursor(self):
        return _FakeCursor(self._rows, self._insert_ids, self._schema)

    def commit(self):
        pass

    def close(self):
        self.closed = True


class _RecordingCursor:
    def __init__(self, conn):
        self._conn = conn
        self.lastrowid = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, *args):
        self._conn.statements.append((str(sql).strip(), args))

    def fetchall(self):
        return []

    def fetchone(self):
        return None


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


class _ClosingCursor:
    """Fidelity-only cursor: raises ``Cursor closed`` if a statement runs
    after the surrounding ``with`` block has closed it (exactly what a real
    pymysql cursor does), and plays back scripted results.

    ``script`` is a list of ``(sql_prefix, result)`` pairs, matched in order
    by substring (case-insensitive) against the most recent ``execute``.
    ``fetchall`` returns ``list(result)`` (so a single-row script entry works
    for both SELECTs); ``fetchone`` returns the first row. A result of
    ``None`` means "no rows". Recording executed statements lets a regression
    assert that a statement no longer runs *after* its cursor closes.
    """

    def __init__(self, script):
        self.script = script
        self._open = False
        self._last_sql = ""
        self.executed = []
        self.lastrowid = None

    def __enter__(self):
        self._open = True
        return self

    def __exit__(self, *exc):
        self._open = False
        return False

    def _match(self, sql):
        s = str(sql).lower()
        for prefix, result in self.script:
            if prefix.lower() in s:
                return result
        return None

    def execute(self, sql, *args):
        if not self._open:
            raise RuntimeError("Cursor closed")
        self._last_sql = str(sql)
        self.executed.append(str(sql).strip())
        if "insert" in str(sql).lower():
            self.lastrowid = (self.lastrowid or 0) + 1
        # SHOW COLUMNS is a SELECT-style statement; _match will find no
        # scripted entry (the script has no "show columns" key) and return
        # None, so fetchall() returns [] — the seeder then sees an empty
        # schema and skips auto-fill, which is safe (the pre-introspection
        # INSERT list is unchanged).
        return self._match(self._last_sql)

    def fetchone(self):
        if not self._open:
            raise RuntimeError("Cursor closed")
        result = self._match(self._last_sql)
        return result[0] if result else None

    def fetchall(self):
        if not self._open:
            raise RuntimeError("Cursor closed")
        result = self._match(self._last_sql)
        return list(result) if result is not None else []


class _ClosingConn:
    """Connection handout for the fidelity cursor: a fresh ``_ClosingCursor``
    per ``cursor()`` call, sharing one script so every block sees the same
    scripted results. Also records every cursor it hands out."""

    def __init__(self, script):
        self.script = script
        self.cursors = []

    def cursor(self):
        cur = _ClosingCursor(self.script)
        self.cursors.append(cur)
        return cur

    def commit(self):
        pass

    def close(self):
        pass


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
            assert set(added) == {
                "vault", "jellyfin", "failtest", "plex", "homeassistant",
                "portainer", "batcave", "flash",
            }
            hosts = await _host_rows(db)
            assert set(h["name"] for h in hosts) == {
                "vault", "jellyfin", "failtest", "plex", "homeassistant",
                "portainer", "batcave", "flash",
            }
            assert hosts[0]["mac_address"] == "46:dc:21:61:26:93"
            assert hosts[1]["port"] == 11000
            async with db.execute("SELECT host_id, status FROM host_state ORDER BY host_id") as cursor:
                states = [dict(r) for r in await cursor.fetchall()]
            # batcave/flash are seeded disabled, so they get no host_state row.
            assert len(states) == 6
            assert all(s["status"] == "unknown" for s in states)
        finally:
            await db.close()


    async def test_idempotent_on_second_run(self, temp_settings):
        await seed.init_db()
        db = await _connect(seed.settings)
        try:
            added1 = await seed.seed_hosts(db)
            added2 = await seed.seed_hosts(db)
            assert added2 == []
            hosts = await _host_rows(db)
            assert len(hosts) == 8
            assert len(added1) == 8
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
        insert_ids = [12, 13, 14, 15, 16]
        conn = _FakeConn(existing, insert_ids)
        monkeypatch.setattr(seed, "_mysql_connect", lambda: conn)
        calls = []
        monkeypatch.setattr(
            seed, "_ensure_npm_defaults", lambda c: calls.append(1) or (3, 4, 0)
        )

        links = seed.ensure_proxy_hosts()
        assert calls == [1]  # ids provisioned exactly once per seeding pass
        assert links == {
            "vault.hylla.us": 11,
            "jelly.hylla.us": 12,
            "none.hylla.us": 13,
            "plex.hylla.us": 14,
            "ha.hylla.us": 15,
            "portainer.hylla.us": 16,
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
            assert linked == 5  # vault was pre-linked to 99, left untouched; 5 others linked
            hosts = {h["name"]: h for h in await _host_rows(db)}
            assert hosts["vault"]["npm_proxy_host_id"] == 99
            assert hosts["jellyfin"]["npm_proxy_host_id"] == 12
            assert hosts["failtest"]["npm_proxy_host_id"] == 13
            assert hosts["plex"]["npm_proxy_host_id"] == 14
            assert hosts["homeassistant"]["npm_proxy_host_id"] == 15
            assert hosts["portainer"]["npm_proxy_host_id"] == 16
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

    async def test_retries_while_schema_still_migrating(self, temp_settings, monkeypatch):
        import pymysql

        # The NPM app and the seeder both start on `up`: the first attempt
        # can hit proxy_host mid-migration (missing column) and must retry
        # until the app's migrations finish, not skip.
        monkeypatch.setattr(seed, "_wait_for_mysql", lambda timeout: True)
        monkeypatch.setattr(seed, "MYSQL_POLL_SECONDS", 0.1)

        calls = {"n": 0}

        class _MigratingCursor:
            def __init__(self):
                self.lastrowid = None
                self._row = None

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def fetchone(self):
                return self._row

            def execute(self, sql, *args):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise pymysql.err.ProgrammingError(
                        1054, "Unknown column 'forward_scheme' in 'field list'"
                    )
                if "INSERT" in str(sql).upper():
                    self.lastrowid = 20
                # _ensure_npm_defaults' SELECTs (user/certificate) fetch a row
                if "SELECT" in str(sql).upper():
                    self._row = {"id": 3}

            def fetchall(self):
                return []

        class _MigratingConn:
            def cursor(self):
                return _MigratingCursor()

            def commit(self):
                pass

            def close(self):
                pass

        monkeypatch.setattr(seed, "_mysql_connect", lambda: _MigratingConn())

        links = seed.ensure_proxy_hosts()
        assert calls["n"] > 1  # the first attempt failed and was retried
        assert links == {
            "vault.hylla.us": 20,
            "none.hylla.us": 20,
            "plex.hylla.us": 20,
            "ha.hylla.us": 20,
            "portainer.hylla.us": 20,
            "jelly.hylla.us": 20,
        }


class TestCursorLifecycle:
    """The "Cursor closed" regression.

    ``_ensure_npm_defaults`` hands out a cursor per ``with`` block. pymysql
    closes the cursor at the end of each block and raises "Cursor closed" if a
    statement runs afterwards. In the buggy revision the owner ``INSERT INTO
    user`` ran *after* the ``SELECT user`` block had closed its cursor — so a
    pristine dev NPM (``user`` table empty, the stock sandbox's exact state)
    failed the moment the INSERT fired, the retry loop saw a non-schema error
    and gave up, and the seeder linked **zero** proxy_host rows.
    """

    def test_defaults_no_cursor_use_after_close(self, temp_settings, monkeypatch):
        monkeypatch.setenv("NPM_DEFAULT_PASSWORD", "dev-healer")
        # A pristine sandbox: no wizard user, no built-in certificate row.
        conn = _ClosingConn([("SELECT id FROM user", []), ("SELECT id FROM certificate", None)])
        owner_id, access_id, cert_id = seed._ensure_npm_defaults(conn)
        assert owner_id is not None  # the seeded owner row was created
        assert access_id is not None  # the dev allowlist was created
        assert cert_id == 1  # no built-in cert, so a new one was created

    def test_full_seed_with_closed_cursor_links_all(self, temp_settings, monkeypatch):
        """End-to-end: with a faithful cursor that closes per block and an
        empty ``user`` table, the whole seeding pass still succeeds and links
        every host — it never trips on the closed-cursor error. (A regression
        here is exactly the bug that left the diagnostics page empty.)"""
        monkeypatch.setenv("NPM_DEFAULT_PASSWORD", "dev-healer")
        monkeypatch.setattr(seed, "_wait_for_mysql", lambda timeout: True)
        # No existing proxy_host rows; scripted INSERT ids come from lastrowid.
        conn = _ClosingConn([("SELECT id, domain_names FROM proxy_host", [])])
        monkeypatch.setattr(seed, "_mysql_connect", lambda: conn)

        links = seed.ensure_proxy_hosts()
        # Domain-less hosts (batcave/flash) get no NPM proxy row.
        assert set(links) == {
            d for d in (spec.get("domain") for spec in seed.SEED_HOSTS) if d
        }
        assert all(isinstance(v, int) for v in links.values())


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


class TestSchemaIntrospection:
    """Regression tests for the NOT-NULL auto-fill introspection.

    The dev NPM sandbox has never run the setup wizard, so the ``user`` table
    is empty and the seeder must create the owner row. But the seeder's INSERT
    only lists the columns it *knows* about — when a new NPM image release adds
    a NOT-NULL column with no default (``user.avatar``, ``proxy_host.
    advanced_config``/``meta`` on current images), the INSERT omits it and the
    whole pass fails with 1364 in strict mode. The fix introspects each table
    (``SHOW COLUMNS``) before INSERT and auto-fills any NOT-NULL-with-no-default
    column the INSERT does not already supply, using values from
    ``_KNOWN_COLUMNS_WITH_DEFAULTS`` (falling back to ``""`` for truly unknown
    columns). These tests lock that behaviour in so a future refactor that
    drops the introspection is caught.
    """

    def test_fills_for_returns_known_defaults_for_required_columns(
        self, temp_settings, monkeypatch
    ):
        """``_fills_for`` introspects the table and returns safe defaults for
        every NOT-NULL-with-no-default column not in ``known``."""
        import scripts.seed_dev as s

        user_cols = [
            {"Field": "id", "Type": "int", "Null": "NO", "Key": "PRI", "Default": None, "Extra": "auto_increment"},
            {"Field": "created_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "modified_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "is_deleted", "Type": "tinyint", "Null": "NO", "Key": "", "Default": "0", "Extra": ""},
            {"Field": "is_disabled", "Type": "tinyint", "Null": "NO", "Key": "", "Default": "0", "Extra": ""},
            {"Field": "email", "Type": "varchar(255)", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "name", "Type": "varchar(255)", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "nickname", "Type": "varchar(255)", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "avatar", "Type": "varchar(255)", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "roles", "Type": "longtext", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
        ]

        class _ColCursor:
            def __init__(self, cols):
                self._cols = cols
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, *a): pass
            def fetchall(self): return list(self._cols)

        class _ColConn:
            def __init__(self, cols): self._cols = cols
            def cursor(self): return _ColCursor(self._cols)
            def commit(self): pass
            def close(self): pass

        conn = _ColConn(user_cols)
        known = {"created_on", "modified_on", "is_deleted", "is_disabled", "email", "name", "nickname", "roles"}
        fills = s._fills_for(conn, "user", known)
        assert fills == {"avatar": ""}

    def test_fills_for_falls_back_to_empty_string_for_unknown_required_column(
        self, temp_settings, monkeypatch
    ):
        """A NOT-NULL-with-no-default column not in ``_KNOWN_COLUMNS_WITH_
        DEFAULTS`` gets ``""`` — safe enough for a dev seed."""
        import scripts.seed_dev as s

        class _ColCursor:
            def __init__(self, cols): self._cols = cols
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, *a): pass
            def fetchall(self): return list(self._cols)

        class _ColConn:
            def __init__(self, cols): self._cols = cols
            def cursor(self): return _ColCursor(self._cols)
            def commit(self): pass
            def close(self): pass

        cols = [
            {"Field": "created_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "modified_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "email", "Type": "varchar(255)", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "brand_new_col", "Type": "varchar(255)", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
        ]
        conn = _ColConn(cols)
        known = {"created_on", "modified_on", "email"}
        fills = s._fills_for(conn, "user", known)
        assert fills == {"brand_new_col": ""}

    def test_fills_for_returns_empty_when_table_not_migrated(self, temp_settings, monkeypatch):
        """If the table does not exist yet (mid-migration), ``SHOW COLUMNS``
        fails; ``_fills_for`` must return an empty dict, not raise."""
        import scripts.seed_dev as s

        class _ErrCursor:
            def __init__(self): self.lastrowid = None
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, *a):
                raise Exception("Table 'proxy_manager.proxy_host' doesn't exist")
            def fetchall(self): return []

        class _ErrConn:
            def cursor(self): return _ErrCursor()
            def commit(self): pass
            def close(self): pass

        conn = _ErrConn()
        fills = s._fills_for(conn, "proxy_host", {"domain_names"})
        assert fills == {}

    def test_inspect_columns_returns_empty_on_error(self, temp_settings, monkeypatch):
        """``_inspect_columns`` never raises; a missing table yields ``[]``."""
        import scripts.seed_dev as s

        class _ErrCursor:
            def __init__(self): self.lastrowid = None
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, *a):
                raise Exception("no such table")
            def fetchall(self): return []

        cur = _ErrCursor()
        assert s._inspect_columns(cur, "proxy_host") == []

    def test_inspect_columns_lowercases_field_names(self, temp_settings, monkeypatch):
        """``_inspect_columns`` folds column names to lower-case so callers
        can use a lower-case default table without per-release guessing."""
        import scripts.seed_dev as s

        class _Cur:
            def __init__(self): self.lastrowid = None
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, *a): pass
            def fetchall(self):
                return [
                    {"Field": "AdvancedConfig", "Type": "text", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
                    {"Field": "Meta", "Type": "longtext", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
                ]

        cur = _Cur()
        cols = s._inspect_columns(cur, "proxy_host")
        assert [c["Field"] for c in cols] == ["advancedconfig", "meta"]

    def test_missing_default_columns_surfaces_unfilled_required_columns(
        self, temp_settings, monkeypatch
    ):
        """``_missing_default_columns`` returns a non-empty list when a NOT-NULL
        column has no default, is not in ``known``, and is not in
        ``_KNOWN_COLUMNS_WITH_DEFAULTS`` — the caller then fails the pass
        loudly rather than silently seeding 1364s."""
        import scripts.seed_dev as s

        cols = [
            {"Field": "created_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "modified_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "new_required", "Type": "varchar(255)", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
        ]
        known = {"created_on", "modified_on"}
        unfilled = s._missing_default_columns("proxy_host", cols, known)
        assert ("new_required", "??") in unfilled

    def test_missing_default_columns_empty_when_all_filled(self, temp_settings, monkeypatch):
        """When every NOT-NULL-no-default column is either in ``known`` or in
        ``_KNOWN_COLUMNS_WITH_DEFAULTS``, the result is empty (the pass
        proceeds)."""
        import scripts.seed_dev as s

        cols = [
            {"Field": "created_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "modified_on", "Type": "datetime", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "advanced_config", "Type": "text", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
            {"Field": "meta", "Type": "longtext", "Null": "NO", "Key": "", "Default": None, "Extra": ""},
        ]
        known = {"created_on", "modified_on"}
        assert s._missing_default_columns("proxy_host", cols, known) == []

    def test_fallback_certificate_uses_values_the_live_schema_accepts(
        self, temp_settings, monkeypatch
    ):
        """The seed creates a fallback certificate only when NPM's built-in
        id 0 is absent (a pristine sandbox's exact state). On the live schema
        ``domain_names`` is ``CHECK (json_valid(…))`` (so ``""`` → 4025),
        ``meta`` is ``CHECK (json_valid(…))``, and ``expires_on`` is
        ``datetime NOT NULL`` (so ``None`` → 1048 and ``""`` → 1292).
        Pin the values the seed actually binds so a future refactor that
        reverts any of them to ``None``/``""`` is caught by the test suite.

        Verified against the live dev DB (192.168.86.38:3306) on 2026-09-16:
        the INSERT succeeded and produced ``domain_names='[]'``,
        ``expires_on=2999-12-31 23:59:59``, ``meta='{}'``."""
        import json

        conn = _RecordingConn()
        monkeypatch.setenv("NPM_DEFAULT_PASSWORD", "dev-healer")
        # No built-in certificate row → the fallback INSERT fires.
        seed._ensure_npm_defaults(conn)

        # Find the certificate INSERT and verify the SQL structure.
        cert_insert = next(
            (sql, args)
            for sql, args in conn.statements
            if "insert into certificate" in sql.lower()
        )
        # The SQL must contain the far-future expires_on literal (NOT a
        # bound %s) and the domain_names/meta must be bound as valid JSON.
        assert "2999-12-31 23:59:59" in cert_insert[0]
        # The bound params (a flat or 1-tuple) must include the JSON values.
        flat = cert_insert[1]
        # Unwrap the 1-tuple if _RecordingCursor stored it as such.
        if len(flat) == 1 and isinstance(flat[0], tuple):
            flat = flat[0]
        assert json.loads(flat[2]) == []  # domain_names = "[]"
        assert flat[3] == "{}"  # meta = "{}"


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

class TestProxyHostDomainJson:
    """Regression: ``proxy_host.domain_names`` is ``longtext CHECK
    (json_valid(…))`` — it holds a JSON array, not a bare hostname. Seeding a
    plain string fails with 4025; the seeder must encode it, and existing-row
    matching must decode it (so a hand-created single-host row still matches).
    """

    def test_domain_helper_decodes_json_array_and_plain_string(self, temp_settings):
        assert seed._proxy_host_domain('"vault.hylla.us"') == "vault.hylla.us"
        assert seed._proxy_host_domain('["vault.hylla.us"]') == "vault.hylla.us"
        assert seed._proxy_host_domain('["a.com","b.com"]') == "a.com"
        assert seed._proxy_host_domain("[]") == ""
        assert seed._proxy_host_domain(None) == ""
        assert seed._proxy_host_domain("") == ""
        assert seed._proxy_host_domain("plain.host") == "plain.host"
        # a malformed value is returned as-is (caller treats it as not-found)
        assert seed._proxy_host_domain("[bad json") == "[bad json"

    def test_seed_inserts_json_array_not_bare_string(self, temp_settings, monkeypatch):
        """The INSERT for a new proxy_host must bind ``domain_names`` as a JSON
        array string (json_valid CHECK passes) — never a bare hostname (which
        would fail 4025). Verified structurally by reading the SQL text and the
        bound params together."""
        import json

        conn = _RecordingConn()
        monkeypatch.setenv("NPM_DEFAULT_PASSWORD", "dev-healer")
        seed._seed_proxy_host_once(conn)
        inserts = [
            (sql, args)
            for sql, args in conn.statements
            if "insert into proxy_host" in sql.lower()
        ]
        assert inserts, "expected the seed to INSERT proxy_host rows"
        for sql, args in inserts:
            # The SQL text shows the %s placeholder position.
            assert "%s" in sql
            # domain_names is the first bound value in the INSERT; it must be
            # a JSON array string (starts with '[').
            if args:
                first = args[0]
                if isinstance(first, str) and first.startswith("["):
                    parsed = json.loads(first)
                    assert isinstance(parsed, list) and len(parsed) == 1
