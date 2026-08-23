import aiosqlite
from pathlib import Path
from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    local_device_name TEXT,
    domain TEXT,
    mac_address TEXT NOT NULL,
    current_ip TEXT,
    npm_proxy_host_id INTEGER,
    port INTEGER NOT NULL DEFAULT 80,
    grace_minutes INTEGER DEFAULT 10,
    enabled INTEGER DEFAULT 1,
    notes TEXT,
    created_at TEXT,
    updated_at TEXT,
    UNIQUE (mac_address, port)
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS notification_channels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL,               -- telegram / email
    name TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    config TEXT NOT NULL,             -- JSON
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS notification_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,         -- unreachable, scan_started, ip_found, updated, recovered, failed
    channel_id INTEGER NOT NULL,
    enabled INTEGER DEFAULT 1,
    FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    event_type TEXT NOT NULL,
    message TEXT,
    details TEXT,
    created_at TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS host_state (
    host_id INTEGER PRIMARY KEY,
    status TEXT DEFAULT 'unknown',   -- healthy, unreachable, recovering, maintenance
    last_seen_at TEXT,
    unreachable_since TEXT,
    last_check_at TEXT,
    last_ip TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
"""

DEFAULT_SETTINGS = {
    "grace_minutes": "10",
    "check_interval_seconds": "600",
    "telegram_enabled": "1",
    "email_enabled": "1",
}


async def init_db():
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(settings.db_path) as db:
        await db.executescript(SCHEMA)
        async with db.execute("PRAGMA table_info(hosts)") as cursor:
            host_columns = {row[1] for row in await cursor.fetchall()}
        if "port" not in host_columns:
            await db.execute("ALTER TABLE hosts ADD COLUMN port INTEGER NOT NULL DEFAULT 80")
        await _migrate_host_identity(db)
        # Seed default settings if empty
        async with db.execute("SELECT COUNT(*) FROM settings") as cursor:
            count = (await cursor.fetchone())[0]
        if count == 0:
            for k, v in DEFAULT_SETTINGS.items():
                await db.execute(
                    "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
                    (k, v),
                )
        await db.commit()


async def _migrate_host_identity(db: aiosqlite.Connection):
    """Replace the legacy MAC-only uniqueness constraint with MAC plus port."""
    async with db.execute("PRAGMA index_list(hosts)") as cursor:
        indexes = await cursor.fetchall()

    for index in indexes:
        if not index[2]:
            continue
        async with db.execute(f'PRAGMA index_info("{index[1]}")') as cursor:
            columns = [row[2] for row in await cursor.fetchall()]
        if columns != ["mac_address"]:
            continue

        await db.commit()
        await db.execute("PRAGMA foreign_keys = OFF")
        await db.execute("""CREATE TABLE hosts_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            domain TEXT,
            mac_address TEXT NOT NULL,
            current_ip TEXT,
            npm_proxy_host_id INTEGER,
            port INTEGER NOT NULL DEFAULT 80,
            grace_minutes INTEGER DEFAULT 10,
            enabled INTEGER DEFAULT 1,
            notes TEXT,
            created_at TEXT,
            updated_at TEXT,
            UNIQUE (mac_address, port)
        )""")
        await db.execute("""INSERT INTO hosts_new
            (id, name, domain, mac_address, current_ip, npm_proxy_host_id, port,
             grace_minutes, enabled, notes, created_at, updated_at)
            SELECT id, name, domain, mac_address, current_ip, npm_proxy_host_id, port,
                   grace_minutes, enabled, notes, created_at, updated_at
            FROM hosts""")
        await db.execute("DROP TABLE hosts")
        await db.execute("ALTER TABLE hosts_new RENAME TO hosts")
        await db.execute("PRAGMA foreign_keys = ON")
        return


async def get_db():
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()
