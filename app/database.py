import aiosqlite
from pathlib import Path
from app.config import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    domain TEXT,
    mac_address TEXT NOT NULL UNIQUE,
    current_ip TEXT,
    npm_proxy_host_id INTEGER,
    grace_minutes INTEGER DEFAULT 10,
    enabled INTEGER DEFAULT 1,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
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
    created_at TEXT DEFAULT (datetime('now'))
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
    created_at TEXT DEFAULT (datetime('now')),
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


async def get_db():
    db = await aiosqlite.connect(settings.db_path)
    db.row_factory = aiosqlite.Row
    try:
        yield db
    finally:
        await db.close()
