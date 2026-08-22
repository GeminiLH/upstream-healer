"""
Notification system – Telegram + Email with per-event toggles.
"""
import json
import logging
import aiosmtplib
from email.message import EmailMessage
from typing import List, Optional
import httpx
import aiosqlite
from app.config import settings

logger = logging.getLogger("healer.notifications")

EVENT_TYPES = [
    "unreachable",
    "scan_started",
    "ip_found",
    "updated",
    "recovered",
    "failed",
    "manual",
]


async def send_event(db: aiosqlite.Connection, event_type: str, message: str, details: str = "", host_id: int = None):
    """Log the event and send to all enabled channels that have this event enabled."""
    # Log to events table
    await db.execute(
        "INSERT INTO events (host_id, event_type, message, details) VALUES (?, ?, ?, ?)",
        (host_id, event_type, message, details),
    )
    await db.commit()

    # Find matching channels
    query = """
        SELECT c.type, c.name, c.config, c.enabled
        FROM notification_channels c
        JOIN notification_rules r ON r.channel_id = c.id
        WHERE r.event_type = ? AND r.enabled = 1 AND c.enabled = 1
    """
    async with db.execute(query, (event_type,)) as cursor:
        channels = await cursor.fetchall()

    for ch in channels:
        try:
            config = json.loads(ch["config"])
            if ch["type"] == "telegram":
                await _send_telegram(config, message, details)
            elif ch["type"] == "email":
                await _send_email(config, message, details)
        except Exception as e:
            logger.error(f"Failed to send {ch['type']} notification: {e}")


async def _send_telegram(config: dict, message: str, details: str = ""):
    token = config.get("bot_token")
    chat_ids = config.get("chat_ids", [])
    if not token or not chat_ids:
        logger.warning("Telegram not configured properly")
        return

    text = f"🔔 *Upstream Healer*\n\n{message}"
    if details:
        text += f"\n\n`{details}`"

    async with httpx.AsyncClient(timeout=15) as client:
        for chat_id in chat_ids:
            try:
                resp = await client.post(
                    f"https://api.telegram.org/bot{token}/sendMessage",
                    json={
                        "chat_id": chat_id,
                        "text": text,
                        "parse_mode": "Markdown",
                        "disable_web_page_preview": True,
                    },
                )
                if resp.status_code != 200:
                    logger.error(f"Telegram error for {chat_id}: {resp.text}")
            except Exception as e:
                logger.error(f"Telegram send failed: {e}")


async def _send_email(config: dict, message: str, details: str = ""):
    """
    config example:
    {
        "smtp_host": "smtp.dynu.com",
        "smtp_port": 587,
        "username": "user@domain.com",
        "password": "...",
        "from_addr": "healer@domain.com",
        "to_addrs": ["person1@...", "person2@..."]
    }
    """
    host = config.get("smtp_host")
    port = int(config.get("smtp_port", 587))
    username = config.get("username")
    password = config.get("password")
    from_addr = config.get("from_addr") or username
    to_addrs = config.get("to_addrs", [])

    if not all([host, username, password, to_addrs]):
        logger.warning("Email not configured properly")
        return

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = f"[Upstream Healer] {message[:60]}"
    body = message
    if details:
        body += f"\n\nDetails:\n{details}"
    msg.set_content(body)

    try:
        await aiosmtplib.send(
            msg,
            hostname=host,
            port=port,
            username=username,
            password=password,
            start_tls=True,
        )
        logger.info(f"Email sent to {to_addrs}")
    except Exception as e:
        logger.error(f"Email send failed: {e}")
