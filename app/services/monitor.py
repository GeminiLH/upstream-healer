"""
Main monitoring & recovery loop.
"""
import asyncio
import logging
from datetime import datetime, time, timedelta, timezone
import aiosqlite
from app.config import settings
from app.config import current_time
from app.services.scanner import check_host_reachable, find_ip_by_mac, normalize_mac
from app.services.npm import NPMClient
from app.services.notifications import send_event

logger = logging.getLogger("healer.monitor")


class Monitor:
    def __init__(self):
        self.running = False
        self._task = None
        self.npm = NPMClient()

    async def start(self):
        if self.running:
            return
        self.running = True
        self._task = asyncio.create_task(self._loop())
        logger.info("Monitor started")

    async def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Monitor stopped")

    async def _loop(self):
        while self.running:
            check_interval_seconds = settings.check_interval_seconds
            try:
                async with aiosqlite.connect(settings.db_path) as db:
                    db.row_factory = aiosqlite.Row
                    async with db.execute(
                        "SELECT value FROM settings WHERE key = 'check_interval_seconds'"
                    ) as cursor:
                        setting = await cursor.fetchone()
                    if setting:
                        check_interval_seconds = max(1, int(setting["value"]))
                    await self._check_all_hosts(db)
            except Exception as e:
                logger.exception(f"Monitor loop error: {e}")
            await asyncio.sleep(check_interval_seconds)

    async def _check_all_hosts(self, db: aiosqlite.Connection):
        async with db.execute(
            "SELECT h.*, s.status, s.unreachable_since, s.last_ip, s.quiet_active, s.quiet_mode "
            "FROM hosts h LEFT JOIN host_state s ON s.host_id = h.id "
            "WHERE h.enabled = 1"
        ) as cursor:
            hosts = await cursor.fetchall()

        for host in hosts:
            await self._process_host(db, host)

    async def _process_host(self, db: aiosqlite.Connection, host):
        host_id = host["id"]
        name = host["name"]
        current_ip = host["current_ip"] or host["last_ip"]
        mac = host["mac_address"]
        port = host["port"] or 80
        grace_minutes = host["grace_minutes"] or settings.default_grace_minutes
        status = host["status"] or "unknown"
        unreachable_since = host["unreachable_since"]
        quiet_active, quiet_mode = self._quiet_state(host)

        now = current_time().isoformat()

        # Ensure state row exists before recording quiet-time transitions.
        await db.execute(
            "INSERT OR IGNORE INTO host_state (host_id, status) VALUES (?, 'unknown')",
            (host_id,),
        )
        await db.commit()

        previous_quiet_active = bool(host["quiet_active"] or 0)
        previous_quiet_mode = host["quiet_mode"]
        if quiet_active != previous_quiet_active or (quiet_active and quiet_mode != previous_quiet_mode):
            transition = "started" if quiet_active else "ended"
            mode_label = quiet_mode if quiet_active else (previous_quiet_mode or quiet_mode)
            await send_event(
                db,
                "quiet_time",
                    f"⏱️ Quiet time {transition} for {name}: {'suppress notifications' if mode_label == 'suppress' else 'stop monitoring and delete checks'}.",
                host_id=host_id,
                notify=False,
            )
        await db.execute(
            "UPDATE host_state SET quiet_active = ?, quiet_mode = ? WHERE host_id = ?",
            (int(quiet_active), quiet_mode if quiet_active else None, host_id),
        )
        await db.commit()

        if quiet_active and quiet_mode == "delete":
            return

        if not current_ip:
            logger.warning(f"Host {name} has no current IP – skipping reachability check")
            return

        reachable = await check_host_reachable(current_ip, port=port)
        notifications_enabled = not (quiet_active and quiet_mode == "suppress")

        if reachable:
            # Healthy
            if status != "healthy":
                await send_event(
                    db,
                    "recovered",
                    f"✅ {name} is reachable again at {current_ip}",
                    host_id=host_id,
                    notify=notifications_enabled,
                )
            await db.execute(
                """UPDATE host_state SET
                    status = 'healthy',
                    last_seen_at = ?,
                    unreachable_since = NULL,
                    last_check_at = ?,
                    last_ip = ?
                    WHERE host_id = ?""",
                (now, now, current_ip, host_id),
            )
            # Also keep hosts.current_ip in sync
            await db.execute(
                "UPDATE hosts SET current_ip = ?, updated_at = ? WHERE id = ?",
                (current_ip, now, host_id),
            )
            await db.commit()
            return

        # Unreachable
        if status == "healthy" or status == "unknown":
            # Just went down – start grace period
            await db.execute(
                """UPDATE host_state SET
                    status = 'unreachable',
                    unreachable_since = ?,
                    last_check_at = ?
                    WHERE host_id = ?""",
                (now, now, host_id),
            )
            await db.commit()
            logger.info(f"{name} became unreachable – grace period {grace_minutes} min started")
            return

        if status == "unreachable":
            # Still in (or past) grace period
            if not unreachable_since:
                return

            down_since = datetime.fromisoformat(unreachable_since)
            if down_since.tzinfo is None:
                down_since = down_since.replace(tzinfo=timezone.utc)
            grace_end = down_since + timedelta(minutes=grace_minutes)

            if datetime.now(timezone.utc) < grace_end.astimezone(timezone.utc):
                # Still in grace – do nothing
                await db.execute(
                    "UPDATE host_state SET last_check_at = ? WHERE host_id = ?",
                    (now, host_id),
                )
                await db.commit()
                return

            # Grace period expired → start recovery
            await self._start_recovery(db, host, notify=notifications_enabled)

    async def _start_recovery(self, db: aiosqlite.Connection, host, notify: bool = True):
        host_id = host["id"]
        name = host["name"]
        mac = host["mac_address"]
        npm_id = host["npm_proxy_host_id"]
        port = host["port"] or 80

        await db.execute(
            "UPDATE host_state SET status = 'recovering', last_check_at = ? WHERE host_id = ?",
            (current_time().isoformat(), host_id),
        )
        await db.commit()

        await send_event(
            db,
            "unreachable",
            f"⚠️ {name} has been unreachable longer than the grace period. Starting recovery.",
            host_id=host_id,
            notify=notify,
        )

        await send_event(
            db,
            "scan_started",
            f"🔍 Scanning local network for {name} (MAC {mac})",
            host_id=host_id,
            notify=notify,
        )

        new_ip = await find_ip_by_mac(mac)

        if not new_ip:
            await send_event(
                db,
                "failed",
                f"❌ Could not find {name} on the network (MAC {mac}). Manual intervention needed.",
                host_id=host_id,
                notify=notify,
            )
            await db.execute(
                "UPDATE host_state SET status = 'unreachable' WHERE host_id = ?",
                (host_id,),
            )
            await db.commit()
            return

        await send_event(
            db,
            "ip_found",
            f"📍 Found {name} at new IP {new_ip}",
            host_id=host_id,
            notify=notify,
        )

        # Update NPM
        if npm_id:
            success = self.npm.update_forward_host(npm_id, new_ip)
            if success:
                reloaded = self.npm.reload_nginx()
                if reloaded:
                    await send_event(
                        db,
                        "updated",
                        f"🔄 Updated NPM proxy host #{npm_id} to {new_ip} and reloaded nginx",
                        host_id=host_id,
                        notify=notify,
                    )
                else:
                    await send_event(
                        db,
                        "failed",
                        f"Updated IP in DB but nginx reload failed for {name}",
                        host_id=host_id,
                        notify=notify,
                    )
            else:
                await send_event(
                    db,
                    "failed",
                    f"Failed to update NPM database for {name}",
                    host_id=host_id,
                    notify=notify,
                )
        else:
            await send_event(
                db,
                "failed",
                f"No NPM proxy host ID configured for {name}",
                host_id=host_id,
                notify=notify,
            )

        # Update our records
        now = current_time().isoformat()
        await db.execute(
            "UPDATE hosts SET current_ip = ?, updated_at = ? WHERE id = ?",
            (new_ip, now, host_id),
        )
        await db.execute(
            """UPDATE host_state SET
                status = 'healthy',
                last_seen_at = ?,
                unreachable_since = NULL,
                last_check_at = ?,
                last_ip = ?
             WHERE host_id = ?""",
            (now, now, new_ip, host_id),
        )
        await db.commit()

        # Final reachability check
        await asyncio.sleep(2)
        if await check_host_reachable(new_ip, port=port):
            await send_event(
                db,
                "recovered",
                f"✅ {name} recovered successfully at {new_ip}",
                host_id=host_id,
                notify=notify,
            )
        else:
            await send_event(
                db,
                "failed",
                f"⚠️ Updated to {new_ip} but host still not responding on port 80",
                host_id=host_id,
                notify=notify,
            )

    @staticmethod
    def _quiet_state(host):
        if not host["quiet_enabled"] or not host["quiet_start"] or not host["quiet_end"]:
            return False, host["quiet_mode"] or "suppress"

        start = time.fromisoformat(host["quiet_start"])
        end = time.fromisoformat(host["quiet_end"])
        current = current_time().time().replace(tzinfo=None)
        if start == end:
            return False, host["quiet_mode"] or "suppress"
        if start < end:
            active = start <= current < end
        else:
            active = current >= start or current < end
        return active, host["quiet_mode"] or "suppress"


# Global instance
monitor = Monitor()
