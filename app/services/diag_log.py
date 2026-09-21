"""Opt-in, file-based debug logging for diagnostic scans.

Why this exists
--------------
A scan that "finds nothing" is not debuggable from the UI: the raw output
shows *what* the tools said, not *what was actually sent* (which egress
interface, which CIDR, which exception scapy swallowed, whether the target
is the scanning machine itself).  This module appends those details to one
log file per scan so a misbehaving sweep can be read afterwards.

Configuration (environment)
---------------------------
``UPSTREAM_HEALER_DEBUG_LOG_DIR``
    Absolute directory for the log files.  **Unset/empty -> logging is fully
    disabled** (every helper below is a no-op).  The dev stack
    (``docker-compose.dev.yml``) sets it to ``/logs`` and bind-mounts
    ``/mnt/data/upstream-healer/logs`` from the host there.  The base
    ``docker-compose.yml`` (test/production) sets nothing, so production
    runs stay completely silent unless someone deliberately adds both the
    variable and a mount.
``UPSTREAM_HEALER_ENV``
    Optional tripwire: when it is ``production``/``prod`` the directory is
    ignored even if set, so a stale env var on a prod box can never enable
    logging.
``UPSTREAM_HEALER_DEBUG_MAX_BYTES`` (default 512 KiB) /
``UPSTREAM_HEALER_DEBUG_KEEP`` (default 20)
    Per-file cap and rotation window.

Safety properties (covered by ``tests/test_diag_log.py``)
---------------------------------------------------------
* Disabled by default and by the production tripwire.
* **Never raises**: a logging failure can never fail a scan.
* Bounded: per-file byte cap + oldest-first rotation, so the directory
  cannot grow without limit.
* Async-safe: the active scan is a ``contextvars`` token.  ``run_scan``
  dispatches each sweep with ``asyncio.to_thread``, which copies the running
  context and runs the target inside it (``contextvars.copy_context().run``),
  so worker threads write to the same per-scan file.

  Note the subtlety that motivated this design: a plain
  ``loop.run_in_executor(None, fn)`` does **not** propagate a ContextVar into
  the worker thread on Python 3.12 (the runtime of the dev image) — the context
  is only copied at task-creation boundaries, not at executor dispatch — so a
  scanner dispatched that way silently logs *nothing* (empty per-scan file),
  while the event-loop-side lines still land.  Python 3.13+ happens to also
  propagate into the executor, but ``asyncio.to_thread`` is the portable fix
  across 3.9-3.13.  **Never** dispatch a function that calls ``emit``/``proc``/
  ``exc`` via a bare ``run_in_executor``; use ``to_thread`` (or wrap the body in
  ``ctx.run`` where ``ctx = copy_context()`` was captured on the loop).
"""
from __future__ import annotations

import contextlib
import contextvars
import os
import platform
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Iterator, Optional

_DEFAULT_MAX_BYTES = 512 * 1024
_DEFAULT_KEEP = 20

# The log for the scan currently running on this task/thread, or None.
_current: contextvars.ContextVar[Optional["ScanLog"]] = contextvars.ContextVar(
    "healer_diag_log", default=None
)
# Per-process sequence so two scans of the same target in the same second
# get distinct files (filenames carry second-resolution timestamps).
_SEQ = 0


def _sequence() -> int:
    global _SEQ
    _SEQ += 1
    return _SEQ


def log_dir() -> Optional[str]:
    """Effective debug-log directory, or ``None`` when logging is disabled."""
    directory = os.environ.get("UPSTREAM_HEALER_DEBUG_LOG_DIR", "").strip()
    if not directory:
        return None
    env = os.environ.get("UPSTREAM_HEALER_ENV", "").strip().lower()
    if env in ("prod", "production"):
        return None
    return directory


def enabled() -> bool:
    return log_dir() is not None


def _max_bytes() -> int:
    try:
        return max(
            16 * 1024,
            int(os.environ.get("UPSTREAM_HEALER_DEBUG_MAX_BYTES", _DEFAULT_MAX_BYTES)),
        )
    except (TypeError, ValueError):
        return _DEFAULT_MAX_BYTES


def _keep() -> int:
    try:
        return max(1, int(os.environ.get("UPSTREAM_HEALER_DEBUG_KEEP", _DEFAULT_KEEP)))
    except (TypeError, ValueError):
        return _DEFAULT_KEEP


def _snap(value: Any, limit: int = 16_000) -> str:
    """Render one value as a size-capped, single-line-safe string.

    Newlines become `` \\ `` markers so a big raw output stays on one
    readable line; anything over ``limit`` chars is cut with a count.
    """
    try:
        text = str(value)
    except Exception:  # noqa: BLE001 - rendering must never raise
        return f"<unrenderable {type(value).__name__}>"
    text = text.replace("\r", " ").replace("\n", " \\ ")
    if len(text) > limit:
        text = text[:limit] + f" …[+{len(text) - limit} chars]"
    return text or "(empty)"


def _rotate(directory: Path) -> None:
    """Keep only the newest ``_keep()`` diag_*.log files (best-effort)."""
    try:
        files = sorted(directory.glob("diag_*.log"), key=lambda p: p.stat().st_mtime)
        for old in files[: max(0, len(files) - _keep())]:
            old.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001
        pass


def self_identity() -> dict:
    """Snapshot of *who is running the scan* (hostname, NICs, routes, neighbours).

    Written at the top of every scan log so a reader can tell whether the
    *target* is the scanning machine itself — a host does not answer its own
    ARP/ICMP broadcast sweeps, so "no match" for your own MAC is expected
    behaviour, not a bug.  Everything here is best-effort; a field that
    cannot be read comes back as ``None`` and never raises.
    """
    info: dict = {"hostname": None, "interfaces": {}, "routes": None, "neighbours": None}
    try:
        import socket

        info["hostname"] = socket.gethostname()
    except Exception:  # noqa: BLE001
        pass
    try:
        proc = subprocess.run(
            ["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5
        )
        for line in (proc.stdout or "").splitlines():
            m = re.match(r"^\d+:\s+(\S+?)(@|\:)", line)
            if not m:
                continue
            mac = re.search(r"link\/\w+\s+([0-9a-f:]{17})", line)
            info["interfaces"].setdefault(m.group(1), {"mac": None, "ipv4": []})[
                "mac"
            ] = mac.group(1).lower() if mac else None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    try:
        proc = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5
        )
        for line in (proc.stdout or "").splitlines():
            parts = line.split()
            if len(parts) >= 4:  # "2: enp6s0  inet 192.168.86.38/24 brd ..."
                info["interfaces"].setdefault(parts[1], {"mac": None, "ipv4": []})[
                    "ipv4"
                ].append(parts[3])
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    try:
        proc = subprocess.run(
            ["ip", "-4", "route", "show"], capture_output=True, text=True, timeout=5
        )
        info["routes"] = (proc.stdout or "").strip() or None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    try:
        proc = subprocess.run(
            ["ip", "-o", "-4", "neigh", "show"], capture_output=True, text=True, timeout=5
        )
        text = (proc.stdout or "").strip()
        info["neighbours"] = text[:8000] or None
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return info


class ScanLog:
    """One diagnostic scan's log file: line-buffered, capped, best-effort.

    Every method swallows all exceptions — this object must be able to
    disappear without disturbing the scan.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._closed = False
        self._bytes = 0
        self._max = _max_bytes()
        self._fh: Optional[Any] = None
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = path.open("x", encoding="utf-8")  # create-only: never overwrite
        except Exception:  # noqa: BLE001 - unreadable dir: become a pure no-op
            self._fh = None
            try:
                _rotate(path.parent)
            except Exception:  # noqa: BLE001
                pass

    def _write(self, text: str) -> None:
        if self._fh is None or self._closed:
            return
        try:
            if self._bytes + len(text) > self._max:
                self._fh.write("[log] size cap reached — further detail dropped\n")
                self._bytes = self._max
                return
            self._fh.write(text)
            self._fh.flush()
            self._bytes += len(text)
        except Exception:  # noqa: BLE001
            self._fh = None

    @staticmethod
    def _stamp() -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S")

    def emit(self, section: str, *args: Any) -> None:
        """Append one ``[time] section: value | value...`` line (values capped)."""
        if not args:
            self._write(f"[{self._stamp()}] {section}\n")
        else:
            self._write(
                f"[{self._stamp()}] {section}: " + " | ".join(_snap(a) for a in args) + "\n"
            )

    def proc(self, tool: str, cmd: list, proc: Any, extra: Any = None) -> None:
        """Log one completed tool run: command, rc, raw stdout/stderr."""
        self.emit(
            tool,
            "cmd=" + " ".join(str(c) for c in cmd),
            f"rc={getattr(proc, 'returncode', None)}",
            f"stdout= {getattr(proc, 'stdout', None)}",
            f"stderr= {getattr(proc, 'stderr', None)}",
            *([] if extra is None else [extra]),
        )

    def exc(self, section: str, exc: BaseException, *context: Any) -> None:
        """Log an exception with the tail of its traceback."""
        import traceback

        tail = "".join(traceback.format_exception(exc))[-2000:]
        self.emit(section, f"exception={exc!r}", "trace=" + tail.replace("\n", " \\ "), *context)

    def close(self, *summary: Any) -> None:
        """Write the summary, close the file, and rotate old logs."""
        if self._closed:
            return
        # NB: write the summary *before* flipping _closed — _write() refuses
        # to write to a closed log (and must keep doing that for stragglers).
        if summary:
            self.emit("== scan complete", *summary)
        self._closed = True
        if self._fh is not None:
            try:
                self._fh.close()
            except Exception:  # noqa: BLE001
                pass
            self._fh = None
        try:
            _rotate(self._path.parent)
        except Exception:  # noqa: BLE001
            pass


class _NullLog:
    """Drop-in replacement for :class:`ScanLog` when logging is disabled."""

    def emit(self, section: str, *args: Any) -> None:  # noqa: B027
        pass

    def proc(self, tool: str, cmd: list, proc: Any, extra: Any = None) -> None:  # noqa: B027
        pass

    def exc(self, section: str, exc: BaseException, *context: Any) -> None:  # noqa: B027
        pass

    def close(self, *summary: Any) -> None:  # noqa: B027
        pass


_NULL = _NullLog()


def _self_is_target(target_mac: str) -> bool:
    """True when ``target_mac`` matches any of this host's own interface MACs."""
    try:
        from app.services.scanner import normalize_mac

        target_mac = normalize_mac(target_mac)
    except Exception:  # noqa: BLE001
        return False
    for iface in self_identity()["interfaces"].values():
        if iface.get("mac") and iface["mac"] == target_mac:
            return True
    return False


@contextlib.contextmanager
def scan_context(
    *,
    target_mac: str,
    method: str,
    subnets: Optional[list[str]] = None,
) -> Iterator[Optional[ScanLog]]:
    """Open the per-scan log (when enabled) and register it for this task.

    Use as a context manager around a whole scan (see the
    ``/api/diagnostic/scan`` endpoint).  Yields ``None`` when logging is
    disabled — every scanner-facing helper (:func:`emit`, :func:`proc`,
    :func:`exc`) is a no-op then, so callers need no branching of their own.
    """
    if not enabled():
        yield None
        return
    from app.services.scanner import normalize_mac

    try:
        target = normalize_mac(target_mac or "")
    except Exception:  # noqa: BLE001
        target = (target_mac or "").strip() or "unknown"
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^a-z0-9:]", "_", target)
    log = ScanLog(
        Path(log_dir()) / f"diag_{stamp}_{(method or 'scan')[:16]}_{safe_target}_{_sequence()}.log"
    )
    _write_header(log, target, method, subnets)
    token = _current.set(log)
    try:
        yield log
    finally:
        try:
            log.close(f"finished={time.strftime('%Y-%m-%d %H:%M:%S')}")
        finally:
            _current.reset(token)


def _write_header(
    log: ScanLog,
    target: str,
    method: str,
    subnets: Optional[list[str]],
) -> None:
    identity = self_identity()
    log.emit(
        "== upstream-healer diagnostic scan log ==",
        f"started={time.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"python={platform.python_version()}",
        f"platform={platform.platform()}",
    )
    log.emit(
        "self",
        f"hostname={identity['hostname']}",
        "interfaces="
        + ", ".join(
            f"{name}(mac={v['mac']},ipv4={v['ipv4']})"
            for name, v in sorted(identity["interfaces"].items())
        )
        or "(none found)",
    )
    log.emit("self", "routes=" + (identity["routes"] or "(none)"))
    log.emit("self", "neighbours=" + (identity["neighbours"] or "(none)"))
    log.emit("scan", f"target_mac={target}", f"method={method}", f"subnets={subnets}")
    if _self_is_target(target):
        log.emit(
            "WARNING: TARGET IS THIS MACHINE ITSELF —",
            "a host does not answer its own ARP/ICMP broadcast sweeps, so a",
            "no-match result for its own MAC is EXPECTED.  Verify the sweeps",
            "actually went out the right interface below before treating",
            "the sweep itself as broken.",
        )
    else:
        log.emit("note", f"target {target} does not match any local interface MAC.")


# -- context propagation helper ---------------------------------------------


def copy_context() -> contextvars.Context:
    """Return a copy of the *running* context, for dispatching context-aware
    work onto a thread pool.

    ``asyncio.to_thread`` does exactly this internally, but a caller that drives
    ``loop.run_in_executor`` directly must wrap the target in
    ``copy_context().run(...)`` (or just switch to ``to_thread``) — otherwise the
    active-scan ``_current`` ContextVar is dropped in the worker thread and every
    ``emit``/``proc``/``exc`` silently no-ops.  See the module docstring.
    Example::

        ctx = copy_context()
        await loop.run_in_executor(None, lambda: ctx.run(worker_fn, *args))
    """
    return contextvars.copy_context()


# -- scanner-facing one-liners (safe no-ops outside a scan / when disabled) --


def emit(section: str, *args: Any) -> None:
    """Append a line to the active scan log (no-op when there is none)."""
    log = _current.get()
    (log if log is not None else _NULL).emit(section, *args)


def proc(tool: str, cmd: list, proc_obj: Any, extra: Any = None) -> None:
    """Log a completed tool run to the active scan log (no-op otherwise)."""
    log = _current.get()
    (log if log is not None else _NULL).proc(tool, cmd, proc_obj, extra)


def exc(section: str, exc_obj: BaseException, *context: Any) -> None:
    """Log an exception + traceback tail to the active scan log (no-op)."""
    log = _current.get()
    (log if log is not None else _NULL).exc(section, exc_obj, *context)


def close(*summary: Any) -> None:
    """Close the active scan log early (e.g. when a scan errors out)."""
    log = _current.get()
    if log is not None:
        log.close(*summary)
        _current.set(None)


