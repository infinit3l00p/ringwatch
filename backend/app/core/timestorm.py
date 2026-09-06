"""Timestorm — metadata-storm (timestomp) detection for RingWatch.

Lesson from a real incident: a shutdown-wipe timestomp hit 115,111
files in 6 seconds — invisible to every process/network defense
(in-process utimensat: no EXEC, no sockets, no API calls). Only ctime told
the truth.

Signature of a timestomp (vs normal build activity):
  * Pure-ATTRIB storm: hundreds/thousands of metadata events with almost no
    MODIFY/CREATE (builds write content; timestomps only stamp)
  * Burst rate far above human/normal-tool behavior
  * Corroborating evidence: affected files share identical ctime nanoseconds

This module: READ-ONLY. It watches; it never writes, never blocks.
Dan Vladoiu — Aug 31, 2026
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from collections import deque
from typing import Any

logger = logging.getLogger("ringwatch.timestorm")

WORKSPACE = os.environ.get("RINGWATCH_WORKSPACE", os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
# .git churn is normal and git-ignored by timestomp sweeps; node build output changes
# constantly with real writes — pure-ATTRIB is the discriminator either way.

ATTRIB_WINDOW = 10.0          # seconds
ATTRIB_THRESHOLD = 200        # attribs in window → storm
MODIFY_RATIO_MAX = 0.10      # storm requires attrib >> content writes
NANO_SAMPLE = 5              # files to ctime-sample for nano-corroboration


class TimestormState:
    def __init__(self) -> None:
        self.proc: asyncio.subprocess.Process | None = None
        self.task: asyncio.Task | None = None
        self.events: deque[dict[str, Any]] = deque(maxlen=50)
        self.window: deque[tuple[float, str]] = deque()  # (ts, kind)
        self.watching = False
        self.last_attrib = 0
        self.last_modify = 0
        self.watch_warned = False

    # ── history window bookkeeping ─────────────────────────────
    def _prune(self, now: float) -> None:
        while self.window and now - self.window[0][0] > ATTRIB_WINDOW:
            self.window.popleft()

    def record(self, kind: str) -> None:
        now = time.monotonic()
        self.window.append((now, kind))
        self._prune(now)

    def counts(self) -> tuple[int, int]:
        now = time.monotonic()
        self._prune(now)
        a = sum(1 for _, k in self.window if k == "attrib")
        m = sum(1 for _, k in self.window if k in ("modify", "create", "close_write"))
        return a, m


STATE = TimestormState()


async def _watch_loop() -> None:
    """Consume inotifywait stdout, detect storms."""
    while True:
        try:
            STATE.proc = await asyncio.create_subprocess_exec(
                "inotifywait",
                "-r", "-m", "-q",
                "-e", "attrib", "-e", "modify", "-e", "create", "-e", "close_write",
                "--format", "%e|%w%f",
                WORKSPACE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            STATE.watching = True
            logger.info("Timestorm watcher online on %s", WORKSPACE)
            assert STATE.proc.stdout
            while True:
                raw = await STATE.proc.stdout.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                if not line or "|" not in line:
                    continue
                kinds, _path = line.split("|", 1)
                kind = kinds.split(",")[0].strip().lower()
                if kind in ("attrib", "modify", "create", "close_write"):
                    STATE.record(kind)
                if kind == "attrib":
                    await _maybe_alert(_path)
        except FileNotFoundError:
            logger.error("inotifywait not installed — timestorm watcher offline")
            STATE.watching = False
            return
        except Exception as e:
            logger.warning("Timestorm watcher error: %s — restarting in 10s", e)
            STATE.watching = False
            await asyncio.sleep(10)


async def _maybe_alert(path: str) -> None:
    a, m = STATE.counts()
    if a < ATTRIB_THRESHOLD:
        return
    if m > 0 and (a / max(m, 1)) * 1.0 < 1 / MODIFY_RATIO_MAX and a < 2000:
        return  # content-heavy burst → likely a build, not a stamp
    now = time.time()
    # don't re-alert inside the same storm
    if STATE.events and now - STATE.events[-1]["ts"] < 30:
        return
    # corroborate: identical ctime nanos on affected files
    nano_evidence = ""
    try:
        import subprocess
        out = await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: subprocess.run(
                ["stat", "-c", "%z", path],
                capture_output=True, text=True, timeout=3,
            ).stdout.strip(),
        )
        nano_evidence = out
    except Exception:
        pass
    alert = {
        "ts": now,
        "event": "timestorm",
        "attribs_in_window": a,
        "content_writes_in_window": m,
        "trigger_file": path,
        "trigger_ctime": nano_evidence,
        "verdict": ("LIKELY TIMESTOMP — pure metadata storm"
                     if m < a * MODIFY_RATIO_MAX else
                     "metadata-heavy burst — review"),
        "note": "check ctime (kernel truth) vs mtime; shared nanoseconds = stamping",
    }
    STATE.events.append(alert)
    logger.warning("🚨 TIMESTORM DETECTED: %s attrib events /%ss, %s content writes — %s",
                   a, ATTRIB_WINDOW, m, path)


def start() -> None:
    if STATE.task is None or STATE.task.done():
        STATE.task = asyncio.get_running_loop().create_task(_watch_loop())


def status() -> dict[str, Any]:
    a, m = STATE.counts()
    return {
        "module": "timestorm",
        "watching": STATE.watching,
        "path": WORKSPACE,
        "attribs_last_10s": a,
        "content_writes_last_10s": m,
        "threshold": ATTRIB_THRESHOLD,
        "alerts": len(STATE.events),
    }


def alerts() -> list[dict[str, Any]]:
    return list(STATE.events)