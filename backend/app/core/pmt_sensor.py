"""PMT Sensor — ME/PMC telemetry as a RingWatch observation module.

RingWatch's thesis, extended: don't just defend against Ring -3 — watch it.
The ME/PMC continuously samples platform rails and counters via PMT and
exposes them below the OS (dvsec telemetry). This module polls the named
decode (pmt-reader) and raises events on:

  * rail state transitions (dead rail ↔ live rail)
  * raw power jumps (V×I deltas above threshold)
  * VID changes (voltage ID moves = power state shifts)

Read-only: samples PMT regions, never writes.
Dan Vladoiu — Aug 31, 2026
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from typing import Any

logger = logging.getLogger("ringwatch.pmt_sensor")

PMT_READER = os.environ.get("RINGWATCH_PMT_READER", os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "pmt-reader.py"))
POLL_INTERVAL = 5.0
POWER_JUMP_FRAC = 0.50     # raw_power change that qualifies as an event
POWER_FLOOR = 3000           # below this raw_power = noise territory (idle rails flap)
POWER_JUMP_ABS = 2500         # absolute delta also required (kills low-value flapping)
RAIL_HISTORY = 240         # samples kept (240 × 5s = 20 min)
EVENT_HISTORY = 100

_pmt = None


def _load_pmt():
    global _pmt
    if _pmt is not None:
        return _pmt
    try:
        import importlib.util as ilu
        spec = ilu.spec_from_file_location("pmt_reader", PMT_READER)
        mod = ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _pmt = mod
        return _pmt
    except Exception as e:
        logger.warning("PMT sensor: cannot load pmt-reader: %s", e)
        return None


def _snapshot() -> dict[str, dict[str, Any]] | None:
    pmt = _load_pmt()
    if not pmt:
        return None
    try:
        regions = pmt.discover()
        rails: dict[str, dict[str, Any]] = {}
        for r in regions:
            guid = (r.get("guid") or "").lower()
            schema = pmt.load_schema(guid)
            if not schema or not r.get("data"):
                continue
            samples = pmt.decode_region(r["data"], schema)
            by_container: dict[str, list[tuple[str, int]]] = {}
            for s in samples:
                cont, _, nm = s["sample"].partition(".")
                by_container.setdefault(cont, []).append((nm, s["value"]))
            if guid != "0x1a067002":
                continue
            for cont in ("Container_1", "Container_2", "Container_3", "Container_5"):
                items = by_container.get(cont, [])
                pair_idx = 0
                i = 0
                while i < len(items):
                    if items[i][0] == "VOLTAGE":
                        v = items[i][1]
                        cur = items[i + 1][1] if i + 1 < len(items) and items[i + 1][0] == "CURRENT" else 0
                        frq = items[i + 2][1] if i + 2 < len(items) and items[i + 2][0] == "FREQ" else 0
                        rails[f"{cont}.{chr(97 + pair_idx)}"] = {
                            "voltage": v, "current": cur, "freq": frq,
                            "raw_power": v * cur,
                        }
                        pair_idx += 1
                        i += 3
                    else:
                        i += 1
            c6 = dict(by_container.get("Container_6", []))
            if c6:
                rails["cpu.vid"] = {"vid": c6.get("VID", 0), "amps_max": c6.get("AMPS", 0)}
        return rails
    except Exception as e:
        logger.warning("PMT sensor snapshot failed: %s", e)
        return None


class PMTSensorState:
    def __init__(self) -> None:
        self.history: deque[dict[str, Any]] = deque(maxlen=RAIL_HISTORY)
        self.events: deque[dict[str, Any]] = deque(maxlen=EVENT_HISTORY)
        self.prev_rails: dict[str, dict[str, Any]] = {}
        self.task: asyncio.Task | None = None
        self.ok = False
        self.last_error: str | None = None
        self.last_emit: dict[tuple[str, str], float] = {}

EVENT_COOLDOWN = 60.0  # same (rail, event-type) fires max once per minute


STATE = PMTSensorState()


async def _poll_loop() -> None:
    while True:
        snap = await asyncio.get_running_loop().run_in_executor(None, _snapshot)
        if snap is None:
            STATE.ok = False
        else:
            STATE.ok = True
            STATE.last_error = None
            ts = time.time()
            STATE.history.append({"t": ts, "rails": snap})
            _detect(ts, snap)
        await asyncio.sleep(POLL_INTERVAL)


def _detect(ts: float, rails: dict[str, dict[str, Any]]) -> None:
    def emit(ev: dict[str, Any]) -> None:
        key = (ev.get("rail", "cpu"), ev.get("event", "?"))
        if ts - STATE.last_emit.get(key, 0.0) < EVENT_COOLDOWN:
            return  # cooldown — don't spam the same rail/event
        STATE.last_emit[key] = ts
        ev["t"] = ts
        STATE.events.append(ev)
        logger.info("PMT event: %s", ev)

    prev = STATE.prev_rails
    for name, cur in rails.items():
        p = prev.get(name)
        if p is None:
            continue
        # rail state transition
        was_alive = (p.get("voltage", 0) >= 50 or p.get("current", 0) >= 10)
        is_alive = (cur.get("voltage", 0) >= 50 or cur.get("current", 0) >= 10)
        if was_alive != is_alive and "cpu.vid" not in name:
            emit({"event": "rail_transition", "rail": name,
                  "from": "alive" if was_alive else "dead",
                  "to": "alive" if is_alive else "dead",
                  "voltage": cur.get("voltage"), "current": cur.get("current")})
        # power jump
        pp = p.get("raw_power", 0)
        cp = cur.get("raw_power", 0)
        if (pp >= POWER_FLOOR and abs(cp - pp) >= POWER_JUMP_ABS
                and abs(cp - pp) / pp > POWER_JUMP_FRAC and "cpu.vid" not in name):
            emit({"event": "power_jump", "rail": name,
                  "from": pp, "to": cp,
                  "delta_pct": round((cp - pp) / pp * 100, 1)})
        # VID change
        if "cpu.vid" in name and p.get("vid") != cur.get("vid"):
            emit({"event": "vid_change", "from": p.get("vid"), "to": cur.get("vid")})
    STATE.prev_rails = rails


def start() -> None:
    if STATE.task is None or STATE.task.done():
        STATE.task = asyncio.get_running_loop().create_task(_poll_loop())
        logger.info("PMT sensor polling every %ss", POLL_INTERVAL)


def status() -> dict[str, Any]:
    latest = STATE.history[-1] if STATE.history else None
    return {
        "module": "pmt_sensor",
        "ok": STATE.ok,
        "last_error": STATE.last_error,
        "poll_interval_s": POLL_INTERVAL,
        "samples": len(STATE.history),
        "events": len(STATE.events),
        "rails_latest": latest["rails"] if latest else {},
        "rails_ts": latest["t"] if latest else None,
    }


def events() -> list[dict[str, Any]]:
    return list(STATE.events)


def history() -> list[dict[str, Any]]:
    return list(STATE.history)