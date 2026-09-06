"""RingWatch API routes."""

from __future__ import annotations

import asyncio
import time
import logging
from typing import Any

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
import json

from app.core.me_state import collect_me_state, state_to_dict, read_rapl_power, read_driver_memory
from app.core import timestorm, pmt_sensor
from app.core.heci_spy import full_probe
import subprocess, re

logger = logging.getLogger(__name__)



# Power history for charting
_power_history: list[dict] = []
_max_power_history = 500  # ~16 minutes at 2s intervals

def _record_power():
    """Record current power reading to history."""
    import time
    power = read_rapl_power()
    drv = read_driver_memory()
    entry = {
        "t": time.time(),
        "package_kj": power.get("package", {}).get("energy_kj", 0),
        "core_kj": power.get("core", {}).get("energy_kj", 0),
        "uncore_kj": power.get("uncore", {}).get("energy_kj", 0),
        "mei_me_kb": drv.get("mei_me", {}).get("size_kb", 0),
        "mei_core_kb": drv.get("mei_core", {}).get("size_kb", 0),
    }
    _power_history.append(entry)
    if len(_power_history) > _max_power_history:
        _power_history.pop(0)

router = APIRouter()

# Cache state
_last_state: dict[str, Any] = {}
_state_history: list[dict[str, Any]] = []
_max_history = 100


@router.get("/state")
async def get_state() -> dict[str, Any]:
    """Get current ME state snapshot."""
    state = await collect_me_state()
    result = state_to_dict(state)
    _last_state.clear()
    _last_state.update(result)
    _state_history.append({"timestamp": result["timestamp"], "dev_state": result["dev_state"], "fw_status": result["fw_status"]})
    if len(_state_history) > _max_history:
        _state_history.pop(0)
    return result


@router.get("/probe")
async def get_probe() -> dict[str, Any]:
    """Run full HECI probe (deeper than state snapshot)."""
    return full_probe()


@router.get("/history")
async def get_history() -> dict[str, Any]:
    """Get state history for timeline view."""
    return {"history": _state_history, "count": len(_state_history)}


@router.get("/stream")
async def stream_state():
    """Server-Sent Events stream — real-time ME state updates every 2 seconds."""
    async def event_stream():
        while True:
            state = await collect_me_state()
            data = state_to_dict(state)
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(2)
    
    return StreamingResponse(event_stream(), media_type="text/event-stream")


@router.get("/power")
async def get_power() -> dict[str, Any]:
    """Get current power consumption and history for charting."""
    power = read_rapl_power()
    drv = read_driver_memory()
    # Record to history
    import time
    entry = {
        "t": time.time(),
        "package_kj": power.get("package", {}).get("energy_kj", 0),
        "core_kj": power.get("core", {}).get("energy_kj", 0),
        "uncore_kj": power.get("uncore", {}).get("energy_kj", 0),
        "mei_me_kb": drv.get("mei_me", {}).get("size_kb", 0),
        "mei_core_kb": drv.get("mei_core", {}).get("size_kb", 0),
    }
    _power_history.append(entry)
    if len(_power_history) > _max_power_history:
        _power_history.pop(0)
    
    return {
        "current": {
            "package": power.get("package", {}),
            "core": power.get("core", {}),
            "uncore": power.get("uncore", {}),
            "me_power_estimate": power.get("me_power_estimate", "100-200mW"),
            "me_power_source": power.get("me_power_source", "3.3VSB"),
        },
        "driver_memory": drv,
        "history": _power_history[-200:],  # Last 200 readings
    }


# ── USB WiFi adapter live stats ──────────────────────────────────────
_USB_IFACE = os.environ.get("RINGWATCH_IFACE", "wlan0")


def _collect_usb_stats() -> dict[str, Any]:
    """Collect live statistics for the USB WiFi adapter."""
    stats: dict[str, Any] = {"interface": _USB_IFACE, "lines": []}
    try:
        # ip -s link show
        out = subprocess.run(
            ["ip", "-s", "link", "show", _USB_IFACE],
            capture_output=True, text=True, timeout=3,
        ).stdout
        stats["lines"].append({"label": "ip -s link", "output": out.strip()})
    except Exception:
        pass

    try:
        # RX/TX byte counters from /sys/class/net
        base = f"/sys/class/net/{_USB_IFACE}/statistics"
        rx_bytes = open(f"{base}/rx_bytes").read().strip()
        tx_bytes = open(f"{base}/tx_bytes").read().strip()
        rx_pkts = open(f"{base}/rx_packets").read().strip()
        tx_pkts = open(f"{base}/tx_packets").read().strip()
        rx_errs = open(f"{base}/rx_errors").read().strip()
        tx_errs = open(f"{base}/tx_errors").read().strip()
        rx_drop = open(f"{base}/rx_dropped").read().strip()
        tx_drop = open(f"{base}/tx_dropped").read().strip()
        stats["counters"] = {
            "rx_bytes": int(rx_bytes), "tx_bytes": int(tx_bytes),
            "rx_packets": int(rx_pkts), "tx_packets": int(tx_pkts),
            "rx_errors": int(rx_errs), "tx_errors": int(tx_errs),
            "rx_dropped": int(rx_drop), "tx_dropped": int(tx_drop),
        }
    except Exception:
        stats["counters"] = None

    try:
        # iw dev wlanX link (signal, rate, tx power)
        out = subprocess.run(
            ["iw", "dev", _USB_IFACE, "link"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        stats["lines"].append({"label": "iw dev link", "output": out.strip()})
        # Parse signal and bitrate
        for line in out.splitlines():
            ll = line.strip()
            if ll.startswith("signal:"):
                stats["signal_dbm"] = ll.split(":")[1].strip().split()[0]
            if ll.startswith("tx bitrate:"):
                stats["tx_bitrate"] = ll.split(":")[1].strip()
            if ll.startswith("rx bitrate:"):
                stats["rx_bitrate"] = ll.split(":")[1].strip()
    except Exception:
        pass

    try:
        # iw dev wlanX station dump for detailed stats
        out = subprocess.run(
            ["iw", "dev", _USB_IFACE, "station", "dump"],
            capture_output=True, text=True, timeout=3,
        ).stdout
        stats["lines"].append({"label": "station dump", "output": out.strip()[:2000]})
    except Exception:
        pass

    try:
        # ethtool -i for driver info
        out = subprocess.run(
            ["ethtool", "-i", _USB_IFACE],
            capture_output=True, text=True, timeout=3,
        ).stdout
        stats["lines"].append({"label": "ethtool -i", "output": out.strip()})
    except Exception:
        pass

    # Internal WiFi state (for contrast — should be DOWN)
    try:
        wlo_carrier = open(f"/sys/class/net/{os.environ.get('RINGWATCH_IF_INTERNAL', 'wlo1')}/carrier").read().strip()
    except Exception:
        wlo_carrier = "0"
    stats["internal_wifi"] = {
        "interface": os.environ.get("RINGWATCH_IF_INTERNAL", "wlo1"),
        "carrier": wlo_carrier,
        "status": "DOWN (NC-SI isolated)" if wlo_carrier == "0" else "UP ⚠️",
    }

    return stats


@router.get("/usb-stats")
async def get_usb_stats() -> dict[str, Any]:
    """Live USB WiFi adapter statistics — the adapter ME can't reach via NC-SI."""
    return _collect_usb_stats()


@router.get("/usb-stream")
async def usb_stream():
    """SSE stream — live USB WiFi stats every 2 seconds."""
    async def event_stream():
        while True:
            data = _collect_usb_stats()
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Timestorm (metadata-storm / timestomp detection) ──────────────
@router.get("/timestorm/status")
async def timestorm_status() -> dict[str, Any]:
    return timestorm.status()

@router.get("/timestorm/alerts")
async def timestorm_alerts() -> list[dict[str, Any]]:
    return timestorm.alerts()

# ── PMT sensor (ME/PMC telemetry observation) ─────────────────────
@router.get("/pmt/status")
async def pmt_status() -> dict[str, Any]:
    return pmt_sensor.status()

@router.get("/pmt/events")
async def pmt_events() -> list[dict[str, Any]]:
    return pmt_sensor.events()

@router.get("/pmt/history")
async def pmt_history() -> list[dict[str, Any]]:
    return pmt_sensor.history()
