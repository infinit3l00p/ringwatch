"""ME state collector — reads sysfs attributes from Intel ME."""

from __future__ import annotations

import os
import time
import asyncio
from typing import Any
from dataclasses import dataclass, field
import logging

from app.core.config import MEI_SYSFS, MEI_BUS

logger = logging.getLogger(__name__)

# Known MEI client UUIDs (from kernel source + our research)
KNOWN_CLIENTS = {
    "55213584-9a29-4916-badf-0fb7ed682aeb": ("MKHIF_FIX", "OS version telemetry — POISON TARGET"),
    "8c2f4425-77d6-4755-aca3-891fdbc66a58": ("AMT", "Active Management Technology — POISON TARGET"),
    "8e6a6715-9abc-4043-88ef-9e39c6f63e0f": ("PTT", "Platform Trust Technology / fTPM — DO NOT TOUCH"),
    "05b79a6f-4628-4d7f-899d-a91514cb32ab": ("WD", "Watchdog Timer"),
    "0f73db04-97ab-4125-b893-e904ad0d5464": ("GSC_PROXY", "Graphics Security Command Proxy"),
    "309dcde8-ccb1-4062-8f78-600115a34327": ("SPI_PROXY", "SPI Flash Proxy (ME read/write to SPI)"),
    "42b3ce2f-bd9f-485a-96ae-26406230b1ff": ("BIOS_INTEG", "BIOS Integration (power/thermal/boot state)"),
    "082ee5a7-7c25-470a-9643-0c06f0466ea1": ("EXT_BOOT", "Extended Boot/Recovery (bulk transfer)"),
    "6861ec7b-d07a-4673-856c-7f22b4d55769": ("HMRFPO", "Host Management Fixed (ME-BIOS sync)"),
    "dd17041c-09ea-4b17-a271-5b989867ec65": ("NFTP_UPDATE", "Firmware Update (NFTP protocol)"),
}


@dataclass
class MEState:
    """Current state of the Intel Management Engine."""
    timestamp: float = 0.0
    fw_status: list[str] = field(default_factory=list)
    dev_state: str = ""
    fw_ver: str = ""
    trc: str = ""
    tx_queue_limit: int = 0
    hbm_ver: str = ""
    kind: str = ""
    clients: list[dict[str, Any]] = field(default_factory=list)
    processes: list[dict[str, str]] = field(default_factory=list)
    dmesg_events: list[str] = field(default_factory=list)
    network_events: list[dict[str, Any]] = field(default_factory=list)
    heci_lock: dict[str, Any] = field(default_factory=dict)


def read_sysfs(path: str) -> str:
    """Read a sysfs file safely."""
    try:
        with open(path) as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return ""


def read_fw_status() -> list[str]:
    """Read ME firmware status registers (8 registers, 4 bytes each)."""
    raw = read_sysfs(f"{MEI_SYSFS}/fw_status")
    if not raw:
        return []
    return raw.split("\n")


def parse_fw_status(regs: list[str]) -> dict[str, str]:
    """Decode fw_status registers into human-readable fields.
    
    fw_status registers (from Intel MEI documentation):
    [0] — Current operational state + mode
    [1] — FW feature subset + error code
    [2] — Operational mode details
    [3-6] — Reserved / additional state
    [7] — Firmware type info
    """
    decoded = {}
    
    if len(regs) >= 1:
        val = int(regs[0], 16) if regs[0] else 0
        state_bits = val & 0xF
        states = {
            0: "INIT", 1: "READY", 2: "RESET", 3: "ERROR",
            4: "RECOVERY", 5: "NORMAL", 6: "POWER_DOWN",
            7: "HOST_INIT", 8: "HOST_RESET", 9: "INIT_2",
        }
        decoded["op_state"] = states.get(state_bits, f"UNKNOWN({state_bits})")
        decoded["init_complete"] = bool(val & 0x10)
        decoded["runtime"] = bool(val & 0x20)
        decoded["recovery"] = bool(val & 0x40)
        decoded["me_bios_sync"] = bool(val & 0x100)
        decoded["fw_init_complete"] = bool(val & 0x200)
        decoded["me_powered"] = bool(val & 0x400)
    
    if len(regs) >= 2:
        val = int(regs[1], 16) if regs[1] else 0
        decoded["error_code"] = (val >> 16) & 0xFFFF
        decoded["feature_subset"] = val & 0xFFFF
    
    return decoded


def get_mei_clients() -> list[dict[str, Any]]:
    """Enumerate all MEI bus clients from sysfs."""
    clients = []
    base = MEI_BUS
    if not os.path.exists(base):
        return clients
    
    for entry in os.listdir(base):
        path = os.path.join(base, entry)
        if not os.path.isdir(path):
            continue
        
        parts = entry.split("-", 1)
        if len(parts) != 2:
            continue
        
        pci_addr = parts[0]
        uuid = parts[1]
        name, desc = KNOWN_CLIENTS.get(uuid, ("UNKNOWN", "Not yet classified"))
        
        client = {
            "uuid": uuid,
            "pci_addr": pci_addr,
            "name": name,
            "description": desc,
            "fixed": read_sysfs(f"{path}/fixed"),
            "max_conn": read_sysfs(f"{path}/max_conn"),
            "max_len": read_sysfs(f"{path}/max_len"),
            "version": read_sysfs(f"{path}/version"),
            "vtag": read_sysfs(f"{path}/vtag"),
        }
        
        # Try to get driver
        driver_link = os.path.join(path, "driver")
        if os.path.islink(driver_link):
            client["driver"] = os.path.basename(os.readlink(driver_link))
        else:
            client["driver"] = None
        
        clients.append(client)
    
    return clients


async def get_processes_using_mei() -> list[dict[str, str]]:
    """Find all processes that have /dev/mei0 open."""
    processes = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "lsof", "-t", "/dev/mei0",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        pids = stdout.decode().strip().split("\n")
        
        for pid in pids:
            pid = pid.strip()
            if not pid:
                continue
            try:
                with open(f"/proc/{pid}/comm") as f:
                    comm = f.read().strip()
                with open(f"/proc/{pid}/cmdline") as f:
                    cmdline = f.read().replace("\x00", " ").strip()[:100]
                processes.append({"pid": pid, "name": comm, "cmdline": cmdline})
            except (FileNotFoundError, ProcessLookupError):
                pass
    except FileNotFoundError:
        # lsof not available — try fuser
        try:
            proc = await asyncio.create_subprocess_exec(
                "fuser", "/dev/mei0",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            pids = stdout.decode().strip().replace("/dev/mei0:", "").split()
            for pid in pids:
                pid = pid.strip()
                if not pid:
                    continue
                try:
                    with open(f"/proc/{pid}/comm") as f:
                        comm = f.read().strip()
                    processes.append({"pid": pid, "name": comm, "cmdline": ""})
                except (FileNotFoundError, ProcessLookupError):
                    pass
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"Could not check processes: {e}")
    
    return processes


async def get_dmesg_mei_events() -> list[str]:
    """Get recent dmesg entries related to MEI/HECI/CSME."""
    events = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "dmesg", "--time-format", "iso",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        for line in stdout.decode().splitlines():
            lower = line.lower()
            if any(kw in lower for kw in ["mei", "heci", "csme", "management engine", "iommu", "dmar"]):
                events.append(line)
    except Exception as e:
        logger.warning(f"Could not read dmesg: {e}")
    
    return events[-20:]  # Last 20 events


def check_heci_lock() -> dict[str, Any]:
    """Check if /dev/mei0 is bind-mounted to /dev/null (HECI lock).
    
    T1542.002 defense — blocks all userspace HECI access to Intel ME.
    Uses ioctl test: if /dev/mei0 is bind-mounted to /dev/null,
    HECI ioctls return ENOTTY instead of connecting to a MEI client.
    """
    import fcntl, os
    
    result = {
        "locked": False,
        "method": "none",
        "device": "/dev/mei0",
        "actual_device": "mei",
        "detail": "HECI accessible — userspace can send MEI messages",
    }
    
    # Check if /dev/mei0 is a bind mount to /dev/null
    try:
        with open("/proc/self/mountinfo") as f:
            for line in f:
                if "/dev/mei0" in line and "/dev/null" in line:
                    result["locked"] = True
                    result["method"] = "bind_mount_null"
                    result["actual_device"] = "/dev/null"
                    result["detail"] = "/dev/mei0 bind-mounted to /dev/null — HECI blocked"
                    break
    except Exception:
        pass
    
    # Verify with ioctl test — try MEI_CONNECT_CLIENT ioctl
    # _IOWR('M', 0x01, struct mei_connect_client_data) = 0x80044d01
    try:
        fd = os.open("/dev/mei0", os.O_RDWR)
        try:
            fcntl.ioctl(fd, 0x80044d01, b"\x00" * 32)
            # If ioctl succeeded, HECI is NOT locked
            result["locked"] = False
            result["detail"] = "HECI ACCESSIBLE — ioctl succeeded, lock not effective"
        except OSError as e:
            if e.errno == 25:  # ENOTTY — Inappropriate ioctl for device
                result["locked"] = True
                result["method"] = "bind_mount_null"
                result["actual_device"] = "/dev/null"
                result["detail"] = "HECI BLOCKED — ioctl returns ENOTTY (bind mount to /dev/null active)"
            # Other errors might mean the device is just not accessible
        os.close(fd)
    except PermissionError:
        result["locked"] = True
        result["method"] = "permission_denied"
        result["detail"] = "HECI BLOCKED — permission denied"
    except Exception as e:
        result["locked"] = True
        result["method"] = "error"
        result["detail"] = f"HECI BLOCKED — {e}"
    
    return result


async def collect_me_state() -> MEState:
    """Collect complete ME state snapshot."""
    state = MEState(timestamp=time.time())
    
    # sysfs attributes
    state.fw_status = read_fw_status()
    state.dev_state = read_sysfs(f"{MEI_SYSFS}/dev_state")
    state.fw_ver = read_sysfs(f"{MEI_SYSFS}/fw_ver")
    state.trc = read_sysfs(f"{MEI_SYSFS}/trc")
    state.tx_queue_limit_str = read_sysfs(f"{MEI_SYSFS}/tx_queue_limit")
    state.tx_queue_limit = int(state.tx_queue_limit_str) if state.tx_queue_limit_str else 0
    state.hbm_ver = read_sysfs(f"{MEI_SYSFS}/hbm_ver")
    state.kind = read_sysfs(f"{MEI_SYSFS}/kind")
    
    # Decoded fw_status
    state.fw_status_decoded = parse_fw_status(state.fw_status)
    
    # MEI clients
    state.clients = get_mei_clients()
    
    # HECI lock status (T1542.002 defense)
    state.heci_lock = check_heci_lock()
    
    # Processes using /dev/mei0
    state.processes = await get_processes_using_mei()
    
    # dmesg events
    state.dmesg_events = await get_dmesg_mei_events()
    
    return state


def state_to_dict(state: MEState) -> dict[str, Any]:
    """Convert MEState to dict for API response."""
    return {
        "timestamp": state.timestamp,
        "dev_state": state.dev_state,
        "fw_ver": state.fw_ver,
        "fw_status": state.fw_status,
        "fw_status_decoded": getattr(state, "fw_status_decoded", {}),
        "trc": state.trc,
        "tx_queue_limit": state.tx_queue_limit,
        "hbm_ver": state.hbm_ver,
        "kind": state.kind,
        "clients": state.clients,
        "processes": state.processes,
        "dmesg_events": state.dmesg_events,
        "heci_lock": getattr(state, "heci_lock", {}),
    }

def read_rapl_power() -> dict[str, Any]:
    """Read Intel RAPL power consumption data."""
    import os
    try:
        result = {}
        for path, name in [
            ("/sys/class/powercap/intel-rapl:0", "package"),
            ("/sys/class/powercap/intel-rapl:0:0", "core"),
            ("/sys/class/powercap/intel-rapl:0:1", "uncore"),
        ]:
            try:
                energy = int(open(f"{path}/energy_uj").read().strip())
                max_energy = int(open(f"{path}/max_energy_range_uj").read().strip())
                domain_name = open(f"{path}/name").read().strip()
                result[name] = {
                    "domain": domain_name,
                    "energy_uj": energy,
                    "energy_kj": round(energy / 1_000_000, 1),
                    "max_range_uj": max_energy,
                    "utilization_pct": round((energy / max(max_energy, 1)) * 100, 2),
                }
            except:
                pass
        result["me_power_estimate"] = "100-200mW"
        result["me_power_source"] = "3.3VSB rail"
        return result
    except Exception as e:
        return {"error": str(e)}


def read_driver_memory() -> dict[str, Any]:
    """Get MEI driver memory usage."""
    try:
        result = {}
        with open("/proc/modules") as f:
            for line in f:
                parts = line.split()
                if parts[0] == "mei_me":
                    result["mei_me"] = {
                        "size_kb": int(parts[1]) // 1024,
                        "ref_count": int(parts[2]) if len(parts) > 2 else 0,
                    }
                elif parts[0] == "mei":
                    result["mei_core"] = {
                        "size_kb": int(parts[1]) // 1024,
                        "ref_count": int(parts[2]) if len(parts) > 2 else 0,
                    }
                elif parts[0] == "mei_gsc_proxy":
                    result["mei_gsc_proxy"] = {
                        "size_kb": int(parts[1]) // 1024,
                        "ref_count": int(parts[2]) if len(parts) > 2 else 0,
                    }
        return result
    except:
        return {}
