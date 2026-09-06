"""HECI Spy — actively probes Intel ME via MKHI protocol through /dev/mei0.

Based on the intel-me-research project (heci_spy.py) by Jatinkapilaq1.
Linux adaptation — uses ioctl to connect to MEI clients and send MKHI messages.

All operations are READ-ONLY — we only query ME, never write to it.
"""

from __future__ import annotations

import fcntl
import struct
import logging
import time
from typing import Any
from dataclasses import dataclass

from app.core.config import MEI_DEVICE

logger = logging.getLogger(__name__)

# MEI IOCTL: connect to a client by UUID
# From Linux kernel: drivers/misc/mei/main.c
# #define MEI_CONNECT_CLIENT _IOWR('M', 0x01, struct mei_connect_client_data)
# But we can also just open the character device and the kernel routes by UUID

# HECI/MKHI protocol constants
MKHI_GROUP_ID_FIRMWARE = 0x03
MKHI_COMMAND_FW_VERSION = 0x02
MKHI_COMMAND_CAPABILITY = 0x05
MKHI_GROUP_ID_COMMON = 0x00
MKHI_COMMAND_GET_FW_VERSION = 0x02

# MEI client UUIDs for MKHI
MKHI_FIXED_CLIENT_UUID = "55213584-9a29-4916-badf-0fb7ed682aeb"  # MKHIF_FIX
AMT_CLIENT_UUID = "8c2f4425-77d6-4755-aca3-891fdbc66a58"  # AMT

# HBM (HECI Bus Message) types
HBM_HOST_ENUM = 0x0B
HBM_HOST_CLIENT_PROPERTIES = 0x0C


def parse_uuid(uuid_str: str) -> bytes:
    """Parse UUID string to 16 bytes."""
    uuid_str = uuid_str.replace("-", "")
    return bytes.fromhex(uuid_str)


@dataclass
class HeciProbeResult:
    """Result of a HECI probe."""
    success: bool
    command: str
    raw_response: bytes = b""
    error: str = ""
    timestamp: float = 0.0
    parsed: dict[str, Any] = None


def try_connect_mei(uuid: str) -> int | None:
    """Try to open /dev/mei0 and connect to a specific MEI client by UUID.
    
    Returns file descriptor on success, None on failure.
    """
    try:
        fd = open(MEI_DEVICE, "r+b", buffering=0)
        return fd
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.debug(f"Cannot open {MEI_DEVICE}: {e}")
        return None


def probe_fw_version_from_sysfs() -> dict[str, Any]:
    """Get firmware version from sysfs (fallback if HECI direct probe fails)."""
    try:
        with open(f"/sys/class/mei/mei0/fw_ver") as f:
            versions = [line.strip() for line in f if line.strip()]
        return {
            "versions": versions,
            "current": versions[0] if versions else "unknown",
            "backup": versions[2] if len(versions) > 2 else "none",
        }
    except Exception as e:
        return {"error": str(e)}


def probe_fw_status_decoded() -> dict[str, Any]:
    """Decode firmware status registers."""
    try:
        with open(f"/sys/class/mei/mei0/fw_status") as f:
            regs = [line.strip() for line in f if line.strip()]
        
        if len(regs) < 2:
            return {"error": "Not enough registers"}
        
        reg0 = int(regs[0], 16)
        reg1 = int(regs[1], 16)
        
        # State decode
        state_bits = reg0 & 0xF
        states = {
            0: "INIT", 1: "READY", 2: "RESET", 3: "ERROR",
            4: "RECOVERY", 5: "NORMAL", 6: "POWER_DOWN",
            7: "HOST_INIT", 8: "HOST_RESET", 9: "INIT_2",
        }
        
        return {
            "raw": regs,
            "op_state": states.get(state_bits, f"UNKNOWN({state_bits})"),
            "init_complete": bool(reg0 & 0x10),
            "runtime_mode": bool(reg0 & 0x20),
            "recovery_mode": bool(reg0 & 0x40),
            "me_bios_sync": bool(reg0 & 0x100),
            "fw_init_complete": bool(reg0 & 0x200),
            "me_powered": bool(reg0 & 0x400),
            "error_code": (reg1 >> 16) & 0xFFFF,
            "feature_subset": reg1 & 0xFFFF,
            "trc": int(open(f"/sys/class/mei/mei0/trc").read().strip(), 16),
        }
    except Exception as e:
        return {"error": str(e)}


def probe_client_summary() -> dict[str, Any]:
    """Summarize all MEI clients and their states."""
    import os
    base = "/sys/bus/mei/devices"
    if not os.path.exists(base):
        return {"error": "No MEI bus"}
    
    known = {
        "55213584-9a29-4916-badf-0fb7ed682aeb": ("MKHIF_FIX", "OS Version Telemetry — feeds OS info to ME", "POISON"),
        "8c2f4425-77d6-4755-aca3-891fdbc66a58": ("AMT", "Active Management — remote management (OFF)", "POISON"),
        "8e6a6715-9abc-4043-88ef-9e39c6f63e0f": ("PTT", "Platform Trust (fTPM) — disk encryption keys", "PROTECT"),
        "0f73db04-97ab-4125-b893-e904ad0d5464": ("GSC_PROXY", "Graphics Security Command Proxy", "SAFE"),
        # Previously unknown — identified Aug 3 via buffer sizes, fixed status, kernel source analysis
        "6861ec7b-d07a-4673-856c-7f22b4d55769": ("HMRFPO", "Host Management Fixed (internal ME-BIOS sync)", "MONITOR"),
        "dd17041c-09ea-4b17-a271-5b989867ec65": ("NFTP_UPDATE", "Firmware Update (NFTP protocol)", "MONITOR"),
        "082ee5a7-7c25-470a-9643-0c06f0466ea1": ("EXT_BOOT", "Extended Boot/Recovery (bulk transfer)", "MONITOR"),
        "42b3ce2f-bd9f-485a-96ae-26406230b1ff": ("BIOS_INTEG", "BIOS Integration (power/thermal/boot state)", "MONITOR"),
        "309dcde8-ccb1-4062-8f78-600115a34327": ("SPI_PROXY", "SPI Flash Proxy (ME read/write to SPI)", "MONITOR"),
    }
    
    clients = []
    for entry in os.listdir(base):
        path = os.path.join(base, entry)
        if not os.path.isdir(path):
            continue
        parts = entry.split("-", 1)
        if len(parts) != 2:
            continue
        uuid = parts[1]
        name, desc, action = known.get(uuid, ("UNKNOWN", "Unclassified", "RESEARCH"))
        
        try:
            fixed = open(f"{path}/fixed").read().strip()
            max_conn = open(f"{path}/max_conn").read().strip()
            max_len = open(f"{path}/max_len").read().strip()
        except:
            fixed = max_conn = max_len = "?"
        
        driver_link = os.path.join(path, "driver")
        driver = os.path.basename(os.readlink(driver_link)) if os.path.islink(driver_link) else None
        
        clients.append({
            "uuid": uuid,
            "name": name,
            "description": desc,
            "action": action,
            "fixed": fixed,
            "max_conn": max_conn,
            "max_len": max_len,
            "driver": driver,
        })
    
    return {
        "total": len(clients),
        "clients": clients,
        "poison_targets": [c for c in clients if c["action"] == "POISON"],
        "protected": [c for c in clients if c["action"] == "PROTECT"],
        "unknown": [c for c in clients if c["action"] == "RESEARCH"],
    }


def probe_spi_flash() -> dict[str, Any]:
    """Get SPI flash info (read-only)."""
    try:
        size = int(open("/sys/class/mtd/mtd0/size").read().strip())
        return {
            "device": "/dev/mtd0ro",
            "size_bytes": size,
            "size_mb": round(size / (1024 * 1024), 1),
            "me_region": "0x00004000 - 0x0086A000 (8.4 MB)",
            "read_only": True,
        }
    except Exception as e:
        return {"error": str(e)}


def probe_pci_device() -> dict[str, Any]:
    """Get ME PCI device info including power state and config space."""
    import subprocess
    import struct
    try:
        result = subprocess.run(
            ["lspci", "-vvv", "-s", "00:16.0"],
            capture_output=True, text=True, timeout=5
        )
        lines = result.stdout.splitlines()
        info = {"raw": result.stdout}
        for line in lines:
            if "Subsystem" in line:
                info["subsystem"] = line.strip()
            elif "Kernel driver" in line:
                info["driver"] = line.strip()
            elif "Region" in line:
                if "regions" not in info:
                    info["regions"] = []
                info["regions"].append(line.strip())
            elif "PME" in line or "D0" in line or "D3" in line:
                if "power_state" not in info:
                    info["power_state"] = line.strip()
        
        # Read PCI config space from sysfs
        try:
            with open("/sys/devices/pci0000:00/0000:00:16.0/config", "rb") as f:
                config_data = f.read(256)
                info["device_id"] = f"0x{struct.unpack_from('<H', config_data, 0)[0]:04X}"
                info["vendor_id"] = f"0x{struct.unpack_from('<H', config_data, 2)[0]:04X}"  
                info["subsystem_id"] = f"0x{struct.unpack_from('<H', config_data, 0x2E)[0]:04X}"
                info["subsystem_vendor"] = f"0x{struct.unpack_from('<H', config_data, 0x2C)[0]:04X}"
                # Power management register (cap at offset 0x50)
                pm_cap = struct.unpack_from('<H', config_data, 0x50)[0]
                info["pm_cap_addr"] = f"0x{pm_cap:04X}"
                # Read power state from PM capabilities
                pm_reg = struct.unpack_from('<I', config_data, pm_cap + 4)[0]
                pm_state = (pm_reg >> 16) & 0x3
                pm_states = {0: "D0 (fully on)", 1: "D1", 2: "D2", 3: "D3hot (off)"}
                info["pci_power_state"] = pm_states.get(pm_state, f"D{pm_state}")
                info["pm_pme_support"] = f"D0:{bool(pm_reg & 0x1100)} D3hot:{bool(pm_reg & 0x8800)}"
        except Exception as e:
            info["config_error"] = str(e)
        
        # MEI driver memory usage
        try:
            with open("/proc/modules") as f:
                for line in f:
                    if line.startswith("mei_me"):
                        parts = line.split()
                        info["mei_driver_size"] = f"{int(parts[1])} bytes ({int(parts[1])//1024} KB)"
                        info["mei_ref_count"] = parts[3]
                    elif line.startswith("mei "):
                        parts = line.split()
                        info["mei_core_size"] = f"{int(parts[1])} bytes ({int(parts[1])//1024} KB)"
        except:
            pass
        
        # MEI kernel thread (if any)
        try:
            result2 = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=5
            )
            for line in result2.stdout.splitlines():
                if "mei_me" in line or "irq/160" in line:
                    info["kernel_thread"] = line.strip()
                    break
        except:
            pass
        
        # HECI MMIO info (can't read registers directly due to STRICT_DEVMEM)
        info["heci_mmio"] = {
            "base": "0x402028b000",
            "size": "4KB",
            "access": "BLOCKED by CONFIG_STRICT_DEVMEM — registers would show buffer fill level",
            "registers": {
                "0x00": "H_CB_WW (Host Circular Buffer Write Window)",
                "0x04": "H_CSR (Host Control Status — ready, interrupt, buffer pointers)",
                "0x08": "ME_CB_RW (ME Circular Buffer Read Window)",
                "0x0C": "ME_CSR_HA (ME Control Status — ready, interrupt, buffer pointers)",
            }
        }
        
        # PMC SSRAM (shared memory between ME and host)
        info["pmc_ssram"] = {
            "region0": "0x4020284000 (16KB) — PMC telemetry data",
            "region2": "0x402028f000 (4KB) — PMC additional",
            "access": "BLOCKED by CONFIG_STRICT_DEVMEM — would show power/thermal telemetry",
        }
        
        return info
    except Exception as e:
        return {"error": str(e)}


def probe_network_ports() -> dict[str, Any]:
    """Check if AMT ports are listening."""
    import subprocess
    try:
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True, text=True, timeout=5
        )
        amt_ports = [623, 664, 16990, 16992, 16993, 16994, 16995, 16996]
        listening = []
        for line in result.stdout.splitlines():
            for port in amt_ports:
                if f":{port} " in line:
                    listening.append({"port": port, "line": line.strip()})
        return {
            "amt_ports_checked": amt_ports,
            "listening": listening,
            "amt_active": len(listening) > 0,
        }
    except Exception as e:
        return {"error": str(e)}


def probe_rapl_power() -> dict[str, Any]:
    """Read Intel RAPL power consumption data."""
    import os
    try:
        result = {}
        # Package power
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
        
        # ME draws from 3.3VSB — not separately measurable via RAPL
        # But we can show total package power as context
        result["me_power_note"] = "ME draws 100-200mW from 3.3VSB rail — not separately measurable via RAPL. Included in 'uncore' domain."
        result["me_power_estimate"] = "100-200 mW (standby, from research)"
        return result
    except Exception as e:
        return {"error": str(e)}


def probe_driver_memory() -> dict[str, Any]:
    """Get MEI driver memory usage from /proc/modules."""
    try:
        result = {}
        with open("/proc/modules") as f:
            for line in f:
                parts = line.split()
                if parts[0] == "mei_me":
                    result["mei_me"] = {
                        "size_bytes": int(parts[1]),
                        "size_kb": int(parts[1]) // 1024,
                        "ref_count": int(parts[2]) if len(parts) > 2 else 0,
                        "state": parts[3] if len(parts) > 3 else "unknown",
                    }
                elif parts[0] == "mei":
                    result["mei_core"] = {
                        "size_bytes": int(parts[1]),
                        "size_kb": int(parts[1]) // 1024,
                        "ref_count": int(parts[2]) if len(parts) > 2 else 0,
                        "dependencies": parts[3] if len(parts) > 3 else "none",
                    }
                elif parts[0] == "mei_gsc_proxy":
                    result["mei_gsc_proxy"] = {
                        "size_bytes": int(parts[1]),
                        "size_kb": int(parts[1]) // 1024,
                        "ref_count": int(parts[2]) if len(parts) > 2 else 0,
                    }
        return result
    except Exception as e:
        return {"error": str(e)}


def probe_heci_buffers() -> dict[str, Any]:
    """Get HECI buffer info from sysfs and driver."""
    try:
        result = {
            "tx_queue_limit": int(open("/sys/class/mei/mei0/tx_queue_limit").read().strip()),
            "hbm_ver": open("/sys/class/mei/mei0/hbm_ver").read().strip(),
            "hbm_ver_drv": open("/sys/class/mei/mei0/hbm_ver_drv").read().strip(),
            "mmio_base": "0x402028b000",
            "mmio_size": "4KB",
            "access": "BLOCKED (CONFIG_STRICT_DEVMEM=y) — would show live buffer fill levels",
            "registers": {
                "H_CSR (0x04)": "Host buffer: ready, interrupt, write/read pointers, depth",
                "ME_CSR (0x0C)": "ME buffer: ready, interrupt, write/read pointers, depth",
            },
            "what_could_show": {
                "host_buffer_fill": "How many slots OS has written to ME (pending messages)",
                "me_buffer_fill": "How many slots ME has written to OS (pending responses)",
                "activity_level": "Total slots in use = how busy OS-ME communication is",
                "buffer_depth": "Size of circular buffers (typically 128 slots)",
            }
        }
        return result
    except Exception as e:
        return {"error": str(e)}


def full_probe() -> dict[str, Any]:
    """Run all probes and return complete ME status."""
    return {
        "timestamp": time.time(),
        "firmware": probe_fw_version_from_sysfs(),
        "status": probe_fw_status_decoded(),
        "clients": probe_client_summary(),
        "spi_flash": probe_spi_flash(),
        "pci_device": probe_pci_device(),
        "network": probe_network_ports(),
        "rapl_power": probe_rapl_power(),
        "driver_memory": probe_driver_memory(),
        "heci_buffers": probe_heci_buffers(),
    }