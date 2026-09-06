"""RingWatch configuration."""

import os

# MEI device paths
MEI_DEVICE = "/dev/mei0"
MEI_SYSFS = "/sys/class/mei/mei0"
MEI_BUS = "/sys/bus/mei/devices"

# SPI flash
SPI_DEVICE = "/dev/mtd0ro"

# Polling intervals (seconds)
POLL_SYSFS = 1        # fw_status, dev_state, trc — fast
POLL_CLIENTS = 5      # MEI bus clients — changes rarely
POLL_PROCESSES = 2    # lsof on /dev/mei0
POLL_DMESG = 3        # kernel ring buffer for MEI events
POLL_NETWORK = 5      # AMT port activity
POLL_HECI = 10        # HECI active probe (MKHI queries)

# Network monitor ports (same as our tcpdump monitor)
AMT_PORTS = [623, 664, 16990, 16992, 16993, 16994, 16995, 16996]

# HECI MKHI protocol constants
MKHI_GROUP_ID_FIRMWARE = 0x03
MKHI_COMMAND_FW_VERSION = 0x02
MKHI_COMMAND_CAPABILITY = 0x05

# Server
HOST = "127.0.0.1"
PORT = 8849

# Database (SQLite for forensic timeline)
DB_PATH = os.environ.get("RINGWATCH_DB", "/var/log/ringwatch.db")