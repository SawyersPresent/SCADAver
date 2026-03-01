"""Siemens device discovery combining Profinet DCP and S7Comm.

By sawyerspresent.

Provides Layer 2 (Profinet DCP) discovery via pcap and Layer 3
(S7Comm/COTP) device information retrieval.
"""

from __future__ import annotations

from scadaver.vendors.siemens.profinet import discover as dcp_discover
from scadaver.vendors.siemens.s7comm import (
    get_cpu_state,
    get_device_info_cotp,
    tcp_scan,
)

# Well-known Siemens device ID mappings
VENDOR_IDS: dict[str, str] = {
    "002a": "Siemens",
}

DEVICE_IDS: dict[str, str] = {
    "0a01": "Switch",
    "0202": "PCSIM (Simulator)",
    "0203": "S7-300 CP",
    "0101": "S7-300",
    "010d": "S7-1200",
    "0301": "HMI",
    "010b": "ET200S",
}


def decode_device_role(role_hex: str | None) -> str:
    """Decode a DCP device role hex byte into human-readable roles.

    Args:
        role_hex: 2-char hex string (e.g. ``'01'``).

    Returns:
        Space-separated role description string.
    """
    if not role_hex:
        return ""
    try:
        role_int = int(role_hex, 16)
    except ValueError:
        return ""

    roles: list[str] = []
    if role_int & 0x01:
        roles.append("IO-Device")
    if role_int & 0x02:
        roles.append("IO-Controller")
    if role_int & 0x04:
        roles.append("IO-Multidevice")
    if role_int & 0x08:
        roles.append("PN-Supervisor")
    return " ".join(roles)


def enrich_device(device: dict) -> dict:
    """Add decoded vendor/device names and TCP info to a DCP device.

    Performs a TCP scan (ports 102, 502), retrieves COTP device info
    and CPU state when port 102 is open.

    Args:
        device: Parsed DCP device dict (from profinet.discover).

    Returns:
        The same dict, enriched with additional fields:
        ``vendor_name``, ``device_name``, ``role_decoded``,
        ``open_ports``, ``hardware``, ``firmware``, ``cpu_state``.
    """
    vid = device.get("vendor_id", "")
    did = device.get("device_id", "")
    device["vendor_name"] = VENDOR_IDS.get(vid, "Unknown")
    device["device_name"] = DEVICE_IDS.get(did, "")
    device["role_decoded"] = decode_device_role(
        device.get("device_role")
    )

    ip = device.get("ip_address")
    if ip and ip != "None":
        device["open_ports"] = tcp_scan(ip)
        if 102 in device["open_ports"]:
            info = get_device_info_cotp(ip)
            device["hardware"] = info.get("hardware")
            device["firmware"] = info.get("firmware")
            device["cpu_state"] = info.get("cpu_state")
        else:
            device["hardware"] = None
            device["firmware"] = None
            device["cpu_state"] = None
    else:
        device["open_ports"] = []
        device["hardware"] = None
        device["firmware"] = None
        device["cpu_state"] = None

    return device


def scan_dcp(
    pcap_device: str,
    src_mac: str,
    timeout: int = 2,
    *,
    enrich: bool = True,
) -> list[dict]:
    """Perform a full Profinet DCP scan with optional TCP enrichment.

    Args:
        pcap_device: Pcap device name (NPF GUID or Linux dev).
        src_mac: Our MAC address (12-char hex, no colons).
        timeout: DCP discovery timeout in seconds.
        enrich: If True, also probe open TCP ports and COTP info.

    Returns:
        List of device dicts.
    """
    devices = dcp_discover(pcap_device, src_mac, timeout)
    if enrich:
        devices = [enrich_device(d) for d in devices]
    return devices


def scan_ip(ip: str) -> dict:
    """Scan a single Siemens device by IP (no Layer 2 required).

    Performs TCP port scan and COTP info retrieval.

    Args:
        ip: Target IPv4 address.

    Returns:
        Device info dict.
    """
    device: dict = {
        "mac_address": "UNK",
        "type_of_station": "Manual Entry",
        "name_of_station": "Manual Entry",
        "vendor_id": None,
        "device_id": None,
        "device_role": None,
        "ip_address": ip,
        "subnet_mask": None,
        "standard_gateway": None,
    }
    return enrich_device(device)
