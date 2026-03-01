"""Profinet DCP Layer 2 discovery and configuration.

By sawyerspresent.

Uses raw Ethernet frames (via pcap) to send PN-DCP Identify
requests and parse responses. Also supports setting network
parameters, station names, and flashing LEDs — all at Layer 2.

Requires WinPcap/Npcap (Windows) or libpcap (Linux).
"""

from __future__ import annotations

import os
import re
import socket
import struct
import time
from binascii import hexlify, unhexlify
from multiprocessing.pool import ThreadPool

from scadaver.core.pcap import pcap_close, pcap_next, pcap_open, pcap_send

DISCOVER_TIMEOUT = 2


# ---------------------------------------------------------------------------
# Raw Ethernet frame helpers
# ---------------------------------------------------------------------------

def _build_raw_frame(
    dst_mac: str,
    src_mac: str,
    ethertype: str,
    payload_hex: str,
) -> bytes:
    """Assemble a complete Ethernet frame from hex strings.

    Args:
        dst_mac: Destination MAC as 12-char hex (no colons).
        src_mac: Source MAC as 12-char hex (no colons).
        ethertype: 4-char hex ethertype (e.g. ``'8892'``).
        payload_hex: Hex payload string.

    Returns:
        Complete frame as bytes.
    """
    return unhexlify(dst_mac + src_mac + ethertype + payload_hex)


def _send_raw(
    pcap_device: str,
    ethertype: str,
    src_mac: str,
    payload_hex: str,
    dst_mac: str = "",
) -> None:
    """Open pcap, send a single raw frame, then close.

    For DCP discovery (ethertype ``'8100'``), the well-known
    Profinet multicast MAC is used as destination.

    Args:
        pcap_device: Pcap device name (NPF GUID or Linux dev).
        ethertype: Frame ethertype.
        src_mac: Source MAC (12-char hex, no colons).
        payload_hex: Hex payload.
        dst_mac: Override destination MAC.
    """
    if ethertype == "8100":
        # PN-DCP multicast discovery
        dst_mac = "010ecf000000"
        full_payload = (
            "00008892fefe05000400000300800004ffff"
            "00000000000000000000000000000000"
            "00000000000000000000000000"
        )
    elif not dst_mac:
        raise ValueError("dst_mac is required for ethertype " + ethertype)
    else:
        full_payload = payload_hex

    frame = _build_raw_frame(dst_mac, src_mac, ethertype, full_payload)
    handle = pcap_open(pcap_device)
    pcap_send(handle, frame)
    pcap_close(handle)


def _receive_raw(
    pcap_device: str,
    timeout: int,
    src_mac: str,
    ethertype: str,
    *,
    stop_on_first: bool = False,
) -> list[bytes]:
    """Receive raw Ethernet frames matching a filter.

    Args:
        pcap_device: Pcap device name.
        timeout: Capture duration in seconds.
        src_mac: Our MAC (12-char hex) — packets TO us.
        ethertype: Ethertype to filter on (4-char hex).
        stop_on_first: Stop after the first matching packet.

    Returns:
        List of matching raw frame byte arrays.
    """
    results: list[bytes] = []
    handle = pcap_open(pcap_device)
    deadline = time.time() + timeout

    while time.time() < deadline:
        pkt = pcap_next(handle)
        if pkt is None:
            continue
        raw_bytes, _ = pkt
        if len(raw_bytes) < 14:
            continue
        pkt_etype = raw_bytes[12:14].hex().lower()
        pkt_dst = raw_bytes[:6].hex().lower()
        if pkt_etype == ethertype.lower() and pkt_dst == src_mac.lower():
            results.append(raw_bytes)
            if stop_on_first:
                break

    pcap_close(handle)
    return results


# ---------------------------------------------------------------------------
# DCP response parser
# ---------------------------------------------------------------------------

def parse_dcp_response(
    raw_frame: bytes,
) -> dict[str, str | None]:
    """Parse a PN-DCP Identify response from a raw Ethernet frame.

    Extracts device type, station name, vendor/device IDs, IP info,
    and MAC address from the DCP payload.

    Args:
        raw_frame: Complete Ethernet frame bytes.

    Returns:
        Dict with keys: ``mac_address``, ``type_of_station``,
        ``name_of_station``, ``vendor_id``, ``device_id``,
        ``device_role``, ``ip_address``, ``subnet_mask``,
        ``standard_gateway``.
    """
    mac = ":".join(
        re.findall(
            ".{2}",
            raw_frame[6:12].hex(),
        )
    )
    hex_data = raw_frame[14:].hex()
    device: dict[str, str | None] = {
        "mac_address": mac,
        "type_of_station": None,
        "name_of_station": None,
        "vendor_id": None,
        "device_id": None,
        "device_role": None,
        "ip_address": None,
        "subnet_mask": None,
        "standard_gateway": None,
    }

    # DCP Identify response starts with FrameID 0xFEFF
    if hex_data[:4].lower() != "feff":
        return device

    data = hex_data[24:]  # Skip to first block
    while len(data) > 0:
        if len(data) < 8:
            break
        block_len = int(data[4:8], 16)
        block = data[: (4 + block_len) * 2]
        block_id = block[:4]

        if block_id == "0201":
            raw = unhexlify(block[8 : 8 + block_len * 2])
            device["type_of_station"] = raw.decode(
                errors="ignore"
            ).replace("\x00", "")
        elif block_id == "0202":
            raw = unhexlify(block[8 : 8 + block_len * 2])
            device["name_of_station"] = raw.decode(
                errors="ignore"
            ).replace("\x00", "")
        elif block_id == "0203":
            device["vendor_id"] = block[12:16]
            device["device_id"] = block[16:20]
        elif block_id == "0204":
            device["device_role"] = block[12:14]
        elif block_id == "0102":
            device["ip_address"] = socket.inet_ntoa(
                struct.pack(">L", int(block[12:20], 16))
            )
            device["subnet_mask"] = socket.inet_ntoa(
                struct.pack(">L", int(block[20:28], 16))
            )
            device["standard_gateway"] = socket.inet_ntoa(
                struct.pack(">L", int(block[28:36], 16))
            )

        padding = block_len % 2
        data = data[(4 + block_len + padding) * 2 :]

    return device


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover(
    pcap_device: str,
    src_mac: str,
    timeout: int = DISCOVER_TIMEOUT,
) -> list[dict[str, str | None]]:
    """Perform a Profinet DCP Layer 2 discovery scan.

    Sends a PN-DCP Identify All broadcast and collects responses.

    Args:
        pcap_device: Pcap device name (NPF GUID or Linux dev).
        src_mac: Our MAC address (12-char hex, no colons).
        timeout: Seconds to wait for responses.

    Returns:
        List of parsed device dicts (one per unique MAC).
    """
    # Start listener in background thread
    pool = ThreadPool(processes=1)
    async_result = pool.apply_async(
        _receive_raw,
        (pcap_device, timeout, src_mac, "8892"),
    )

    # Small delay to ensure listener is active
    time.sleep(0.2)

    # Send DCP Identify All multicast
    _send_raw(pcap_device, "8100", src_mac, "")

    raw_packets = async_result.get()
    pool.close()

    # Deduplicate by MAC
    seen_macs: set[str] = set()
    devices: list[dict[str, str | None]] = []
    for pkt in raw_packets:
        parsed = parse_dcp_response(pkt)
        mac = parsed.get("mac_address", "")
        if mac and mac not in seen_macs:
            seen_macs.add(mac)
            devices.append(parsed)

    return devices


# ---------------------------------------------------------------------------
# Network configuration (Layer 2)
# ---------------------------------------------------------------------------

def _ip_to_hex(ip: str) -> str:
    """Convert dotted-decimal IP to hex string."""
    return "".join(hex(int(o))[2:].zfill(2) for o in ip.split("."))


def set_network(
    pcap_device: str,
    src_mac: str,
    dst_mac: str,
    new_ip: str,
    new_mask: str,
    new_gateway: str,
    timeout: int = DISCOVER_TIMEOUT,
) -> str | None:
    """Set network parameters on a Profinet device via DCP SET.

    Args:
        pcap_device: Pcap device name.
        src_mac: Our MAC (12-char hex).
        dst_mac: Target device MAC (12-char hex).
        new_ip: New IPv4 address.
        new_mask: New subnet mask.
        new_gateway: New default gateway.
        timeout: Response timeout.

    Returns:
        Response code as 4-char hex string, or None if no response.
        ``'0000'`` indicates success.
    """
    network_data = _ip_to_hex(new_ip) + _ip_to_hex(new_mask) + _ip_to_hex(new_gateway)

    payload = (
        "fefd 04 00 04000001 0000 0012 0102 000e 0001"
        + network_data
        + "0000 0000 0000 0000 0000 0000"
    ).replace(" ", "")

    # Start listener
    pool = ThreadPool(processes=1)
    async_result = pool.apply_async(
        _receive_raw,
        (pcap_device, timeout, src_mac, "8892"),
        {"stop_on_first": True},
    )

    frame = _build_raw_frame(dst_mac, src_mac, "8892", payload)
    handle = pcap_open(pcap_device)
    pcap_send(handle, frame)
    pcap_close(handle)

    results = async_result.get()
    pool.close()

    if results:
        resp_hex = results[0][14:].hex()
        return resp_hex[36:40]
    return None


def set_station_name(
    pcap_device: str,
    src_mac: str,
    dst_mac: str,
    new_name: str,
    timeout: int = DISCOVER_TIMEOUT,
) -> str | None:
    """Set the station name on a Profinet device via DCP SET.

    Args:
        pcap_device: Pcap device name.
        src_mac: Our MAC (12-char hex).
        dst_mac: Target device MAC (12-char hex).
        new_name: New station name (lowercase, ``.-`` allowed).
        timeout: Response timeout.

    Returns:
        Response code byte (2-char hex), or None if no response.
        ``'00'`` indicates success.
    """
    name_hex = new_name.lower().encode().hex()
    name_len = len(new_name)
    padding = "00" if name_len % 2 == 1 else ""

    first_dcp = hex(name_len + len(padding) // 2 + 6)[2:].zfill(4)
    second_dcp = hex(name_len + 2)[2:].zfill(4)

    data = "fefd 04 00 02010004 0000".replace(" ", "")
    data += first_dcp
    data += "0202"
    data += second_dcp
    data += "0001"
    data += name_hex + padding

    # Pad to minimum 60 bytes total frame payload
    min_payload_hex = 46 * 2  # 46 bytes minimum payload
    if len(data) < min_payload_hex:
        data += "00" * ((min_payload_hex - len(data)) // 2)

    # Start listener
    pool = ThreadPool(processes=1)
    async_result = pool.apply_async(
        _receive_raw,
        (pcap_device, timeout, src_mac, "8892"),
        {"stop_on_first": True},
    )
    time.sleep(0.5)

    frame = _build_raw_frame(dst_mac, src_mac, "8892", data)
    handle = pcap_open(pcap_device)
    pcap_send(handle, frame)
    pcap_close(handle)

    results = async_result.get()
    pool.close()

    if results:
        resp_hex = results[0][14:].hex()
        return resp_hex[36:38]
    return None


def flash_led(
    pcap_device: str,
    src_mac: str,
    dst_mac: str,
    duration: int = 2,
) -> None:
    """Flash the LED on a Profinet device via DCP Signal.

    Sends repeated DCP Signal packets for the given duration.

    Args:
        pcap_device: Pcap device name.
        src_mac: Our MAC (12-char hex).
        dst_mac: Target device MAC (12-char hex).
        duration: Seconds to flash (rounded up to multiples of 2).
    """
    payload = (
        "fefd 040000001912000000080503000400000100"
        "000000000000000000000000000000000000"
        "000000000000000000000000"
    ).replace(" ", "")

    for _ in range(0, duration, 2):
        frame = _build_raw_frame(dst_mac, src_mac, "8892", payload)
        handle = pcap_open(pcap_device)
        pcap_send(handle, frame)
        pcap_close(handle)
        time.sleep(2)
