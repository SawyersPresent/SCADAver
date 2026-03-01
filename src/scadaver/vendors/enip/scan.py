"""EtherNet/IP (CIP) broadcast scanner for Allen-Bradley and other CIP devices.

Sends a List Identity broadcast on UDP port 44818 and parses responses.
"""

from __future__ import annotations

from scadaver.core.bytes import convert_to_int, invert_hex_string
from scadaver.core.network import (
    NetworkInterface,
    collect_responses_with_addr,
    create_udp_broadcast_socket,
    send_udp,
)
from scadaver.vendors.enip.enums import DEVICE_TYPE, VENDOR_ID

DISCOVERY_PACKET = "630000000000000000000000000000000000000000000000"
DEST_PORT = 44818
DEFAULT_TIMEOUT = 2


def parse_list_identity(data: bytes) -> dict | None:
    """Parse an EtherNet/IP List Identity response.

    Args:
        data: Raw response bytes.

    Returns:
        Dictionary with parsed device info, or None if unparseable.
    """
    if not data[:2] == b"\x63\x00":
        return None

    data_len = convert_to_int(data[2:4])
    response_data = data[-data_len:]

    item_count = convert_to_int(response_data[:2])
    if item_count < 1 or response_data[2:4] != b"\x0c\x00":
        return None

    item_len = convert_to_int(response_data[4:5])
    item = response_data[6 : 6 + item_len]

    encaps_version = invert_hex_string(item[:2].hex())

    socket_addr = {
        "sin_family": convert_to_int(item[2:4], inverted=False),
        "sin_port": convert_to_int(item[4:6], inverted=False),
        "sin_addr": f"{item[6]}.{item[7]}.{item[8]}.{item[9]}",
    }

    vendor_raw = invert_hex_string(item[18:20].hex())
    device_type_id = convert_to_int(item[20:22])
    product_code = convert_to_int(item[22:24])
    rev_major = convert_to_int(item[24:25], inverted=False)
    rev_minor = convert_to_int(item[25:26], inverted=False)
    revision = f"{rev_major}.{rev_minor}"
    status = invert_hex_string(item[26:28].hex())
    serial = invert_hex_string(item[28:32].hex())
    name_len = convert_to_int(item[32:33])
    product_name = item[33 : 33 + name_len].decode(errors="replace")
    state = item[-1:].hex()

    return {
        "SocketAddr": socket_addr,
        "EncapsVersion": encaps_version,
        "VendorID": vendor_raw,
        "DeviceType": device_type_id,
        "ProductCode": product_code,
        "Revision": revision,
        "Status": status,
        "SerialNumber": serial,
        "ProductName": product_name,
        "State": state,
    }


def scan(
    interface: NetworkInterface,
    timeout: int = DEFAULT_TIMEOUT,
    verbose: bool = False,
) -> list[dict]:
    """Broadcast-scan for EtherNet/IP devices.

    Args:
        interface: Local network interface to send from.
        timeout: Seconds to wait for responses.
        verbose: If True, print raw responses.

    Returns:
        List of parsed device dictionaries.
    """
    sock = create_udp_broadcast_socket(
        bind_ip=interface.ip, timeout=timeout
    )
    send_udp(sock, "255.255.255.255", DEST_PORT, DISCOVERY_PACKET)

    raw_responses = collect_responses_with_addr(sock)
    sock.close()

    if not raw_responses:
        print("No EtherNet/IP devices found.")
        return []

    devices = []
    header = f"{'Device Name':25} | {'IP Address':16} | {'Device Type':30} | {'Vendor':20}"
    print(header)
    print("-" * len(header))

    for data, _addr in raw_responses:
        device = parse_list_identity(data)
        if not device:
            continue
        devices.append(device)

        dev_type = DEVICE_TYPE.get(str(device["DeviceType"]), f"Unknown ({device['DeviceType']})")
        vendor_int = convert_to_int(bytes.fromhex(device["VendorID"]), inverted=False)
        vendor_name = VENDOR_ID.get(str(vendor_int), f"Unknown ({device['VendorID']})")

        print(
            f"{device['ProductName']:25} | "
            f"{device['SocketAddr']['sin_addr']:16} | "
            f"{dev_type:30} | "
            f"{vendor_name:20}"
        )

    if verbose:
        print("\nRaw results:")
        for device in devices:
            print(device)

    return devices


def scan_ip(
    ip: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[dict]:
    """Send a List Identity request to a specific IP address.

    Args:
        ip: Target IP address.
        timeout: Seconds to wait for response.

    Returns:
        List with one device dict, or empty list.
    """
    import socket as _socket

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(bytes.fromhex(DISCOVERY_PACKET), (ip, DEST_PORT))
        data, _ = sock.recvfrom(1024)
    except (_socket.timeout, OSError):
        print(f"No EtherNet/IP response from {ip}")
        return []
    finally:
        sock.close()

    device = parse_list_identity(data)
    if not device:
        return []

    dev_type = DEVICE_TYPE.get(str(device["DeviceType"]), f"Unknown ({device['DeviceType']})")
    vendor_int = convert_to_int(bytes.fromhex(device["VendorID"]), inverted=False)
    vendor_name = VENDOR_ID.get(str(vendor_int), f"Unknown ({device['VendorID']})")
    header = f"{'Device Name':25} | {'IP Address':16} | {'Device Type':30} | {'Vendor':20}"
    print(header)
    print("-" * len(header))
    print(
        f"{device['ProductName']:25} | "
        f"{device['SocketAddr']['sin_addr']:16} | "
        f"{dev_type:30} | "
        f"{vendor_name:20}"
    )
    return [device]
