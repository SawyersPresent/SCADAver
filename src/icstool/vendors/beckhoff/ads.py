"""Beckhoff AMS/ADS protocol packet construction and parsing.

Shared utilities for all Beckhoff ADS-based operations.
"""

from __future__ import annotations

import random

from icstool.core.bytes import ip_to_hex, reverse_bytes

DEFAULT_REMOTE_PORT = 10000
DEFAULT_LOCAL_PORT = 31337


def construct_ams_packet(
    remote_netid: str,
    local_netid: str,
    cmd_id: int,
    ads_data_list: list | tuple = (),
    invoke_id: str | None = None,
    is_request: bool = True,
    remote_port: int = DEFAULT_REMOTE_PORT,
    local_port: int = DEFAULT_LOCAL_PORT,
) -> str:
    """Construct a Beckhoff AMS/ADS packet as a hex string.

    AMS packet structure:
    0000 | cbData | TargetNETID | TargetPort |
    SenderNETID | SenderPort | CmdID | StateFlag |
    cbDataLength | ErrorCode | InvokeID | ADSData

    Args:
        remote_netid: Target AMS Net ID as hex string.
        local_netid: Sender AMS Net ID as hex string.
        cmd_id: ADS command ID (1-9).
        ads_data_list: Parameters depending on cmd_id.
        invoke_id: Optional hex invoke ID (8 chars).
        is_request: True for request, False for response.
        remote_port: Target AMS port number.
        local_port: Sender AMS port number.

    Returns:
        Complete AMS packet as hex string.
    """
    r_port = reverse_bytes(hex(remote_port)[2:].zfill(4))
    l_port = reverse_bytes(hex(local_port)[2:].zfill(4))
    s_cmd = reverse_bytes(hex(cmd_id)[2:].zfill(4))
    state_flag = 4 if is_request else 5
    s_state = reverse_bytes(hex(state_flag)[2:].zfill(4))

    ads_data = _build_ads_data(cmd_id, ads_data_list)

    data_len = reverse_bytes(
        hex(len(ads_data) // 2)[2:].zfill(8)
    )
    if not invoke_id:
        invoke_id = hex(random.randint(0, 0xFFFFFFFF))[2:].zfill(8)

    ams_data = (
        remote_netid + r_port
        + local_netid + l_port
        + s_cmd + s_state + data_len
        + "0" * 8 + reverse_bytes(invoke_id)
        + ads_data
    )
    ams_len = reverse_bytes(
        hex(len(ams_data) // 2)[2:].zfill(8)
    )
    return "0" * 4 + ams_len + ams_data


def _build_ads_data(cmd_id: int, params: list | tuple) -> str:
    """Build ADS data section based on command ID."""
    if cmd_id == 2:  # ADS Read
        if len(params) != 3:
            raise ValueError("ADS Read requires 3 params")
        return (
            reverse_bytes(hex(params[0])[2:].zfill(8))
            + reverse_bytes(hex(params[1])[2:].zfill(8))
            + reverse_bytes(hex(params[2])[2:].zfill(8))
        )
    if cmd_id == 3:  # ADS Write
        if len(params) != 3:
            raise ValueError("ADS Write requires 3 params")
        write_data = (
            params[2].hex()
            if isinstance(params[2], bytes)
            else params[2].encode().hex()
        )
        return (
            reverse_bytes(hex(params[0])[2:].zfill(8))
            + reverse_bytes(hex(params[1])[2:].zfill(8))
            + reverse_bytes(
                hex(len(write_data) // 2)[2:].zfill(8)
            )
            + write_data
        )
    if cmd_id == 4:  # ADS Read State
        return ""
    if cmd_id == 5:  # ADS Write Control
        if len(params) != 3:
            raise ValueError("ADS WriteControl requires 3 params")
        write_data = (
            params[2].hex()
            if isinstance(params[2], bytes)
            else params[2].encode().hex()
        )
        return (
            reverse_bytes(hex(params[0])[2:].zfill(4))
            + reverse_bytes(hex(params[1])[2:].zfill(4))
            + reverse_bytes(
                hex(len(write_data) // 2)[2:].zfill(8)
            )
            + write_data
        )
    if cmd_id == 9:  # ADS ReadWrite
        if len(params) != 4:
            raise ValueError("ADS ReadWrite requires 4 params")
        write_data = (
            params[3].hex()
            if isinstance(params[3], bytes)
            else params[3].encode().hex()
        )
        return (
            reverse_bytes(hex(params[0])[2:].zfill(8))
            + reverse_bytes(hex(params[1])[2:].zfill(8))
            + reverse_bytes(hex(params[2])[2:].zfill(8))
            + reverse_bytes(
                hex(len(write_data) // 2)[2:].zfill(8)
            )
            + write_data
        )
    if cmd_id in (1, 0, 6, 7, 8):
        raise NotImplementedError(
            f"ADS command {cmd_id} not implemented"
        )
    raise ValueError(f"Invalid ADS command ID: {cmd_id}")


def parse_ams_response(response: bytes) -> dict:
    """Parse a raw AMS response into its fields.

    Args:
        response: Raw bytes of the AMS response.

    Returns:
        Dictionary with parsed AMS fields.
    """
    data = response.hex()
    if data[:4] != "0000":
        raise ValueError(
            f"Malformed response header: {data[:4]}"
        )

    return {
        "PacketLength": int(reverse_bytes(data[4:12]), 16),
        "AMSDstNetID": data[12:24],
        "AMSDstPortID": int(reverse_bytes(data[24:28]), 16),
        "AMSSrcNetID": data[28:40],
        "AMSSrcNetPort": int(reverse_bytes(data[40:44]), 16),
        "CmdID": int(reverse_bytes(data[44:48]), 16),
        "StateFlags": int(reverse_bytes(data[48:52]), 16),
        "ErrorCode": reverse_bytes(data[60:68]),
        "InvokeID": reverse_bytes(data[68:76]),
        "ADSData": data[76 : 76 + int(reverse_bytes(data[52:60]), 16) * 2],
    }


def parse_ads_response(ads_data: str) -> dict:
    """Parse the ADS data portion of an AMS response.

    Args:
        ads_data: Hex string of ADS data.

    Returns:
        Dictionary with ErrorCode and ADSData fields.
    """
    error_code = reverse_bytes(ads_data[0:8])
    if len(ads_data) == 8:
        return {"ErrorCode": error_code, "ADSData": ""}

    data_len = int(reverse_bytes(ads_data[8:16]), 16) * 2
    return {
        "ErrorCode": error_code,
        "ADSData": ads_data[16 : 16 + data_len],
    }


def build_local_netid(local_ip: str) -> str:
    """Build a local AMS Net ID hex string from an IP.

    Converts IP to hex and appends '.1.1' equivalent.

    Args:
        local_ip: Local IP address string.

    Returns:
        12-character hex string for AMS Net ID.
    """
    return ip_to_hex(local_ip) + "0101"
