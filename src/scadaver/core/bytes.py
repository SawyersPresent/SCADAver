"""Byte-manipulation helpers shared across vendor modules."""


def reverse_bytes(data: str | bytes) -> str | bytes:
    """Reverse byte pairs in a hex string or bytes object.

    Input ``b'12345678'`` becomes ``b'78563412'``.
    Input ``'12345678'`` becomes ``'78563412'``.

    Args:
        data: Hex-encoded string or bytes to reverse pairwise.

    Returns:
        The byte-reversed result in the same type as the input.
    """
    if isinstance(data, bytes):
        return b"".join(
            [data[x : x + 2] for x in range(0, len(data), 2)][::-1]
        )
    return "".join(
        [data[x : x + 2] for x in range(0, len(data), 2)][::-1]
    )


def ip_to_hex(ip: str) -> str:
    """Convert a dotted-decimal IPv4 address to a hex string.

    ``'192.168.1.1'`` becomes ``'c0a80101'``.

    Args:
        ip: Dotted-decimal IPv4 address.

    Returns:
        8-character lowercase hex string.
    """
    return "".join(hex(int(octet))[2:].zfill(2) for octet in ip.split("."))


def hex_to_ip(hexstr: str) -> str:
    """Convert an 8-character hex string to a dotted-decimal IPv4 address.

    ``'c0a80101'`` becomes ``'192.168.1.1'``.

    Args:
        hexstr: 8-character hex string representing 4 octets.

    Returns:
        Dotted-decimal IPv4 string.
    """
    return ".".join(str(int(hexstr[i : i + 2], 16)) for i in range(0, len(hexstr), 2))


def get_netid_as_string(hex_netid: str) -> str:
    """Convert a hex AMS Net ID to dotted-decimal notation.

    ``'c0a80101c801'`` becomes ``'192.168.1.1.200.1'``.

    Args:
        hex_netid: 12-character hex string (6 bytes).

    Returns:
        Dotted-decimal AMS Net ID string.
    """
    parts = []
    for i in range(0, len(hex_netid), 2):
        parts.append(str(int(hex_netid[i : i + 2], 16)))
    return ".".join(parts)


def invert_hex_string(hex_input: str) -> str:
    """Swap endianness of a hex string by reversing byte pairs.

    ``'01020304'`` becomes ``'04030201'``.

    Args:
        hex_input: Even-length hex string.

    Returns:
        Byte-swapped hex string.
    """
    inverted = ""
    for x in range(-1, -len(hex_input), -2):
        inverted += hex_input[x - 1] + hex_input[x]
    return inverted


def convert_to_int(raw: bytes, inverted: bool = True) -> int:
    """Convert raw bytes to an integer, optionally byte-swapping first.

    Args:
        raw: Raw bytes to convert.
        inverted: If True (default), reverse byte order before conversion.

    Returns:
        Integer value.
    """
    if inverted:
        return int(invert_hex_string(raw.hex()), 16)
    return int(raw.hex(), 16)
