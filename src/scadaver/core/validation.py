"""Input validation helpers used across all vendor modules."""

import re


def is_ipv4(ip: str) -> bool:
    """Validate an IPv4 address string.

    Args:
        ip: Dotted-decimal IPv4 address string.

    Returns:
        True if the string is a valid IPv4 address with a non-zero first octet.
    """
    match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
    if not match:
        return False
    octets = [int(n) for n in match.groups()]
    if octets[0] < 1:
        return False
    return all(0 <= n <= 255 for n in octets)


def require_ipv4(ip: str) -> str:
    """Validate and return an IPv4 address, raising on failure.

    Args:
        ip: Dotted-decimal IPv4 address string.

    Returns:
        The validated IP string.

    Raises:
        SystemExit: If the IP is not valid.
    """
    if not is_ipv4(ip):
        raise SystemExit(f"Invalid IPv4 address: {ip}")
    return ip
