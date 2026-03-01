# ICSSecurityScripts / icstool

Unified ICS/SCADA security toolkit consolidating 16 vendor scripts into a single installable Python package with a CLI and interactive menu.

Supports: **Beckhoff**, **Siemens**, **Schneider**, **Mitsubishi**, **Phoenix Contact**, **eWON**, **EtherNet/IP**

---

## Installation

### pip / uv (recommended)

**System-wide (Linux, requires root):**

```bash
sudo pip install .
# icstool is now at /usr/local/bin/icstool
icstool --help
```

**User install (no root) — most common on Linux:**

```bash
pip install --user .
# Script lands at ~/.local/bin/icstool
# If not found, add it to PATH:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
icstool --help
```

**With [uv](https://github.com/astral-sh/uv) (faster, recommended):**

```bash
uv venv
source .venv/bin/activate
uv pip install .
icstool --help
```

Or without activating:

```bash
uv venv
uv pip install .
uv run icstool --help
```

**No install — run as a module directly:**

```bash
python -m icstool --help
```

**With ARP/route-spoofing support (Linux only, requires scapy + root):**

```bash
sudo pip install ".[spoof]"
# or
uv pip install ".[spoof]"
```

> **Note (Windows):** Siemens Profinet DCP discovery requires [Npcap](https://npcap.com/) installed in **WinPcap-compatible mode**.

---

### Docker

Build the image:

```bash
docker build -t icstool .
```

Run any command:

```bash
docker run --rm --network host icstool scan enip
docker run --rm --network host icstool --help
```

> `--network host` is required so the container can send/receive broadcast packets on your local network interfaces. On Linux this works natively. On Windows/macOS, use a Linux VM or WSL2.

---

## Usage

```
icstool [OPTIONS] COMMAND [ARGS]...
```

### Scan

```bash
icstool scan enip          # EtherNet/IP UDP broadcast discovery
icstool scan ewon          # eWON device discovery
icstool scan schneider     # Schneider PLC broadcast scan
icstool scan mitsubishi    # Mitsubishi GX Works broadcast scan
icstool scan beckhoff      # Beckhoff ADS UDP discovery
icstool scan siemens       # Siemens Profinet DCP + S7Comm scan
```

### Control

```bash
icstool control mitsubishi   # RUN/STOP/PAUSE Mitsubishi PLC
icstool control phoenix      # Read/revert Phoenix Contact CPU state
icstool control siemens-io   # Read I/O and write outputs on Siemens S7
icstool control siemens-cpu  # Change Siemens CPU run state
icstool control beckhoff-tc  # Set Beckhoff TwinCAT run state
```

### Exploit

```bash
icstool exploit ewon-creds         # Retrieve eWON credentials (CVE auth bypass)
icstool exploit schneider-flash    # Flash Schneider PLC LED
icstool exploit schneider-hijack   # Session hijack CVE-2017-6026
icstool exploit phoenix-passwords  # Retrieve WebVisit passwords (CVE-2016-8366)
icstool exploit phoenix-tags       # Get/set HMI tag values (CVE-2016-8380)
icstool exploit beckhoff-reboot    # Reboot Beckhoff PLC via UPnP/SOAP
icstool exploit beckhoff-user      # Add admin user to Beckhoff web interface
icstool exploit beckhoff-route-spoof  # ADS route brute-force via ARP spoofing (Linux)
```

### Interactive menu

Running `icstool` with no arguments launches a numbered interactive menu:

```bash
icstool
```

---

## Legacy scripts

The original standalone scripts are preserved in [`legacy/`](legacy/) for reference. The CVE-specific scripts are in [`legacy/CVEs/`](legacy/CVEs/).

---

## Credits

Original scripts by [Tijl Deneut](https://github.com/tijldeneut/ICSSecurityScripts)
