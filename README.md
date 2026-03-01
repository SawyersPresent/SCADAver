# SCADAVER

Unified ICS/SCADA security toolkit consolidating 16 vendor scripts into a single installable Python package with a CLI and interactive menu.

Supports: **Beckhoff**, **Siemens**, **Schneider**, **Mitsubishi**, **Phoenix Contact**, **eWON**, **EtherNet/IP**, **Rockwell Allen-Bradley (Logix)**

---

## Installation

### pip / uv (recommended)

**System-wide (Linux, requires root):**

```bash
sudo pip install .
# scadaver is now at /usr/local/bin/scadaver
scadaver --help
```

**User install (no root) — most common on Linux:**

```bash
pip install --user .
# Script lands at ~/.local/bin/scadaver
# If not found, add it to PATH:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
scadaver --help
```

**With [uv](https://github.com/astral-sh/uv) (faster, recommended):**

```bash
uv venv
source .venv/bin/activate
uv pip install .
scadaver --help
```

Or without activating:

```bash
uv venv
uv pip install .
uv run scadaver --help
```

**No install — run as a module directly:**

```bash
python -m scadaver --help
```

**With ARP/route-spoofing support (Linux only, requires scapy + root):**

```bash
sudo pip install ".[spoof]"
# or
uv pip install ".[spoof]"
```

---

### pipx (isolated install, no venv management)

[pipx](https://pipx.pypa.io/) installs CLI tools into their own isolated environments and puts the entry point on your PATH automatically — no venv activation needed.

```bash
# Install pipx if you don't have it
pip install --user pipx
pipx ensurepath   # adds ~/.local/bin to PATH (re-open shell after)

# Install scadaver from the repo directory
pipx install .

scadaver --help
```

With ARP/route-spoofing support:

```bash
pipx install ".[spoof]"
```

To upgrade after pulling changes:

```bash
pipx reinstall scadaver
```

To remove:

```bash
pipx uninstall scadaver
```

> **Note (Windows):** Siemens Profinet DCP discovery requires [Npcap](https://npcap.com/) installed in **WinPcap-compatible mode**.

---

### Docker

Build the image:

```bash
docker build -t scadaver .
```

Run any command:

```bash
docker run --rm --network host scadaver scan enip
docker run --rm --network host scadaver --help
```

> `--network host` is required so the container can send/receive broadcast packets on your local network interfaces. On Linux this works natively. On Windows/macOS, use a Linux VM or WSL2.

---

## Usage

```
scadaver [OPTIONS] COMMAND [ARGS]...
```

### Scan

```bash
scadaver scan enip          # EtherNet/IP UDP broadcast discovery
scadaver scan ewon          # eWON device discovery
scadaver scan schneider     # Schneider PLC broadcast scan
scadaver scan mitsubishi    # Mitsubishi GX Works broadcast scan
scadaver scan beckhoff      # Beckhoff ADS UDP discovery
scadaver scan siemens       # Siemens Profinet DCP + S7Comm scan
```

### Control

```bash
scadaver control mitsubishi   # RUN/STOP/PAUSE Mitsubishi PLC
scadaver control phoenix      # Read/revert Phoenix Contact CPU state
scadaver control siemens-io   # Read I/O and write outputs on Siemens S7
scadaver control siemens-cpu  # Change Siemens CPU run state
scadaver control beckhoff-tc  # Set Beckhoff TwinCAT run state
```

### Exploit

```bash
scadaver exploit ewon-creds         # Retrieve eWON credentials (CVE auth bypass)
scadaver exploit schneider-flash    # Flash Schneider PLC LED
scadaver exploit schneider-hijack   # Session hijack CVE-2017-6026
scadaver exploit phoenix-passwords  # Retrieve WebVisit passwords (CVE-2016-8366)
scadaver exploit phoenix-tags       # Get/set HMI tag values (CVE-2016-8380)
scadaver exploit beckhoff-reboot    # Reboot Beckhoff PLC via UPnP/SOAP
scadaver exploit beckhoff-user      # Add admin user to Beckhoff web interface
scadaver exploit beckhoff-route-spoof  # ADS route brute-force via ARP spoofing (Linux)
```

### Rockwell Allen-Bradley Logix

Requires a Logix PLC reachable over EtherNet/IP. Tag lists are cached under `data/` (keyed by PLC IP).

```bash
# Discover and list all tags
scadaver rockwell tags -t 192.168.1.10

# Re-discover (bypass cache)
scadaver rockwell tags -t 192.168.1.10 --refresh

# Read all tags
scadaver rockwell read -t 192.168.1.10

# Read a single tag
scadaver rockwell read -t 192.168.1.10 Program:MainProgram.MyTag

# Write one or more tags (TAG=value pairs)
scadaver rockwell write -t 192.168.1.10 Program:MainProgram.Counter=42
scadaver rockwell write -t 192.168.1.10 TagA=true TagB=3.14

# Live TUI monitor — polls every N seconds, highlights changes yellow
scadaver rockwell monitor -t 192.168.1.10
scadaver rockwell monitor -t 192.168.1.10 -i 2.0

# Interactive TUI editor — select tag by number, stage writes, commit with w
scadaver rockwell edit -t 192.168.1.10

# View change history (last N events)
scadaver rockwell history -t 192.168.1.10
scadaver rockwell history -t 192.168.1.10 -n 50
```

### Interactive menu

Running `scadaver` with no arguments launches a numbered interactive menu. Rockwell scan and control are included in the respective sub-menus:

```bash
scadaver
```

---

## Legacy scripts

The original standalone scripts are preserved in [`legacy/`](legacy/) for reference. The CVE-specific scripts are in [`legacy/CVEs/`](legacy/CVEs/).

---

## Credits

By [sawyerspresent](https://github.com/tijldeneut/ICSSecurityScripts).
