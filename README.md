# netscan

[![GitHub release](https://img.shields.io/badge/version-1.0-blue?style=flat-square)](https://github.com/karanikn/netscan)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1-blue?style=flat-square&logo=powershell)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20%7C%20Server-lightgrey?style=flat-square&logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](https://github.com/karanikn/netscan/blob/main/LICENSE)
[![AI Assisted](https://img.shields.io/badge/built%20with-Claude%20AI-orange?style=flat-square)](https://claude.ai)

> **A WinForms PowerShell network scanner with DHCP rogue detection, port scanning, OUI vendor lookup, Ping Monitor, and Traceroute — powered by nmap.**  
> Single-file PowerShell script — no installation required.

---

## ✨ Overview

**netscan** is a Windows GUI network scanner built in PowerShell + WinForms. It scans subnets for live hosts, identifies their MAC addresses and NIC vendors, detects unauthorized (rogue) DHCP servers by listening on UDP/67, and performs configurable TCP/UDP port scans — all in the background via `Start-Job` so the UI stays responsive.

From the right-click context menu on any result row you can open a **Ping Monitor** window, run a **Traceroute**, or directly **connect via RDP** to the selected host.

A built-in **Settings dialog** lets you define custom port lists and configure general scan behaviour. 

---

## 📸 Screenshots

| Main |
|:---:|
| ![Main](https://raw.githubusercontent.com/karanikn/netscan/main/Screenshots/netscan_main.png) |

| Ping Monitor | Traceroute |
|:---:|:---:|
| ![Ping Monitor](https://raw.githubusercontent.com/karanikn/netscan/main/Screenshots/netscan_ping-monitor.png) | ![Traceroute](https://raw.githubusercontent.com/karanikn/netscan/main/Screenshots/netscan_traceroute.png) |

| Settings — General | Settings — Ports |
|:---:|:---:|
| ![Settings General](https://raw.githubusercontent.com/karanikn/netscan/main/Screenshots/netscan_settings-General.png) | ![Settings Ports](https://raw.githubusercontent.com/karanikn/netscan/main/Screenshots/netscan_settings-Ports.png) |

---

## 🚀 Quick Start

### Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1 (built into Windows 10/11/Server) |
| .NET Framework | 4.5 or later (pre-installed on modern Windows) |
| nmap | Downloaded automatically on first run if not found |
| Administrator | Required — script self-elevates via UAC |

### Running the script

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\netscan.ps1
```

> **Note:** The script requires administrator privileges. If not already elevated, it will prompt for UAC elevation automatically on launch.

On first run, netscan checks for `nmap` in the script directory. If not found, it offers to download **nmap 7.92** portable automatically. It also checks for the **IEEE OUI database** (`oui.txt`) used for NIC vendor lookup — if missing or older than 90 days it prompts to download an updated copy.

---

## 🖥️ Interface

The main window is divided into three panels:

- **Top panel** — Scan results grid with columns for IP, Hostname, MAC Address, NIC Vendor, and any detected open ports
- **Bottom-left panel** — Live scan log with timestamped output from nmap and DHCP listener
- **Bottom-right panel** — Network interface information for the local machine

---

## ⚙️ Features

### Scan Engine

| Feature | Description |
|---|---|
| Host Discovery | ARP sweep + nmap ping scan to detect all live hosts on the subnet |
| MAC Address | Resolved from ARP table for each discovered host |
| NIC Vendor | Looked up from the IEEE OUI database (`oui.txt`) |
| Hostname Resolution | Reverse DNS lookup for each live host |
| Port Scanning | Configurable TCP/UDP port scan via nmap |
| DHCP Rogue Detection | Listens on UDP/67 for DHCP broadcast responses; flags unauthorized servers |
| Background Execution | All scans run via `Start-Job` — UI never freezes |
| CSV Export | Export full scan results to CSV with one click |

### Context Menu (Right-click on result row)

| Action | Description |
|---|---|
| Ping Monitor | Opens a live ping graph window for the selected host |
| Traceroute | Opens a hop-by-hop traceroute window for the selected host |
| Connect via RDP | Launches `mstsc.exe /v:<host>` directly |
| Copy IP | Copies the selected host's IP address to clipboard |
| Copy All (row) | Copies the full result row as tab-separated text |

### Ping Monitor Window

| Feature | Description |
|---|---|
| Continuous Ping | Pings target host at configurable intervals |
| Live Graph | Scrolling RTT graph with min/avg/max display |
| Packet Loss | Running count of timeouts |
| Stop / Restart | Start and stop monitoring at any time |

### Traceroute Window

| Feature | Description |
|---|---|
| Hop-by-hop trace | Runs `tracert` to the target host |
| Live output | Results appear line by line as the trace progresses |
| Stop button | Cancel a long-running trace mid-way |

### Settings Dialog

| Tab | Options |
|---|---|
| General | Scan timeout, ping count, thread limits, DHCP listener toggle |
| Ports | Define custom port lists for TCP and UDP scanning |

---

## 📁 File Structure

```
netscan/
├── netscan.ps1          # Main script
├── netscan.exe          # exe file
├── netscan.ico          # icon
├── oui.txt              # IEEE OUI database (auto-downloaded on first run)
├── nmap/                # nmap binaries (auto-downloaded on first run)
│   └── nmap.exe
├── Screenshots/
│   ├── netscan_main.png
│   ├── netscan_ping-monitor.png
│   ├── netscan_settings-General.png
│   ├── netscan_settings-Ports.png
│   └── netscan_traceroute.png
├── LICENSE
└── README.md
```

---

## 📋 Changelog

### v1.0 — June 2026 *(public release — renamed to netscan)*

- Renamed project from `DHCP-RogueDetector` to **netscan** for public release
- Added **Settings dialog** with General and Ports tabs for runtime configuration
- Finalized UI layout: results grid (top), scan log + network info (bottom split)

---

### v0.6 — June 2026

- Added **Ping Monitor** standalone window with live RTT graph, launched from context menu
- Added **Traceroute** standalone window with live hop output, launched from context menu
- **Connect via RDP**: direct `Start-Process mstsc.exe /v:<host>` launch (previously copied to clipboard)
- Fixed event handler closures using `.GetNewClosure()` on all WinForms handler scriptblocks
- Moved helper functions to top-level script scope for reliable resolution from event handlers
- Fixed `Register-ObjectEvent -Action` variable passing — switched from `$using:` to `-MessageData`

---

### v0.5 — June 2026

- Added **right-click context menu** on results grid: Copy IP, Copy All (row), RDP, Ping Monitor, Traceroute
- Added **double-click to copy** row behaviour
- Updated nmap auto-download: portable zip 7.92 with retry/backoff; falls back to silent NSIS installer 7.99 if portable fails
- Installer extracts to `nmap/` subfolder next to the script

---

### v0.4 — June 2026

- Fixed DHCP **false-positive rogue detection**: removed `--open` nmap flag so only definitive `67/udp open` results are flagged (not ambiguous `open|filtered`)
- Added **NIC Vendor** column using IEEE OUI database (`oui.txt`)
- OUI file check on startup: prompts to download if missing or older than 90 days
- OUI download uses retry/backoff with browser-like headers to avoid HTTP 418 bot-protection responses; falls back to linuxnet.ca mirror

---

### v0.3 — June 2026 *(WinForms migration)*

- Full rewrite from WPF to **WinForms** for better stability and event model reliability
- Split-panel layout: scan results (top), scan log (bottom-left), network info (bottom-right)
- Migrated to **`Start-Job`** background execution architecture — scan output polled via `DispatcherTimer`-equivalent
- `SplitterDistance` and `Panel1MinSize`/`Panel2MinSize` set correctly after controls added to form
- Fixed WinForms Dock stacking rule (Fill first, then Top controls in reverse visual order)

---

### v0.2 — June 2026

- Added **Light / Dark theme engine** with toggle button
- Version label displayed in status bar
- Improved scan output formatting and column alignment
- Minor layout and UX polish

---

### v0.1 — June 2026 *(initial version)*

- Initial WPF GUI with **admin elevation** via inline C# (`ProcessStartInfo` + `runas`)
- **DHCP rogue detection** via UDP/67 broadcast listener
- **nmap integration**: checks for nmap, auto-downloads portable zip if not found
- Basic host discovery: ARP sweep + ping
- Results grid: IP, MAC address, hostname
- Scan log panel with timestamped nmap output

---

## 👤 Author

**Nikolaos Karanikolas**  
[karanik.gr](https://karanik.gr)

---

## 🤖 AI Assistance

This project was built with assistance from **Claude AI** by [Anthropic](https://www.anthropic.com).

---

## ⚠️ Disclaimer

netscan is intended for use by network administrators on networks they own or have explicit permission to scan. Unauthorized network scanning may be illegal in your jurisdiction. The author accepts no responsibility for misuse.

Always verify that network scanning is permitted by your organization's policies before use.
