# 🛡️ TrackerControl PC & Linux — Sovereign Edition

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue.svg)](https://github.com/TrackerControl/trackercontrol-pc)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://python.org)
[![Architecture](https://img.shields.io/badge/Architecture-x86__64-orange.svg)](#downloads--packages)

> **A specialized, high-performance desktop port and evolution of [TrackerControl](https://github.com/TrackerControl) designed for Windows and all Linux Distributions.**

TrackerControl on Android popularized per-app tracker visibility and blocking using local VPN loopback. However, **desktop computers are an even larger surveillance blindspot**: desktop applications (Discord, Spotify, Steam, Chrome, Slack, VS Code, Electron apps, games) and operating systems (Windows DiagTrack, Ubuntu Whoopsie, Red Hat Insights) transmit massive volumes of behavioral telemetry, analytics, and device fingerprinting that **browser adblockers (like uBlock Origin) are completely blind to**.

**TrackerControl PC** bridges this gap by bringing deep process attribution, multi-tier threat intelligence, cross-platform kernel firewall enforcement, multi-tunnel WireGuard, Proton VPN, and Tor/Orbot integration directly to your workstation.

---

## 📦 Downloads & Proper Release Packages

Pre-built standalone releases with bundled Python runtime, threat database, and assets are available in [`dist/`](dist/):

| OS / Distribution | Package Type | File | Description |
|---|---|---|---|
| **Windows 10 / 11** | Standalone Executable | [`TrackerControl-PC.exe`](dist/TrackerControl-PC.exe) | Single-file portable executable (17.4 MB) |
| **Windows 10 / 11** | Release ZIP | [`TrackerControl-PC-v1.0.0-Windows-x64.zip`](dist/TrackerControl-PC-v1.0.0-Windows-x64.zip) | Portable bundle with batch launcher (17.2 MB) |
| **Debian / Ubuntu / Mint** | Native `.deb` | [`trackercontrol_1.0.0_amd64.deb`](dist/linux/trackercontrol_1.0.0_amd64.deb) | Native Debian package with systemd & desktop integration (19.5 MB) |
| **Universal Linux** | Standalone Binary | [`trackercontrol-linux`](dist/linux/trackercontrol-linux) | Native 64-bit ELF standalone executable (19.7 MB) |
| **Universal Linux** | Portable Tarball | [`trackercontrol-v1.0.0-linux-x86_64.tar.gz`](dist/linux/trackercontrol-v1.0.0-linux-x86_64.tar.gz) | Complete bundle with `install.sh` and `uninstall.sh` (19.5 MB) |
| **Arch Linux / Manjaro** | PKGBUILD | [`packaging/arch/PKGBUILD`](packaging/arch/PKGBUILD) | AUR / Arch build recipe |
| **Fedora / RHEL / openSUSE** | RPM Spec | [`packaging/rpm/trackercontrol.spec`](packaging/rpm/trackercontrol.spec) | RPM packaging specification |

---

## 🐧 Full Linux Distribution & Windows Support

TrackerControl PC is engineered to run seamlessly across all major operating systems and distributions:

* **Debian Family**: Ubuntu, Debian, Linux Mint, Pop!_OS, Kali Linux, Elementary OS
* **Red Hat Family**: Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux
* **Arch Family**: Arch Linux, Manjaro, EndeavourOS, Artix
* **SUSE Family**: openSUSE (Leap & Tumbleweed)
* **Lightweight / Musl**: Alpine Linux, Void Linux
* **Windows**: Windows 10 & Windows 11 (x64 / ARM64)

### Cross-Platform Matrix

| Feature | Windows | Linux (All Distros) |
|---|---|---|
| **Process Attribution** | Windows Network Sockets & `iphlpapi` | `/proc` socket inodes & `psutil` kernel tracking |
| **App Discovery** | Windows Registry & `%LocalAppData%\Programs` | Freedesktop `.desktop` specs, Flatpaks, Snaps, & `/usr/bin` |
| **Firewall Engine** | Windows Advanced Firewall (`netsh`) | `iptables`, `nftables`, `ufw`, or `firewalld` (with owner match) |
| **OS Privacy Debloater** | DiagTrack, dmwappushservice, Advertising ID | `whoopsie`, `apport`, `popularity-contest`, `ubuntu-report`, `abrt` |
| **WireGuard VPN** | Wintun / WireGuard Windows Service | Standard `wg-quick` & Linux kernel WireGuard module |
| **Orbot / Tor** | Local SOCKS5 (`9050`) & ControlPort (`9051`) | Native Tor daemon / SOCKS5 (`9050`) & ControlPort (`9051`) |
| **Port Forwarding** | Async Python Stream Relay + Netsh PortProxy | Async Python Stream Relay + Linux `iptables` NAT |

---

## ⚡ Why TrackerControl PC is Way More Powerful

| Capability | TrackerControl (Android) | TrackerControl PC (Sovereign) |
|---|---|---|
| **Monitoring Scope** | Android apps only (VPNService sandbox) | **Every PC process** (Spotify, Discord, Games, Steam, VS Code, OS services) |
| **Process Attribution** | Limited UID mapping | **Full PID, Executable Path, Process Tree, & Parent Process correlation** |
| **OS Telemetry Neutralizer** | ❌ N/A | **Native DiagTrack / Advertising ID killer (Windows) & Whoopsie/Apport/Popcon silencer (Linux)** |
| **Enforcement Engine** | User-space Android VPNService | **Dual-Engine: High-speed DNS Sinkhole (0.0.0.0) + Kernel-level Firewall (`iptables`/`nftables`/`netsh`)** |
| **Threat Intelligence** | Exodus Privacy + Disconnect | **4,500+ Signatures: Exodus Privacy + Disconnect.me + WindowsSpyBlocker + DuckDuckGo Radar** |
| **Multi-Tunnel WireGuard** | ❌ Single tunnel | **Concurrent multi-tunnel manager with live Rx/Tx speedometers** |
| **Proton VPN Fleet** | ❌ N/A | **Direct Proton credential vault & verified global server deployment** |
| **Split Tunneling** | Basic app selection | **Per-app granular routing: WireGuard Tunnel vs Orbot/Tor vs Clearnet Bypass vs Complete Block** |
| **Real-Time Stream** | Mobile list view | **Cyber-dark reactive desktop dashboard with sub-second WebSocket live waterfall** |
| **Port Forwarding** | ❌ N/A | **TCP/UDP port forwarder with WireGuard, Orbot relay, and P2P torrent presets** |

---

## 🚀 Installation & Quickstart

### 🐧 On Linux

#### 1. Debian / Ubuntu / Linux Mint / Pop!_OS (`.deb`)
```bash
sudo dpkg -i dist/linux/trackercontrol_1.0.0_amd64.deb
sudo trackercontrol
```

#### 2. Universal Standalone Tarball (Any Linux Distro)
```bash
tar -xzf dist/linux/trackercontrol-v1.0.0-linux-x86_64.tar.gz
cd trackercontrol-1.0.0
sudo ./install.sh
```

#### 3. Standalone Binary Launch
```bash
chmod +x dist/linux/trackercontrol-linux
sudo ./dist/linux/trackercontrol-linux
```
*(Or run `sudo ./start_trackercontrol.sh`)*

---

### 🪟 On Windows

* **Direct Executable**: Double-click or run:
  ```powershell
  .\dist\TrackerControl-PC.exe
  ```
* **Or via Batch Launcher**:
  ```powershell
  .\start_trackercontrol.bat
  ```

---

### 🌐 Open the Control Center

Navigate to **`http://localhost:8000`** in any web browser to access:
* **Live Tracker Radar**: Sub-second waterfall of all outbound sockets, process attribution, categories, and block status.
* **App Privacy Matrix**: Privacy health cards for every application with 1-click toggles:
  * ➕ **System Installed App Picker**: Browse and select from all applications on your system (Linux `.desktop`, Flatpaks, Snaps, and Windows Registry). Configure proactive protection before apps even launch!
  * 🛡️ *Block Trackers Only*: The application functions normally, while telemetry and ads are silently neutralized.
  * 🛑 *Block All Internet*: Instantly blocks all outbound network access for that executable via kernel firewall.
  * 🟢 *Allow All Traffic*: Whitelist mode.
  * 📁 *Custom Binary / Executable Path*: Add portable or unregistered apps by entering their path directly.
* **WireGuard & Proton VPN Engine**:
  * 🔗 **Multi-Tunnel WireGuard Concurrency**: Run and monitor multiple concurrent WireGuard connections simultaneously with live speedometers (Rx/Tx kbps and total MB transferred).
  * ⚛️ **Direct Proton VPN Integration**: Configure Proton WireGuard credentials (PrivateKey, Address, Plan tier, or auto-parse `.conf`). Browse the global Proton server fleet (Free & Plus across Netherlands, US, Japan, Switzerland, Germany, UK, etc.) and deploy tunnels with one click.
  * 🔀 **TrackerControl-Style Split Tunneling**: Choose how each desktop application routes its network traffic:
    * `🛡️ WireGuard Tunnel` (Route via specific Proton or custom tunnel)
    * `🧅 Orbot / Tor` (Route via The Onion Router)
    * `🌐 Clearnet Bypass` (Direct clearnet connection, bypassing all VPNs)
    * `🛑 Block All Traffic` (Full isolation)
  * 🧅 **Built-in Orbot / Tor Gateway**: Detects local Orbot/Tor SOCKS5 (`9050`/`9150`), ControlPort (`9051`), and HTTP proxies (`8118`). Features one-click Tor circuit cycling (`SIGNAL NEWNYM`) and `.onion` resolution.
  * 🔀 **Port Forwarding Engine**: Dual-mode TCP/UDP port forwarding (Async Python Stream Relay + OS Kernel Forwarding). Built-in presets for WireGuard (51820), Orbot (9055 &rarr; 9050), and P2P torrent ports.
* **OS Privacy Debloater**: One-click toggles for Windows diagnostics (`DiagTrack`, Advertising ID) and Linux telemetry services (`whoopsie`, `apport`, `popularity-contest`, `ubuntu-report`, `abrt`, `insights-client`).
* **Corporate Intel**: Breakdown of data harvested by Alphabet, Meta, Microsoft, ByteDance, Adobe, Amazon, etc.
* **Custom Rules**: Add custom domain wildcards (`*.telemetry.*`) or IP blocks.

---

## 📁 Repository Structure

```
trackercontrol-pc/
├── .github/
│   └── workflows/
│       └── release.yml          # GitHub Actions CI/CD for auto-building releases
├── backend/
│   ├── platform_helper.py       # OS detection & Linux distro parser (/etc/os-release)
│   ├── database.py              # SQLite persistent connection history & app profiles
│   ├── tracker_intelligence.py  # 4,500+ Exodus, WindowsSpyBlocker, Disconnect.me signatures
│   ├── process_monitor.py       # Real-time socket & PID attribution scanner (Linux & Windows)
│   ├── dns_proxy.py             # Async DNS server & 0.0.0.0 sinkhole
│   ├── firewall_enforcer.py     # Cross-platform firewall (iptables/nftables/netsh) & OS debloater
│   ├── app_discovery.py         # App discovery (Freedesktop .desktop, Flatpak, Snap, Registry)
│   ├── wireguard_manager.py     # Multi-tunnel WireGuard (wg-quick, iproute2, Windows Service)
│   ├── proton_service.py        # Proton VPN credentials, server fleet & conf parser
│   ├── orbot_service.py         # Orbot / Tor Onion routing & ControlPort circuit cycling
│   ├── port_forwarder.py        # Async TCP/UDP stream forwarder & OS portproxy
│   ├── engine.py                # Core event bus & WebSocket orchestrator
│   └── server.py                # FastAPI REST & WebSocket server
├── frontend/
│   ├── index.html               # Cyber-dark glassmorphic control center
│   ├── styles.css               # Futuristic cyberpunk styling & responsive layouts
│   └── app.js                   # WebSocket client, radar stream & app matrix controller
├── packaging/
│   ├── arch/PKGBUILD            # Arch Linux package specification
│   ├── rpm/trackercontrol.spec  # Fedora / RHEL RPM specification
│   ├── assets/trackercontrol.svg# Scalable application icon
│   ├── trackercontrol.desktop   # Freedesktop application entry
│   └── package_linux_releases.sh# Master Linux release builder
├── data/
│   ├── trackers.json            # Curated tracker database (4,541 entries)
│   ├── companies.json           # Corporate intelligence profiles
│   └── windows_telemetry.json   # Known OS telemetry signatures
├── dist/                        # Standalone pre-compiled releases
│   ├── TrackerControl-PC.exe
│   ├── TrackerControl-PC-v1.0.0-Windows-x64.zip
│   ├── trackercontrol-v1.0.0-linux-x86_64.tar.gz
│   └── linux/
│       ├── trackercontrol-linux
│       └── trackercontrol_1.0.0_amd64.deb
├── main.py                      # Application bootstrap
├── requirements.txt             # Python dependencies
├── start_trackercontrol.sh      # Universal Linux launcher
├── start_trackercontrol.bat     # Windows launcher (with UTF-8 fix)
├── install_linux.sh             # Linux daemon installer
├── trackercontrol.service       # Linux systemd service unit
├── CONTRIBUTING.md              # Open source contribution guide
├── SECURITY.md                  # Security and vulnerability reporting
├── LICENSE                      # MIT License
└── .gitignore                   # Production git exclusion rules
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE) — see the [LICENSE](LICENSE) file for details.
