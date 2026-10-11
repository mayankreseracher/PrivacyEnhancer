# 🛡️ TrackerControl PC & Linux — Sovereign Edition

> **A specialized, high-performance desktop port and evolution of [TrackerControl](https://github.com/TrackerControl) designed for Windows and all Linux Distributions.**

TrackerControl on Android popularized per-app tracker visibility and blocking using local VPN loopback. However, **desktop computers are an even larger surveillance blindspot**: desktop apps (Discord, Spotify, Steam, Chrome, Slack, VS Code, Electron apps, games) and operating systems (Windows DiagTrack, Ubuntu Whoopsie, Red Hat Insights, etc.) transmit massive volumes of behavioral telemetry, analytics, and device fingerprinting that **browser adblockers (like uBlock Origin) are completely blind to**.

**TrackerControl PC** bridges this gap by bringing deep process attribution, multi-tier threat intelligence, cross-platform firewall enforcement, multi-tunnel WireGuard, Proton VPN, and Tor/Orbot integration directly to your workstation.

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

## 🚀 Quickstart & Usage

### 🐧 Running on Linux

#### Option A: Quick Run
Make the launcher executable and launch:
```bash
chmod +x start_trackercontrol.sh
sudo ./start_trackercontrol.sh
```
*(Running with `sudo` gives TrackerControl access to kernel-level socket inspection and `iptables`/`nftables` packet filtering).*

#### Option B: Install as a Persistent System Daemon
```bash
chmod +x install_linux.sh
sudo ./install_linux.sh
```
This automatically installs prerequisites (`wireguard-tools`, `iptables`), copies the project to `/opt/trackercontrol-pc`, and enables the systemd service:
```bash
sudo systemctl status trackercontrol
sudo systemctl restart trackercontrol
```

---

### 🪟 Running on Windows

Run the one-click Windows launcher:
```powershell
.\start_trackercontrol.bat
```
Or start manually:
```powershell
python main.py
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

## 📁 Project Structure

```
trackercontrol-pc/
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
├── data/
│   ├── trackers.json            # Curated tracker database (4,541 entries)
│   ├── companies.json           # Corporate intelligence profiles
│   └── trackercontrol.db        # SQLite live event store
├── packaging/
│   ├── linux/
│   │   ├── trackercontrol.desktop  # Freedesktop XDG desktop launcher with icon
│   │   ├── trackercontrol.svg      # Vector high-res cyberpunk shield application icon
│   │   └── build_deb.sh            # Debian/Ubuntu .deb package generator
│   └── package_releases.py         # Universal release bundler for Windows and Linux
├── .github/workflows/
│   └── release.yml                 # Automated GitHub Actions multi-platform release CI/CD
├── TrackerControl.spec             # PyInstaller standalone binary compilation specification
├── build_linux.sh                  # One-click Linux ELF binary compiler
├── main.py                         # Application bootstrap & entrypoint
├── requirements.txt                # Python cross-platform dependencies
├── start_trackercontrol.sh         # Universal Linux developer launcher
├── install_linux.sh                # Linux systemd auto-installer
├── trackercontrol.service          # Linux systemd unit file
└── start_trackercontrol.bat        # Windows one-click launcher
```

---

## 📦 Distribution Packages & Installation

TrackerControl PC provides official pre-compiled standalone releases that **do not require Python to be installed on the host**:

### 🐧 Linux Distributions

#### 1. Debian, Ubuntu, Mint, Pop!_OS, Kali (`.deb`)
Download `trackercontrol_1.0.0_amd64.deb` from Releases and install via `dpkg` or `apt`:
```bash
sudo dpkg -i trackercontrol_1.0.0_amd64.deb
# or
sudo apt-get install ./trackercontrol_1.0.0_amd64.deb
```
This installs:
- Executable in `/opt/trackercontrol-pc/trackercontrol-linux`
- Symlink in `/usr/local/bin/trackercontrol`
- Desktop shortcut in your application launcher with full icon and menu integration (`trackercontrol.desktop`)
- Systemd service (`trackercontrol.service`)

#### 2. Universal Linux Standalone (`.tar.gz`)
Works on **Arch Linux, Fedora, openSUSE, Alpine, Void, RHEL, and Debian**:
```bash
tar -xzf trackercontrol-v1.0.0-linux-x86_64.tar.gz
cd trackercontrol-linux-x86_64
sudo ./install_linux.sh
```

---

### 🪟 Windows (10 & 11)

Download `TrackerControl-PC-v1.0.0-Windows-x64.zip` from Releases:
1. Extract the `.zip` archive to any directory (e.g. `C:\Program Files\TrackerControl-PC` or desktop folder).
2. Right-click `TrackerControl-PC.exe` and select **Run as administrator** (necessary for kernel-level `netsh` firewall enforcement and `iphlpapi` socket tracking).
3. The dashboard opens automatically at `http://localhost:8000`.

---

## 🔨 Building From Source

### Building Linux Releases
Prerequisites: Python 3.10+, `pip`, `binutils`, and `dpkg-deb` (on Debian/Ubuntu).
```bash
# 1. Install dependencies
pip install -r requirements.txt
pip install pyinstaller

# 2. Build standalone ELF binary and .deb package
chmod +x build_linux.sh packaging/linux/build_deb.sh
./build_linux.sh
./packaging/linux/build_deb.sh

# 3. Create compressed release archives
python packaging/package_releases.py
```
Output artifacts are saved to `dist/`.

### Building Windows Releases
Prerequisites: Windows 10/11, Python 3.10+, `pip`.
```powershell
pip install -r requirements.txt
pip install pyinstaller
pyinstaller TrackerControl.spec
python packaging\package_releases.py
```

---

## 🤖 GitHub Actions Automated Releases

The repository includes a complete CI/CD workflow (`.github/workflows/release.yml`). Whenever a git tag matching `v*` is pushed:
```bash
git tag v1.0.0
git push origin v1.0.0
```
GitHub Actions will automatically:
1. Compile the standalone Windows executable (`TrackerControl-PC.exe`) on `windows-latest`.
2. Compile the standalone Linux ELF binary (`trackercontrol-linux`) on `ubuntu-latest`.
3. Package the Debian `.deb` installer.
4. Compress release archives (`.zip` and `.tar.gz`).
5. Publish a GitHub Release with SHA-256 checksums and downloadable release assets.

---

## 📜 License

TrackerControl PC is licensed under the [MIT License](LICENSE).

```
MIT License
Copyright (c) 2026 TrackerControl Contributors
```

You are free to use, modify, distribute, and integrate this software in private, personal, or commercial environments according to the terms of the MIT license.
