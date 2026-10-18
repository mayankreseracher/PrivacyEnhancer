# 🛡️ TrackerControl PC — Sovereign Desktop Privacy & Telemetry Guard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue.svg)](https://github.com/mayankreseracher/PrivacyEnhancer)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://python.org)
[![Architecture](https://img.shields.io/badge/Architecture-Universal%20%7C%20x86__64%20%7C%20ARM64-orange.svg)](#-downloads--packages)

> **A specialized, high-performance desktop privacy suite and GlassWire-style network sentinel engineered natively for Windows, macOS, and all Linux distributions.**

TrackerControl on Android popularized per-app tracker visibility and blocking using local VPN loopback. However, **desktop computers are an even larger surveillance blindspot**: desktop applications (Discord, Spotify, Steam, Chrome, Slack, VS Code, Electron apps, games) and operating systems (Windows DiagTrack, macOS Analytics/CrashReporter, Ubuntu Whoopsie, Red Hat Insights) transmit massive volumes of behavioral telemetry, analytics, and device fingerprinting that **browser adblockers (like uBlock Origin) are completely blind to**.

**TrackerControl PC** bridges this gap by bringing deep process attribution, multi-tier threat intelligence, GlassWire-style network monitoring with live animated wave graphs, kernel firewall enforcement, multi-tunnel WireGuard, Proton VPN, and Tor/Orbot integration directly to your workstation.

---

## 🌟 Flagship GlassWire-Style Features

* 📈 **Live Network Activity Wave Graph**: Real-time dual glowing wave graph (Download in Cyan `#00e5ff`, Upload in Magenta `#ff007f`) with amber markers pinpointing blocked tracker drops along the timeline. Includes live digital speedometers (⬇️ Rx KB/s, ⬆️ Tx KB/s, 📊 Session MB) and selectable time windows (60s, 3m, 5m, 10m).
* 🚨 **Instant Security Alerts Feed**: Real-time notifications whenever a newly installed application connects to the internet for the first time, or whenever a high-risk tracker is neutralized.
* 📱 **Per-Application 3-Way Firewall**: GlassWire-style 1-click toggles directly on application cards:
  * 🟢 **Allow All**: Clearnet whitelist.
  * 🛡️ **Drop Trackers**: Silent neutralization of ads, tracking SDKs, and telemetry while the application functions normally.
  * 🚫 **Firewall App**: Full outbound isolation via operating system kernel packet filters.
* 🖥️ **OS Privacy Debloaters**:
  * **Windows**: DiagTrack, dmwappushservice, and Advertising ID suppression.
  * **macOS**: `AutoSubmitDiagnostics` (CrashReporter), `allowApplePersonalizedAdvertising`, `SuppressSearchSuggestions` (Safari & Siri keystroke leaks), and `analyticsd`.
  * **Linux**: `whoopsie`, `apport`, `popularity-contest`, `ubuntu-report`, `abrt`, and `insights-client`.
* 🛡️ **Multi-Tunnel WireGuard & Proton VPN**: Concurrent tunnels with speedometers, split-tunneling per application, and direct Proton VPN server fleet deployment.
* 🧅 **Built-in Orbot / Tor Gateway**: SOCKS5 and HTTP proxy routing with ControlPort `SIGNAL NEWNYM` circuit cycling.

---

## 📦 Official App Releases & Direct Downloads

Official pre-built desktop releases with bundled Python runtime, threat database, and assets are available on the [**Official GitHub Releases Page (v1.0.2)**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/tag/v1.0.2) or in [`dist/`](dist/):

| OS / Distribution | Package Type | Direct Download Link | Description |
|---|---|---|---|
| **Windows 10 / 11** | Standalone Executable | [**`TrackerControl-PC.exe`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/TrackerControl-PC.exe) | Single-file portable executable (18.9 MB) |
| **Windows 10 / 11** | Release ZIP | [**`TrackerControl-PC-Windows-x64.zip`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/TrackerControl-PC-Windows-x64.zip) | Portable bundle with batch launcher (18.7 MB) |
| **macOS (Apple Silicon & Intel)** | Native Disk Image (.dmg) | [**`TrackerControl-v1.0.0-macOS.dmg`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/TrackerControl-v1.0.0-macOS.dmg) | Drag-and-drop macOS installer image |
| **macOS (Apple Silicon & Intel)** | App Bundle Archive | [**`TrackerControl-v1.0.0-macOS-universal.tar.gz`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/TrackerControl-v1.0.0-macOS-universal.tar.gz) | Standalone `.app` bundle with launcher script |
| **macOS (Apple Silicon & Intel)** | Universal Release ZIP | [**`TrackerControl-v1.0.0-macOS-universal.zip`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/TrackerControl-v1.0.0-macOS-universal.zip) | Complete `.app` bundle with `install_mac.sh` |
| **macOS (Homebrew)** | Homebrew Cask | [`packaging/macos/trackercontrol.rb`](packaging/macos/trackercontrol.rb) | `brew install --cask trackercontrol.rb` |
| **Debian / Ubuntu / Mint** | Native `.deb` | [**`trackercontrol_1.0.0_amd64.deb`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/trackercontrol_1.0.0_amd64.deb) | Native Debian package with systemd & desktop integration (30.1 MB) |
| **Fedora / RHEL / openSUSE** | Native `.rpm` | [**`trackercontrol-1.0.0-1.x86_64.rpm`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/trackercontrol-1.0.0-1.x86_64.rpm) | Native RPM package with systemd & desktop integration (30.2 MB) |
| **Universal Linux** | Standalone Binary | [**`trackercontrol-linux`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/trackercontrol-linux) | Native 64-bit ELF standalone executable (30.4 MB) |
| **Universal Linux** | Portable Tarball | [**`trackercontrol-v1.0.0-linux-x86_64.tar.gz`**](https://github.com/mayankreseracher/PrivacyEnhancer/releases/download/v1.0.2/trackercontrol-v1.0.0-linux-x86_64.tar.gz) | Complete bundle with `install.sh` and `uninstall.sh` (30.2 MB) |
| **Arch Linux / Manjaro** | PKGBUILD | [`packaging/arch/PKGBUILD`](packaging/arch/PKGBUILD) | AUR / Arch build recipe |
| **Fedora / RHEL / openSUSE** | RPM Spec | [`packaging/rpm/trackercontrol.spec`](packaging/rpm/trackercontrol.spec) | RPM packaging specification |

---

## 💻 Cross-Platform Architecture Matrix

| Capability | Windows 10 / 11 | macOS (Sonoma / Sequoia) | Linux (All Distributions) |
|---|---|---|---|
| **Process Attribution** | Windows Network Sockets & `iphlpapi` | BSD Socket Inodes, `lsof` & `psutil` | `/proc` socket inodes & `psutil` |
| **App Discovery** | Windows Registry & `%LocalAppData%\Programs` | `/Applications`, `/System/Applications` & `Info.plist` | Freedesktop `.desktop`, Flatpak, Snap, `/usr/bin` |
| **Firewall Engine** | Windows Advanced Firewall (`netsh`) | BSD Packet Filter (`pfctl` anchors) + `socketfilterfw` | `iptables`, `nftables`, `ufw`, `firewalld` |
| **OS Privacy Debloater** | DiagTrack, dmwappushservice, Advertising ID | CrashReporter, Personalized Ads, Siri suggestions, `analyticsd` | `whoopsie`, `apport`, `popcon`, `ubuntu-report`, `abrt` |
| **WireGuard VPN** | Wintun / WireGuard Windows Service | `wg-quick` with `utun` virtual interfaces | Standard `wg-quick` & kernel module |
| **Orbot / Tor** | Local SOCKS5 (`9050`) & ControlPort (`9051`) | Native Tor daemon / SOCKS5 & ControlPort | Native Tor daemon / SOCKS5 & ControlPort |
| **Desktop GUI** | Native Window (pywebview) + Web Dashboard | Native Window (pywebview Cocoa) + Web Dashboard | Native Window (pywebview WebKit) + Web Dashboard |

---

## ⚡ Why TrackerControl PC is Way More Powerful

| Capability | TrackerControl (Android) | GlassWire | TrackerControl PC (Sovereign) |
|---|---|---|---|
| **Monitoring Scope** | Android apps only | Network stats & firewall | **Every PC process** (Spotify, Discord, Games, Steam, VS Code, OS services) |
| **Process Attribution** | Basic UID mapping | Process name | **Full PID, Executable Path, Process Tree & Parent Process correlation** |
| **DNS Threat Interception** | Basic local loopback | ❌ None | **0.0.0.0 High-speed Async DNS Sinkhole + 4,500+ Curated Signatures** |
| **Live Network Graph** | ❌ None | Dual-color Wave | **Live Glowing Dual-Wave Canvas Graph with Blocked Threat Markers** |
| **Security Alerts Feed** | ❌ None | App alerts | **First-connection alerts, neutralized tracker log & OS telemetry feed** |
| **OS Privacy Debloater** | ❌ N/A | ❌ None | **Native DiagTrack/Ad ID (Windows), Apple Analytics (macOS) & Whoopsie (Linux)** |
| **Multi-Tunnel WireGuard**| ❌ Single tunnel | ❌ None | **Concurrent multi-tunnel manager with live Rx/Tx speedometers** |
| **Proton VPN Integration** | ❌ None | ❌ None | **Direct Proton credential vault & verified global server deployment** |
| **Split Tunneling** | Basic app selection | ❌ None | **Per-app granular routing: WireGuard vs Orbot/Tor vs Clearnet vs Block** |

---

## 🚀 Installation & Quickstart

### 🪟 Windows (10 & 11)

1. **Direct Standalone Executable**:
   Double-click `dist/TrackerControl-PC.exe` or execute in PowerShell as Administrator:
   ```powershell
   .\dist\TrackerControl-PC.exe
   ```
2. **Or via Batch Launcher**:
   ```powershell
   .\start_trackercontrol.bat
   ```

---

### 🍎 macOS

1. **Portable Bundle Launch**:
   ```bash
   tar -xzf dist/macos/TrackerControl-v1.0.0-macOS-universal.tar.gz
   chmod +x run_trackercontrol.sh
   ./run_trackercontrol.sh
   ```
2. **Or via macOS Launcher Script (Elevated for `pfctl` support)**:
   ```bash
   chmod +x start_trackercontrol_mac.sh
   sudo ./start_trackercontrol_mac.sh
   ```
3. **Via Homebrew Cask**:
   ```bash
   brew install --cask packaging/macos/trackercontrol.rb
   ```

---

### 🐧 Linux

#### 1. Debian / Ubuntu / Linux Mint / Pop!_OS (`.deb`)
```bash
sudo dpkg -i dist/linux/trackercontrol_1.0.0_amd64.deb
sudo trackercontrol
```

#### 2. Fedora / RHEL / openSUSE / Rocky Linux (`.rpm`)
```bash
sudo rpm -i dist/linux/trackercontrol-1.0.0-1.x86_64.rpm
# Or with dnf / zypper:
sudo dnf install dist/linux/trackercontrol-1.0.0-1.x86_64.rpm
sudo trackercontrol
```

#### 3. Universal Standalone Tarball (Any Linux Distro)
```bash
tar -xzf dist/linux/trackercontrol-v1.0.0-linux-x86_64.tar.gz
cd trackercontrol-1.0.0
sudo ./install.sh
```

#### 4. Standalone Binary Launch
```bash
chmod +x dist/linux/trackercontrol-linux
sudo ./dist/linux/trackercontrol-linux
```
*(Or run `sudo ./start_trackercontrol.sh`)*

---

### 🌐 Open the Desktop Control Center

TrackerControl PC launches directly in a native desktop window (via `pywebview`) or at **`http://localhost:8000`** in any web browser:
* **📈 Live Network Graph**: Monitor real-time upload and download bandwidth curves, inspect peak transfer rates, and see exact moments where privacy threats were dropped.
* **🚨 Security Alerts Feed**: Review background network attempts by unfamiliar software, verify newly running executables, and shield them with one click.
* **🛰️ Live Tracker Radar**: Sub-second waterfall of all outbound sockets, process attribution, categories, and block status.
* **📱 App Privacy Matrix**: Visual 3-way firewall buttons (`🟢 Allow All`, `🛡️ Drop Trackers`, `🚫 Firewall App`) for every application.
* **🛡️ OS Privacy Debloater**: Kernel and service-level privacy controls for Windows, macOS, and Linux.
* **🔒 WireGuard & Proton VPN Engine**: Multi-tunnel concurrency, Proton VPN server selector, and per-app split tunneling.

---

## 📁 Repository Structure

```
trackercontrol-pc/
├── .github/
│   └── workflows/
│       └── release.yml          # GitHub Actions CI/CD for Windows, macOS & Linux releases
├── backend/
│   ├── platform_helper.py       # OS detection (Windows, macOS Darwin, Linux distros)
│   ├── database.py              # SQLite persistent connection history & app profiles
│   ├── tracker_intelligence.py  # 4,500+ Exodus, WindowsSpyBlocker, Disconnect.me signatures
│   ├── process_monitor.py       # Real-time socket & PID attribution scanner
│   ├── dns_proxy.py             # Async DNS server, 0.0.0.0 sinkhole & OS resolver configuration
│   ├── firewall_enforcer.py     # Firewall engine (pfctl/socketfilterfw, netsh, iptables/nftables)
│   ├── app_discovery.py         # App discovery (macOS /Applications, Windows Registry, Linux .desktop)
│   ├── wireguard_manager.py     # Multi-tunnel WireGuard (utun, wintun, Linux wg-quick)
│   ├── proton_service.py        # Proton VPN credentials, server fleet & conf parser
│   ├── orbot_service.py         # Orbot / Tor Onion routing & ControlPort circuit cycling
│   ├── port_forwarder.py        # Async TCP/UDP stream forwarder & OS portproxy
│   ├── engine.py                # Core event bus, 1s bandwidth sampler & security alert engine
│   └── server.py                # FastAPI REST & WebSocket server
├── frontend/
│   ├── index.html               # Glassmorphic control center with Live Wave Graph & Alerts
│   ├── styles.css               # Futuristic styling, digital speedometers & alert cards
│   └── app.js                   # Canvas wave graph, WebSocket bus & per-app firewall controller
├── packaging/
│   ├── macos/
│   │   ├── Info.plist           # macOS Application bundle descriptor
│   │   ├── build_macos.sh       # Automated macOS build and DMG packaging script
│   │   └── trackercontrol.rb    # Homebrew Cask formula
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
│   ├── macos/
│   │   └── TrackerControl-v1.0.0-macOS-universal.tar.gz
│   └── linux/
│       ├── trackercontrol-linux
│       ├── trackercontrol-v1.0.0-linux-x86_64.tar.gz
│       └── trackercontrol_1.0.0_amd64.deb
├── main.py                      # Desktop app entry point (pywebview native window + browser fallback)
├── requirements.txt             # Python dependencies
├── start_trackercontrol.bat     # Windows launcher (with UTF-8 fix)
├── start_trackercontrol.sh      # Universal Linux launcher
├── start_trackercontrol_mac.sh  # macOS launcher (with pfctl elevation handling)
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
