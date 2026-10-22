# Security Policy & Architecture

TrackerControl PC is a sovereign, open-source desktop privacy guard and multi-VPN orchestrator. Because TrackerControl PC interacts with operating system networking stacks, firewall rules, and private cryptographic keys, security and verifiability are primary architectural foundations.

---

## 1. Vulnerability Reporting (VDP)

We welcome reports from security researchers, penetration testers, and the open-source community. We practice **Coordinated Vulnerability Disclosure**.

### Reporting Channel
- **GitHub Private Vulnerability Reporting**: [Open a Security Advisory](https://github.com/mayankreseracher/PrivacyEnhancer/security/advisories/new)
- **Security Contact Email**: `tiger.sasquatch115@passinbox.com`

### Response SLAs
- **Acknowledgment**: Within 48 hours.
- **Initial Triage & Assessment**: Within 5 business days.
- **Remediation & Patch Release**: Within 14 business days for critical vulnerabilities.

Please do not report security vulnerabilities through public GitHub issues or public discussions.

---

## 2. Threat Model & Architecture

### STRIDE Assessment

| Threat Category | Potential Vector | TrackerControl PC Defense |
| :--- | :--- | :--- |
| **Spoofing** | Rogue processes spoofing DNS or API queries | Local loopback binding (`127.0.0.1`), strict CORS whitelisting, origin verification. |
| **Tampering** | Modifying saved WireGuard / Proton credentials on disk | Hardware-backed Windows DPAPI / machine-bound AES-GCM encryption at rest with strict file ACLs (`0600`). |
| **Repudiation** | Untracked network telemetry egress | SQLite append-only connection audit log with process attribution, timestamps, and destination tagging. |
| **Information Disclosure** | Private keys leaked in API responses or logs | Automatic in-memory masking (`pop("private_key")`), zero plaintext keys sent over REST/WebSockets. |
| **Denial of Service** | DNS sinkhole failure breaking internet access | Persistent disk backup (`original_dns_backup.json`), multi-resolver fail-over (`1.1.1.1`, `9.9.9.9`, `8.8.8.8`), and `--restore-dns` emergency CLI. |
| **Elevation of Privilege** | Subprocess injection via firewall/netsh commands | 100% tokenized command lists (`subprocess.run(["cmd", "arg"])`), strict binary whitelisting, **zero** `shell=True`. |

---

## 3. Privilege Boundary & Least-Privilege Execution

Operating system packet filtering (`netsh advfirewall`, Linux `iptables`/`nftables`) and low-port DNS listening (`UDP 53`) require administrative/root privileges on most operating systems.

To minimize the blast radius of any potential defect:
1. **Unprivileged User Mode (Audit / SOCKS5 Proxy Mode)**:
   - TrackerControl PC can run completely unprivileged without Administrator/root using `--audit` or `--no-elevate`.
   - In this mode, TrackerControl provides full local SOCKS5 proxying, process traffic auditing, real-time threat notifications, and per-app proxy routing without touching the system firewall or OS DNS.
2. **Elevated Privilege Mode**:
   - Explicitly requested via Windows UAC or `sudo`/`pkexec` on Linux.
   - Used strictly for applying discrete firewall rules and configuring local DNS redirection.
3. **Subprocess Execution Hardening**:
   - All external command invocations (`netsh`, `iptables`, `nftables`, `ip`, `wg`) use rigid, tokenized Python lists.
   - `shell=True` is prohibited throughout the entire codebase to prevent argument and shell injection.
   - Command inputs (IP addresses, process names, interface names) are validated against strict regex and type checks.

---

## 4. Hardware-Backed Credential Vault & Encryption at Rest

TrackerControl PC handles sensitive cryptographic credentials, including Proton VPN client private keys and WireGuard tunnel keys.

- **Windows**: Stored using the Windows Data Protection API (**DPAPI** via `CryptProtectData` / `CryptUnprotectData`). Keys are encrypted at rest using keys derived directly from the user's Windows login credentials and TPM/LSA kernel secrets.
- **Linux & macOS**: Stored using machine-bound PBKDF2-HMAC-SHA256 key derivation tied to hardware UUIDs (`/etc/machine-id`, macOS `IOPlatformExpertDevice`) and user credentials, encrypted using authenticated ciphers with strict POSIX file permissions (`0600` / owner-only).
- **Zero Plaintext at Rest**: Files `data/proton_auth.json` and `data/wireguard_tunnels.json` store only `ENC:v1:...` encrypted payloads on disk.
- **API Leak Prevention**: All REST and WebSocket endpoints automatically strip or mask private keys before transmitting state to the UI.

---

## 5. DNS Sinkhole Resilience & Emergency Recovery

A critical failure in a local DNS sinkhole can break internet resolution for the host operating system. TrackerControl PC employs a defense-in-depth safety system:

1. **Persistent On-Disk State**:
   - Before modifying any network adapter's DNS settings, TrackerControl records the exact original configuration to `data/original_dns_backup.json`.
   - Even if the application is killed abruptly (`kill -9`, Task Manager, power loss), the backup survives on disk.
2. **Crash Watchdog & Shutdown Traps**:
   - `sys.excepthook`, `atexit`, `SIGINT`, and `SIGTERM` handlers automatically restore original system DNS and flush the OS resolver cache upon termination.
3. **Emergency Standalone Recovery CLI**:
   - If any unexpected network condition occurs, users or recovery scripts can instantly restore all system adapters to default DHCP without launching the GUI:
     ```bash
     # Windows
     TrackerControl-PC.exe --restore-dns
     # Or via Python
     python main.py --restore-dns
     ```
4. **Upstream Multi-Resolver Fail-Over**:
   - If the configured upstream DNS server times out or fails, queries automatically cycle through secondary resilient public resolvers (`1.1.1.1`, `9.9.9.9`, `8.8.8.8`) rather than dropping traffic.

---

## 6. Supply Chain Security & Reproducible Builds

- **Zero Tracked Binaries**: The Git repository contains 100% source code, tests, and configuration. Pre-compiled binaries (`.exe`, `.deb`, `.rpm`, `.AppImage`, ELF) are prohibited from Git tracking.
- **Clean-Room CI/CD**: All official releases are compiled from verified source tags using GitHub Actions in clean-room virtualized runners.
- **Cryptographic Verification (`SHA256SUMS`)**:
  Every official release includes a cryptographic `SHA256SUMS` manifest generated during the build job. Users can verify the integrity of any downloaded asset:
  ```bash
  sha256sum -c SHA256SUMS
  ```
