# Security Audit & Hardening Report

**Application**: TrackerControl PC (Sovereign Desktop Edition)  
**Repository**: `mayankreseracher/PrivacyEnhancer`  
**Audit Scope**: Supply Chain, Credential Storage, Privilege Boundaries, DNS Sinkhole Resilience, and CI/CD Security  
**Audit Status**: Verified & Remediated for Release `v1.1.0`

---

## Executive Summary

A comprehensive security review of the TrackerControl PC codebase identified six critical operational, architectural, and supply-chain vulnerabilities. All six findings have been resolved in release `v1.1.0`.

| Finding ID | Area | Severity | Status | Remediation Summary |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | Pre-compiled Binaries in Git | High | **RESOLVED** | Purged all 15 compiled `.exe`, `.deb`, `.rpm`, `.zip`, `.tar.gz` binaries from git index; strengthened `.gitignore` to prevent any binary tracking. |
| **SEC-02** | Credential Storage at Rest | High | **RESOLVED** | Implemented `backend/credential_vault.py` with Windows DPAPI (TPM/LSA kernel protected) and machine-bound authenticated fallback. Zero plaintext keys on disk. |
| **SEC-03** | Privilege Escalation & Admin Risk | Medium | **RESOLVED** | Documented least-privilege boundary; verified 100% tokenized subprocess execution with zero `shell=True`; enabled `--audit` unprivileged user mode. |
| **SEC-04** | DNS Sinkhole Single Point of Failure | High | **RESOLVED** | Implemented persistent on-disk state backup (`original_dns_backup.json`), crash watchdog with `sys.excepthook`, multi-resolver failover, and `--restore-dns` emergency CLI. |
| **SEC-05** | Lack of Security Audit & Policy | Medium | **RESOLVED** | Published comprehensive `SECURITY.md` with STRIDE threat model, vulnerability disclosure SLAs, and cryptographic guarantees. |
| **SEC-06** | CI/CD Auto-Release Supply Chain | Medium | **RESOLVED** | Restricted GitHub Actions permissions, enforced strict tag pattern `v*.*.*`, and automated generation of cryptographic `SHA256SUMS` manifests. |

---

## Detailed Findings & Remediations

### Finding SEC-01: Pre-compiled Binaries in Git (Supply Chain Risk)

**Problem Description**:  
The `dist/` directory in the git repository tracked pre-compiled `.exe`, `.deb`, `.rpm`, and macOS binaries. Shipping binaries directly in git source control represents an unverified supply-chain vector and prevents reproducible verification.

**Remediation**:
1. Executed `git rm -r --cached dist/` to untrack all 15 pre-compiled binaries from the git index.
2. Updated `.gitignore` to explicitly and recursively ignore `dist/`, `build/`, `*.exe`, `*.deb`, `*.rpm`, `*.dmg`, `*.AppImage`, `*.bin`, `*.tar.gz`, and `*.zip`.
3. Established a clean source-only repository policy where all binaries are built in isolated CI/CD runners.

---

### Finding SEC-02: Handles Sensitive Credentials Without Encryption at Rest

**Problem Description**:  
WireGuard client private keys and Proton VPN credentials were stored in plaintext JSON files (`data/proton_auth.json` and `data/wireguard_tunnels.json`). Any local malware or process with file-read access could extract the private keys.

**Remediation**:
1. Implemented `backend/credential_vault.py` (`CredentialVault` singleton):
   - **Windows**: Utilizes Windows DPAPI (`ctypes.windll.crypt32.CryptProtectData`) to encrypt secrets using keys backed by the operating system kernel, TPM, and user login credentials.
   - **Linux & macOS**: Derives a 256-bit machine-bound key via PBKDF2-HMAC-SHA256 (120,000 rounds) bound to hardware identifiers (`/etc/machine-id`, `IOPlatformUUID`) and user credentials, using an authenticated CTR stream cipher with HMAC integrity check.
   - **File ACL Hardening**: Sensitive files are restricted to current user read/write only (`0600` on POSIX, user ACL on Windows).
2. Integrated `vault.encrypt()` and `vault.decrypt()` into `backend/proton_service.py` and `backend/wireguard_manager.py`.
3. Implemented automatic backwards-compatible migration: legacy unencrypted keys are decrypted cleanly and re-saved in encrypted `ENC:v1:...` format on the next load.
4. Hardened REST and WebSocket endpoints: `t_copy.pop("private_key", None)` ensures private keys are never transmitted over API endpoints.

---

### Finding SEC-03: Excessive Privileges & Admin Execution Risks

**Problem Description**:  
TrackerControl PC requires administrative/root privileges for packet filtering (`netsh advfirewall`, `iptables`, `nftables`) and low-port DNS binding. Bugs in elevated processes could compromise the host system.

**Remediation**:
1. Audited all `subprocess.run` and `subprocess.Popen` calls across the codebase. Verified that **100% of subprocess calls** use strict array/token lists (`["cmd", "arg1", "arg2"]`) with **zero** `shell=True` usages, eliminating command injection vectors.
2. Formalized the **Unprivileged User Mode**:
   - Running with `--audit`, `--no-elevate`, or non-elevated user accounts runs TrackerControl PC in a secure user-space sandbox.
   - User mode provides full SOCKS5 proxy routing, process network inspection, and threat notifications without requiring any administrative rights.
3. Added input validation to prevent arbitrary executable launching in application-binding APIs.

---

### Finding SEC-04: DNS Sinkhole Fragility & Network Blackout Risk

**Problem Description**:  
If the local DNS sinkhole crashed, the machine lost power, or the process was terminated, the host network adapters remained pointed at `127.0.0.1:53`. With the proxy dead, all domain resolution on the computer failed, breaking internet connectivity.

**Remediation**:
1. **Persistent On-Disk State**: Added `_save_dns_backup_to_disk()` in `backend/dns_proxy.py`. Prior to altering adapter settings, original DNS servers are recorded to `data/original_dns_backup.json`.
2. **Crash Watchdog**: Added `sys.excepthook` in `main.py` and signal handlers (`SIGINT`, `SIGTERM`, `atexit`) ensuring `restore_system_dns()` is executed even during unhandled Python exceptions.
3. **Emergency Standalone CLI**: Added `--restore-dns` / `--repair-dns` CLI flag to `main.py`:
   ```bash
   python main.py --restore-dns
   ```
   Can be run at any time to instantly restore all adapters to DHCP without launching the GUI.
4. **Emergency DHCP Fallback**: If backup state is missing or corrupted, `_restore_windows_dns(force_clean_all=True)` scans all active adapters and resets any adapter configured with `127.0.0.1` back to DHCP.
5. **Multi-Resolver Upstream Fail-Over**: If the primary upstream resolver fails or times out, the UDP forwarder automatically queries `1.1.1.1`, `9.9.9.9`, and `8.8.8.8` to ensure uninterrupted connectivity.
6. **Emergency API Endpoint**: Exposed `POST /api/dns/restore-emergency` for one-click frontend recovery.

---

### Finding SEC-05: Lack of Visible Security Policy & Audit Trail

**Problem Description**:  
The project lacked a public `SECURITY.md`, vulnerability disclosure guidelines, SLA commitments, or documented STRIDE threat modeling.

**Remediation**:
1. Created `SECURITY.md` in the repository root adhering to open-source security best practices.
2. Defined Coordinated Vulnerability Disclosure SLAs (48-hour response, 14-day critical fix target).
3. Documented STRIDE threat analysis and technical defenses.

---

### Finding SEC-06: CI/CD Auto-Release Pipeline Security

**Problem Description**:  
GitHub Actions auto-published release binaries without cryptographic checksums or verifiable build manifests.

**Remediation**:
1. Updated `.github/workflows/release.yml`:
   - Restricted workflow permissions explicitly: `permissions: contents: write` at workflow level and `contents: read` at job level.
   - Enforced strict tag pattern matching: `v*.*.*`.
   - Added automated generation of `SHA256SUMS` covering all build outputs (Windows `.exe`, Windows `.zip`, Linux `.deb`, `.rpm`, `.tar.gz`, macOS `.zip`, `.tar.gz`, `.dmg`).
   - Attached `SHA256SUMS` directly to GitHub Releases for client-side cryptographic verification.

---

## Verification & Test Results

- **DPAPI CryptProtectData / CryptUnprotectData**: Verified working with hardware-backed user profile isolation.
- **Legacy Plaintext Migration**: Verified transparent decryption and re-encryption.
- **Emergency CLI `--restore-dns`**: Verified execution across all active adapters with successful DHCP restoration and DNS cache flush.
- **Python Syntax & Bytecode Compilation**: All files in `backend/`, `main.py`, and `packaging/` compiled cleanly with zero errors.
