"""
Cross-Platform Auto-Updater Engine for TrackerControl PC.
Checks GitHub Releases API for new releases, matches appropriate platform assets,
enforces strict cryptographic SHA-256 integrity verification against official SHA256SUMS,
quarantines staging, and automates safe binary replacement and restart.
"""

import asyncio
import os
import sys
import json
import time
import shutil
import re
import zipfile
import hashlib
import urllib.request
import urllib.error
import subprocess
from typing import Dict, Any, List, Optional, Tuple, Callable

from .platform_helper import IS_WINDOWS, IS_LINUX, IS_MACOS, PlatformHelper

CURRENT_VERSION = "1.1.0"
GITHUB_REPO = "mayankreseracher/PrivacyEnhancer"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
ALL_RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases"


def parse_version(v_str: str) -> Tuple[int, ...]:
    """
    Parses version strings like 'v1.0.4', '1.0.5', 'v1.0.4-patch1'
    into comparable integer tuples: (1, 0, 4)
    """
    if not v_str:
        return (0, 0, 0)
    clean = v_str.strip().lstrip("vV")
    clean = re.split(r"[-_+~]", clean)[0]
    parts = clean.split(".")
    nums = []
    for p in parts:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)
    while len(nums) < 3:
        nums.append(0)
    return tuple(nums[:4])


def is_newer_version(remote: str, current: str) -> bool:
    """Returns True if the remote version string is strictly newer than current."""
    return parse_version(remote) > parse_version(current)


class AutoUpdater:
    def __init__(self, database=None, event_callback: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.database = database
        self.event_callback = event_callback
        self.current_version = CURRENT_VERSION
        
        # State
        self.status = "idle"  # idle, checking, update_available, up_to_date, downloading, ready, applying, error
        self.latest_version: Optional[str] = None
        self.release_name: Optional[str] = None
        self.release_notes: Optional[str] = None
        self.published_at: Optional[str] = None
        self.html_url: Optional[str] = None
        self.selected_asset: Optional[Dict[str, Any]] = None
        self.sha256sums_url: Optional[str] = None
        self.verified_sha256: Optional[str] = None
        
        # Download telemetry
        self.download_progress: float = 0.0  # 0.0 to 100.0%
        self.download_speed_kbps: float = 0.0
        self.downloaded_bytes: int = 0
        self.total_bytes: int = 0
        self.staged_file_path: Optional[str] = None
        
        self.error_message: Optional[str] = None
        self.last_checked: Optional[float] = None
        self.is_checking: bool = False
        self.is_downloading: bool = False
        
        # Updates Staging Directories (Quarantine & Verified)
        self.updates_dir = os.path.join(PlatformHelper.get_data_dir(), "updates")
        self.quarantine_dir = os.path.join(self.updates_dir, "quarantine")
        self.verified_dir = os.path.join(self.updates_dir, "verified")
        os.makedirs(self.updates_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)
        os.makedirs(self.verified_dir, exist_ok=True)
        
        # Background checking task handle
        self._periodic_task: Optional[asyncio.Task] = None
        self._download_task: Optional[asyncio.Task] = None

    # ==================== Settings Persistence ====================

    def get_auto_check_enabled(self) -> bool:
        if self.database:
            val = self.database.get_setting("updater_auto_check", "true")
            return val.lower() in ("true", "1", "yes")
        return True

    def set_auto_check_enabled(self, enabled: bool):
        if self.database:
            self.database.set_setting("updater_auto_check", "true" if enabled else "false")

    def get_check_interval_hours(self) -> int:
        if self.database:
            try:
                return int(self.database.get_setting("updater_interval_hours", "6"))
            except Exception:
                return 6
        return 6

    def set_check_interval_hours(self, hours: int):
        if self.database:
            self.database.set_setting("updater_interval_hours", str(max(1, hours)))

    # ==================== Strict Release Asset Validation ====================

    def _is_safe_asset_name(self, filename: str) -> bool:
        """
        Enforces a strict security whitelist on release artifact filenames and extensions.
        Rejects arbitrary executables, shell scripts, batch files, and mismatched platforms.
        """
        if not filename or not isinstance(filename, str):
            return False
        fname = filename.strip().lower()

        # Reject any suspicious, script, or non-package extensions
        disallowed = (".bat", ".cmd", ".vbs", ".ps1", ".sh", ".bash", ".py", ".dll", ".so", ".dylib", ".msi", ".jar")
        if any(fname.endswith(bad) for bad in disallowed):
            return False

        if IS_WINDOWS:
            # Standalone TrackerControl-PC.exe or TrackerControl-PC-*.zip
            if fname == "trackercontrol-pc.exe":
                return True
            if (fname.startswith("trackercontrol-pc") or fname.startswith("trackercontrol")) and fname.endswith(".zip") and ("win" in fname or "windows" in fname):
                return True
            return False

        elif IS_LINUX:
            # Debian, RPM, or tarball packages matching official naming convention
            if fname.startswith("trackercontrol") and (fname.endswith((".deb", ".rpm", ".tar.gz")) or fname == "trackercontrol-linux"):
                return True
            return False

        elif IS_MACOS:
            # macOS disk image or universal zip/tarball
            if fname.startswith("trackercontrol") and (fname.endswith((".dmg", ".zip", ".tar.gz"))):
                return True
            return False

        return False

    def _match_asset_for_platform(self, assets: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Picks the best binary/package asset from GitHub release assets
        matching the current operating system and architecture with strict whitelist checking.
        """
        if not assets:
            return None

        # Filter strictly safe assets
        safe_assets = [a for a in assets if self._is_safe_asset_name(a.get("name", ""))]

        # 1. Windows:
        if IS_WINDOWS:
            for a in safe_assets:
                name = a.get("name", "").lower()
                if name == "trackercontrol-pc.exe":
                    return a
            for a in safe_assets:
                name = a.get("name", "").lower()
                if name.endswith(".exe") and "trackercontrol" in name:
                    return a
            for a in safe_assets:
                name = a.get("name", "").lower()
                if ("windows" in name or "win" in name) and name.endswith(".zip"):
                    return a
            return None

        # 2. macOS:
        elif IS_MACOS:
            for a in safe_assets:
                name = a.get("name", "").lower()
                if name.endswith(".dmg"):
                    return a
            for a in safe_assets:
                name = a.get("name", "").lower()
                if ("macos" in name or "darwin" in name) and (name.endswith(".tar.gz") or name.endswith(".zip")):
                    return a
            return None

        # 3. Linux:
        elif IS_LINUX:
            distro_info = PlatformHelper.get_linux_distro_info()
            family = distro_info.get("family", "")

            # Debian / Ubuntu family -> .deb
            if family == "debian":
                for a in safe_assets:
                    name = a.get("name", "").lower()
                    if name.endswith(".deb"):
                        return a

            # RHEL / Fedora / SUSE family -> .rpm
            if family in ("rhel", "suse"):
                for a in safe_assets:
                    name = a.get("name", "").lower()
                    if name.endswith(".rpm"):
                        return a

            # Standalone ELF binary or tarball
            for a in safe_assets:
                name = a.get("name", "").lower()
                if "linux" in name and not name.endswith((".deb", ".rpm")):
                    return a
            return None

        return None

    # ==================== Check for Updates ====================

    async def check_for_updates(self, manual: bool = False) -> Dict[str, Any]:
        """
        Queries GitHub API for the latest release and verifies if an update is available.
        """
        if self.is_checking:
            return self.get_status()

        self.is_checking = True
        self.status = "checking"
        self.error_message = None

        loop = asyncio.get_event_loop()
        try:
            release_data = await loop.run_in_executor(None, self._fetch_latest_release_sync)
            self.last_checked = time.time()

            tag_name = release_data.get("tag_name", "")
            latest_v = tag_name.lstrip("vV")
            self.latest_version = latest_v
            self.release_name = release_data.get("name") or f"Release {tag_name}"
            self.release_notes = release_data.get("body") or "No release notes provided."
            self.published_at = release_data.get("published_at")
            self.html_url = release_data.get("html_url")

            assets = release_data.get("assets", [])

            # Locate official SHA256SUMS manifest in release assets
            self.sha256sums_url = None
            for a in assets:
                aname = a.get("name", "").lower()
                if aname in ("sha256sums", "sha256sums.txt", "checksums.txt"):
                    self.sha256sums_url = a.get("browser_download_url")
                    break

            matched_asset = self._match_asset_for_platform(assets)
            
            if matched_asset:
                self.selected_asset = {
                    "name": matched_asset.get("name"),
                    "size": matched_asset.get("size", 0),
                    "download_url": matched_asset.get("browser_download_url"),
                    "content_type": matched_asset.get("content_type", "")
                }
            else:
                self.selected_asset = None

            if is_newer_version(latest_v, self.current_version):
                if self.selected_asset:
                    self.status = "update_available"
                else:
                    self.status = "update_available"  # New tag exists, but no binary for this specific OS
            else:
                self.status = "up_to_date"

            print(f"[AutoUpdater] Check complete: current={self.current_version}, latest={latest_v}, status={self.status}, sha256_manifest={bool(self.sha256sums_url)}")

        except Exception as e:
            self.status = "error"
            self.error_message = f"Failed to check for updates: {e}"
            print(f"[AutoUpdater] Check failed: {e}")
        finally:
            self.is_checking = False

        self._dispatch_event({
            "type": "UPDATE_STATUS",
            "data": self.get_status()
        })
        return self.get_status()

    def _fetch_latest_release_sync(self) -> Dict[str, Any]:
        """
        Fetches latest release info from GitHub API with an automated rate-limit-free
        HTML redirect & expanded_assets fallback.
        """
        # Attempt 1: Standard GitHub REST API
        req = urllib.request.Request(
            RELEASES_API,
            headers={
                "User-Agent": f"TrackerControl-PC-Updater/{self.current_version}",
                "Accept": "application/vnd.github.v3+json"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data
        except Exception as api_err:
            print(f"[AutoUpdater] Notice: GitHub API returned {api_err}. Engaging rate-limit-free Web Fallback...")

        # Attempt 2: Resilient Web Fallback
        try:
            web_latest_url = f"https://github.com/{GITHUB_REPO}/releases/latest"
            req_web = urllib.request.Request(
                web_latest_url,
                headers={"User-Agent": f"Mozilla/5.0 (TrackerControl-PC/{self.current_version})"}
            )
            with urllib.request.urlopen(req_web, timeout=6) as resp:
                final_url = resp.geturl()
                tag = final_url.split("/")[-1]

            # Fetch expanded assets table
            expanded_url = f"https://github.com/{GITHUB_REPO}/releases/expanded_assets/{tag}"
            req_exp = urllib.request.Request(
                expanded_url,
                headers={"User-Agent": f"Mozilla/5.0 (TrackerControl-PC/{self.current_version})"}
            )
            assets = []
            with urllib.request.urlopen(req_exp, timeout=8) as resp_exp:
                html = resp_exp.read().decode("utf-8", errors="ignore")
                matches = re.findall(r'href="([^"]*/releases/download/[^/]+/([^"]+))"', html)
                seen_names = set()
                for full_path, fname in matches:
                    if fname in seen_names:
                        continue
                    seen_names.add(fname)
                    dl_url = "https://github.com" + full_path if full_path.startswith("/") else full_path
                    assets.append({
                        "name": fname,
                        "browser_download_url": dl_url,
                        "size": 0,
                        "content_type": "application/octet-stream"
                    })

            return {
                "tag_name": tag,
                "name": f"TrackerControl PC {tag}",
                "body": "Latest release from GitHub.",
                "published_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "html_url": f"https://github.com/{GITHUB_REPO}/releases/tag/{tag}",
                "assets": assets
            }
        except Exception as web_err:
            print(f"[AutoUpdater] Web fallback also failed: {web_err}")
            raise web_err

    # ==================== Download & Cryptographic Integrity ====================

    @staticmethod
    def _compute_file_sha256(filepath: str) -> str:
        """Computes the SHA-256 hash of a file on disk using 64KB chunk streaming."""
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(64 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest().lower()

    async def start_download(self) -> Dict[str, Any]:
        """
        Asynchronously downloads the matched update asset into quarantine,
        downloads SHA256SUMS, and performs strict cryptographic verification.
        """
        if self.is_downloading:
            return {"success": False, "error": "Download already in progress", "status": self.status}

        if not self.selected_asset or not self.selected_asset.get("download_url"):
            return {"success": False, "error": "No downloadable asset available for this platform."}

        filename = self.selected_asset["name"] or "TrackerControl-PC-update"
        if not self._is_safe_asset_name(filename):
            return {"success": False, "error": f"Rejected asset '{filename}': does not match allowed security whitelist."}

        self.is_downloading = True
        self.status = "downloading"
        self.download_progress = 0.0
        self.downloaded_bytes = 0
        self.total_bytes = self.selected_asset.get("size", 0)
        self.error_message = None
        self.verified_sha256 = None

        url = self.selected_asset["download_url"]

        loop = asyncio.get_event_loop()
        self._download_task = loop.create_task(self._download_worker(url, filename))
        return {"success": True, "message": "Download and verification started", "asset": filename}

    async def _download_worker(self, url: str, filename: str):
        loop = asyncio.get_event_loop()
        quarantine_file = os.path.join(self.quarantine_dir, filename)
        sums_file = os.path.join(self.quarantine_dir, "SHA256SUMS")

        try:
            # Step 1: Download target update payload into quarantine
            await loop.run_in_executor(None, self._download_file_sync, url, quarantine_file)

            # Step 2: Download and verify SHA256SUMS manifest
            if not self.sha256sums_url:
                raise ValueError("Security Policy Error: Release does not provide an official SHA256SUMS manifest. Cannot verify update integrity.")

            await loop.run_in_executor(None, self._download_file_sync, self.sha256sums_url, sums_file)

            # Step 3: Parse SHA256SUMS for expected hash
            expected_hash = None
            with open(sums_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        h_val, f_val = parts[0], parts[1]
                        if os.path.basename(f_val).lower() == filename.lower():
                            expected_hash = h_val.lower().strip()
                            break

            if not expected_hash or len(expected_hash) != 64:
                raise ValueError(f"Integrity Error: Release asset '{filename}' is not cataloged in official SHA256SUMS manifest!")

            # Step 4: Compute SHA-256 of quarantined payload
            computed_hash = await loop.run_in_executor(None, self._compute_file_sha256, quarantine_file)

            if computed_hash != expected_hash:
                raise ValueError(
                    f"CRITICAL SECURITY ALERT: Cryptographic hash mismatch for '{filename}'! "
                    f"Expected: {expected_hash}, Computed: {computed_hash}. Staged artifact was purged."
                )

            # Step 5: Move verified payload to verified directory
            verified_file = os.path.join(self.verified_dir, filename)
            if os.path.exists(verified_file):
                try:
                    os.remove(verified_file)
                except Exception:
                    pass
            shutil.move(quarantine_file, verified_file)

            # Enforce user-only permissions (0600 on POSIX)
            if not IS_WINDOWS:
                try:
                    os.chmod(verified_file, 0o600)
                except Exception:
                    pass

            self.staged_file_path = verified_file
            self.verified_sha256 = computed_hash
            self.status = "ready"
            self.download_progress = 100.0
            print(f"[AutoUpdater] Cryptographic integrity VERIFIED for {filename} (SHA-256: {computed_hash[:16]}...)")
            self._dispatch_event({
                "type": "UPDATE_READY",
                "data": self.get_status()
            })

        except asyncio.CancelledError:
            self.status = "idle"
            if os.path.exists(quarantine_file):
                try:
                    os.remove(quarantine_file)
                except Exception:
                    pass
        except Exception as e:
            self.status = "error"
            self.error_message = str(e)
            print(f"[AutoUpdater] Download/verification error: {e}")
            if os.path.exists(quarantine_file):
                try:
                    os.remove(quarantine_file)
                except Exception:
                    pass
        finally:
            self.is_downloading = False
            self._dispatch_event({
                "type": "UPDATE_STATUS",
                "data": self.get_status()
            })

    def _download_file_sync(self, url: str, dest_path: str):
        req = urllib.request.Request(
            url,
            headers={"User-Agent": f"TrackerControl-PC-Updater/{self.current_version}"}
        )
        temp_dest = dest_path + ".part"
        start_time = time.time()
        last_calc_time = start_time
        last_calc_bytes = 0

        with urllib.request.urlopen(req, timeout=30) as resp:
            total_size = int(resp.headers.get("content-length", self.total_bytes or 0))
            if total_size > 0:
                self.total_bytes = total_size

            with open(temp_dest, "wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    self.downloaded_bytes += len(chunk)

                    now = time.time()
                    dt = now - last_calc_time
                    if dt >= 0.5:
                        bytes_diff = self.downloaded_bytes - last_calc_bytes
                        self.download_speed_kbps = max(0.0, (bytes_diff / 1024.0) / dt)
                        last_calc_time = now
                        last_calc_bytes = self.downloaded_bytes

                        if self.total_bytes > 0:
                            self.download_progress = round(
                                min(100.0, (self.downloaded_bytes / self.total_bytes) * 100.0), 1
                            )

                        self._dispatch_event({
                            "type": "UPDATE_PROGRESS",
                            "data": {
                                "progress": self.download_progress,
                                "downloaded_bytes": self.downloaded_bytes,
                                "total_bytes": self.total_bytes,
                                "speed_kbps": round(self.download_speed_kbps, 1)
                            }
                        })

        if os.path.exists(dest_path):
            try:
                os.remove(dest_path)
            except Exception:
                pass
        shutil.move(temp_dest, dest_path)

    # ==================== Apply Update & Restart ====================

    async def apply_update(self) -> Dict[str, Any]:
        """
        Applies the downloaded update package and restarts TrackerControl PC.
        Validates cryptographic integrity and prevents TOCTOU tampering before execution.
        """
        if not self.staged_file_path or not os.path.exists(self.staged_file_path):
            return {"success": False, "error": "No downloaded update file found. Download first."}

        if not self.verified_sha256:
            return {"success": False, "error": "Integrity check failed: Update was not cryptographically verified against SHA256SUMS."}

        # Anti-TOCTOU: Re-compute SHA-256 before actual execution
        current_hash = self._compute_file_sha256(self.staged_file_path)
        if current_hash != self.verified_sha256:
            try:
                os.remove(self.staged_file_path)
            except Exception:
                pass
            self.staged_file_path = None
            self.verified_sha256 = None
            self.status = "error"
            return {"success": False, "error": "CRITICAL SECURITY ALERT: Staged update file was modified on disk prior to application! Aborting."}

        self.status = "applying"
        current_pid = os.getpid()

        # Handle zip extraction if archive was downloaded
        payload_file = self.staged_file_path
        if payload_file.endswith(".zip"):
            try:
                with zipfile.ZipFile(payload_file, "r") as zf:
                    extracted_dir = os.path.join(self.updates_dir, "extracted")
                    os.makedirs(extracted_dir, exist_ok=True)
                    zf.extractall(extracted_dir)
                    for root, _, files in os.walk(extracted_dir):
                        for f in files:
                            if f.lower() == "trackercontrol-pc.exe":
                                payload_file = os.path.join(root, f)
                                break
            except Exception as zip_err:
                print(f"[AutoUpdater] Warning extracting zip update: {zip_err}")

        # Determine target application executable path safely
        if getattr(sys, "frozen", False):
            target_exe = os.path.abspath(sys.executable)
        else:
            # Running from source in dev mode: avoid overwriting python script
            base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            target_exe = os.path.join(base_dir, "dist", "TrackerControl-PC.exe")
            if not os.path.exists(os.path.dirname(target_exe)):
                os.makedirs(os.path.dirname(target_exe), exist_ok=True)

        print(f"[AutoUpdater] Applying verified update: {payload_file} -> {target_exe}")

        # 1. Windows Self-Replacement via detached batch script
        if IS_WINDOWS:
            script_path = os.path.join(self.updates_dir, "apply_update.bat")
            bat_script = f"""@echo off
chcp 65001 >nul
echo ========================================================
echo  TrackerControl PC Auto-Updater -- Applying Update
echo ========================================================
timeout /t 2 /nobreak >nul

:wait_loop
taskkill /PID {current_pid} /F >nul 2>&1
timeout /t 1 /nobreak >nul

copy /Y "{payload_file}" "{target_exe}" >nul 2>&1
if errorlevel 1 (
    echo [!] Target executable is still locked by process. Retrying in 1s...
    goto wait_loop
)

echo [+] Binary replaced successfully!
echo [+] Relaunching TrackerControl PC...
start "" "{target_exe}"

timeout /t 2 /nobreak >nul
del "%~f0" >nul 2>&1
exit
"""
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(bat_script)

            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            subprocess.Popen(
                ["cmd.exe", "/c", script_path],
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                close_fds=True
            )

            # Trigger graceful exit after small delay
            asyncio.get_event_loop().call_later(1.0, lambda: os._exit(0))
            return {"success": True, "message": "Applying update and restarting application on Windows..."}

        # 2. Linux Package or Standalone Binary Replacement
        elif IS_LINUX:
            # If native Debian package (.deb)
            if self.staged_file_path.endswith(".deb"):
                try:
                    subprocess.Popen(["pkexec", "dpkg", "-i", self.staged_file_path])
                    return {"success": True, "message": "Launched package installer for Debian/Ubuntu (.deb)."}
                except Exception as e:
                    return {"success": False, "error": f"Failed to launch pkexec: {e}"}

            # If standalone binary
            elif not self.staged_file_path.endswith((".tar.gz", ".zip")):
                try:
                    os.chmod(self.staged_file_path, 0o755)
                    shutil.move(self.staged_file_path, target_exe)
                    subprocess.Popen([target_exe])
                    asyncio.get_event_loop().call_later(0.5, lambda: os._exit(0))
                    return {"success": True, "message": "Updated standalone binary and restarting..."}
                except Exception as e:
                    return {"success": False, "error": f"Failed replacing Linux binary: {e}"}

            return {
                "success": True,
                "message": f"Update downloaded to {self.staged_file_path}. Please extract or install.",
                "path": self.staged_file_path
            }

        # 3. macOS Disk Image or Tarball
        elif IS_MACOS:
            try:
                subprocess.Popen(["open", self.staged_file_path])
                return {"success": True, "message": "Mounted update image / opened installer on macOS."}
            except Exception as e:
                return {"success": False, "error": f"Failed to open macOS installer: {e}"}

        return {"success": False, "error": f"Unsupported platform {sys.platform} for automatic self-replacement."}

    # ==================== Periodic Background Task ====================

    async def start_periodic_check(self, delay_initial_seconds: int = 5):
        """Runs periodic checks for updates in the background without blocking."""
        if delay_initial_seconds > 0:
            await asyncio.sleep(delay_initial_seconds)

        while True:
            try:
                if self.get_auto_check_enabled():
                    await self.check_for_updates(manual=False)
            except Exception as e:
                print(f"[AutoUpdater] Periodic check error: {e}")

            interval_sec = max(3600, self.get_check_interval_hours() * 3600)
            await asyncio.sleep(interval_sec)

    def stop(self):
        if self._periodic_task and not self._periodic_task.done():
            self._periodic_task.cancel()
        if self._download_task and not self._download_task.done():
            self._download_task.cancel()

    # ==================== Telemetry & Dispatch ====================

    def _dispatch_event(self, event: Dict[str, Any]):
        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                pass

    def get_status(self) -> Dict[str, Any]:
        return {
            "current_version": self.current_version,
            "latest_version": self.latest_version or self.current_version,
            "update_available": self.status == "update_available" or (
                bool(self.latest_version) and is_newer_version(self.latest_version, self.current_version)
            ),
            "status": self.status,
            "is_checking": self.is_checking,
            "is_downloading": self.is_downloading,
            "release_name": self.release_name,
            "release_notes": self.release_notes,
            "published_at": self.published_at,
            "html_url": self.html_url,
            "selected_asset": self.selected_asset,
            "sha256sums_available": bool(self.sha256sums_url),
            "verified_sha256": self.verified_sha256,
            "sha256_verified": bool(self.verified_sha256),
            "download_progress": self.download_progress,
            "download_speed_kbps": round(self.download_speed_kbps, 1),
            "downloaded_bytes": self.downloaded_bytes,
            "total_bytes": self.total_bytes,
            "staged_file_path": self.staged_file_path,
            "last_checked": self.last_checked,
            "auto_check_enabled": self.get_auto_check_enabled(),
            "check_interval_hours": self.get_check_interval_hours(),
            "error_message": self.error_message
        }
