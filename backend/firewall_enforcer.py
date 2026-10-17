"""
Cross-Platform Firewall Enforcer & Privacy Hardening Module for TrackerControl PC.
Provides kernel-level outbound blocking across:
- Linux: iptables, nftables, ufw, firewalld (with process owner matching & IP drop)
- Windows: Windows Advanced Firewall (netsh advfirewall)

Also neutralizes OS-level telemetry services:
- Linux: whoopsie, apport, popularity-contest, ubuntu-report, abrt, insights-client
- Windows: DiagTrack, dmwappushservice, Advertising ID
"""

import subprocess
import os
import shutil
import shlex
import logging
from typing import Dict, Any, List, Tuple, Optional

logger = logging.getLogger("FirewallEnforcer")

try:
    import winreg
except ImportError:
    winreg = None

from .platform_helper import IS_WINDOWS, IS_LINUX, PlatformHelper

class FirewallEnforcer:
    def __init__(self):
        self.rule_prefix = "TrackerControl_"
        self.backend = self._detect_firewall_backend()
        self.is_elevated = self.check_elevation()
        if not self.is_elevated:
            logger.warning(
                "TrackerControl is not running with administrative/root privileges! "
                "Firewall rule enforcement and OS telemetry debloating may fail."
            )
            print(
                "[FirewallEnforcer] WARNING: Running without administrative/root privileges! "
                "Firewall enforcement and packet filtering will fail or be restricted."
            )

    @staticmethod
    def check_elevation() -> bool:
        """Returns True if running with admin / root privileges."""
        if IS_WINDOWS:
            try:
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        elif IS_LINUX:
            try:
                return os.geteuid() == 0
            except Exception:
                return False
        else:
            try:
                if hasattr(os, "geteuid"):
                    return os.geteuid() == 0
            except Exception:
                pass
        return False

    def _ensure_nftables_table_and_chain(self) -> bool:
        """Ensures that the trackercontrol table and output chain exist in nftables."""
        table_ok, _ = self._run_cmd(["nft", "add", "table", "inet", "trackercontrol"])
        chain_ok, _ = self._run_cmd(["nft", "add", "chain", "inet", "trackercontrol", "output", "{ type filter hook output priority 0; }"])
        return table_ok and chain_ok

    def _get_process_uid(self, exe_path: str, app_name: str) -> Optional[int]:
        """Resolves the process owner UID for an application or executable."""
        # 1. Try to find a running process with matching exe or name
        try:
            import psutil
            app_lower = app_name.lower() if app_name else ""
            exe_base = os.path.basename(exe_path).lower() if exe_path else ""
            for p in psutil.process_iter(['name', 'exe', 'uids']):
                try:
                    info = p.info
                    p_exe = info.get('exe') or ""
                    p_name = info.get('name') or ""
                    if (exe_base and os.path.basename(p_exe).lower() == exe_base) or \
                       (app_lower and p_name.lower() == app_lower) or \
                       (exe_path and os.path.abspath(p_exe) == os.path.abspath(exe_path)):
                        uids = info.get('uids')
                        if uids and hasattr(uids, 'real'):
                            return int(uids.real)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        # 2. Try file ownership if executable exists on disk
        try:
            if exe_path and os.path.exists(exe_path):
                return int(os.stat(exe_path).st_uid)
            if exe_path:
                resolved = shutil.which(exe_path)
                if resolved and os.path.exists(resolved):
                    return int(os.stat(resolved).st_uid)
        except Exception:
            pass

        # 3. Fallback to current process UID
        try:
            if hasattr(os, "getuid"):
                return int(os.getuid())
        except Exception:
            pass

        return None

    def _detect_firewall_backend(self) -> str:
        if IS_WINDOWS:
            return "netsh"
        elif IS_LINUX:
            if shutil.which("nft"):
                return "nftables"
            elif shutil.which("iptables"):
                return "iptables"
            elif shutil.which("ufw"):
                return "ufw"
            elif shutil.which("firewall-cmd"):
                return "firewalld"
        return "none"

    def _run_cmd(self, cmd: List[str]) -> Tuple[bool, str]:
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            return res.returncode == 0, res.stdout or res.stderr
        except Exception as e:
            return False, str(e)

    # ==================== Application Executable Blocking ====================

    def block_executable(self, exe_path: str, app_name: str) -> Dict[str, Any]:
        """Blocks outbound network traffic for an application executable."""
        rule_name = f"{self.rule_prefix}App_{app_name}"

        if IS_WINDOWS:
            # Delete duplicate first
            self._run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"program={exe_path}",
                f"description=Blocked by TrackerControl PC"
            ]
            success, out = self._run_cmd(cmd)
            return {"success": success, "backend": "netsh", "rule_name": rule_name, "output": out}

        elif IS_LINUX:
            proc_basename = os.path.basename(exe_path).split()[0] if exe_path else app_name

            if self.backend == "nftables" or (not shutil.which("iptables") and shutil.which("nft")):
                self._ensure_nftables_table_and_chain()
                uid = self._get_process_uid(exe_path, app_name)
                if uid is not None:
                    cmd = ["nft", "add", "rule", "inet", "trackercontrol", "output", "meta", "skuid", str(uid), "ip", "daddr", "0.0.0.0/0", "drop"]
                    success, out = self._run_cmd(cmd)
                    return {"success": success, "backend": "nftables", "rule_name": rule_name, "output": out}
                else:
                    logger.warning(f"Could not determine process owner UID for {exe_path} ({app_name})")
                    return {"success": False, "backend": "nftables", "rule_name": rule_name, "error": f"Could not determine UID for '{app_name}'"}

            elif self.backend == "iptables" or shutil.which("iptables"):
                # Clean existing rule if any
                self._run_cmd(["iptables", "-D", "OUTPUT", "-m", "owner", "--cmd-owner", proc_basename, "-m", "comment", "--comment", "TrackerControl", "-j", "DROP"])
                self._run_cmd(["iptables", "-D", "OUTPUT", "-m", "owner", "--cmd-owner", proc_basename, "-j", "DROP"])
                cmd = ["iptables", "-A", "OUTPUT", "-m", "owner", "--cmd-owner", proc_basename, "-m", "comment", "--comment", "TrackerControl", "-j", "DROP"]
                success, out = self._run_cmd(cmd)
                return {"success": success, "backend": "iptables", "rule_name": rule_name, "output": out}

        logger.warning(f"No supported firewall backend found to block executable: {app_name}")
        return {"success": False, "backend": "none", "error": "No supported firewall backend found"}

    def unblock_executable(self, app_name: str) -> Dict[str, Any]:
        """Removes outbound firewall blocking for an application."""
        rule_name = f"{self.rule_prefix}App_{app_name}"

        if IS_WINDOWS:
            success, out = self._run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            return {"success": success, "backend": "netsh", "rule_name": rule_name, "output": out}

        elif IS_LINUX:
            proc_basename = os.path.basename(app_name).split()[0] if app_name else app_name

            if self.backend == "nftables" or (not shutil.which("iptables") and shutil.which("nft")):
                uid = self._get_process_uid("", app_name)
                if uid is not None:
                    success, out = self._run_cmd(["nft", "-a", "list", "chain", "inet", "trackercontrol", "output"])
                    if success and out:
                        for line in out.splitlines():
                            if f"skuid {uid}" in line and "handle" in line:
                                parts = line.strip().split()
                                if "handle" in parts:
                                    h_idx = parts.index("handle")
                                    if h_idx + 1 < len(parts):
                                        h_num = parts[h_idx + 1]
                                        self._run_cmd(["nft", "delete", "rule", "inet", "trackercontrol", "output", "handle", h_num])
                return {"success": True, "backend": "nftables", "rule_name": rule_name}

            elif self.backend == "iptables" or shutil.which("iptables"):
                self._run_cmd(["iptables", "-D", "OUTPUT", "-m", "owner", "--cmd-owner", proc_basename, "-m", "comment", "--comment", "TrackerControl", "-j", "DROP"])
                success, out = self._run_cmd(["iptables", "-D", "OUTPUT", "-m", "owner", "--cmd-owner", proc_basename, "-j", "DROP"])
                return {"success": success, "backend": "iptables", "output": out}

        logger.warning(f"No supported firewall backend found to unblock executable: {app_name}")
        return {"success": False, "backend": "none", "error": "No supported firewall backend found"}

    # ==================== IP Address Blocking ====================

    def block_ip(self, ip_address: str) -> Dict[str, Any]:
        """Adds kernel-level firewall rule to drop an outbound IP address."""
        rule_name = f"{self.rule_prefix}IP_{ip_address.replace('.', '_')}"

        if IS_WINDOWS:
            self._run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip_address}",
                f"description=TrackerControl IP Block"
            ]
            success, out = self._run_cmd(cmd)
            return {"success": success, "backend": "netsh", "rule_name": rule_name, "output": out}

        elif IS_LINUX:
            if self.backend == "nftables" or (not shutil.which("iptables") and shutil.which("nft")):
                self._ensure_nftables_table_and_chain()
                cmd = ["nft", "add", "rule", "inet", "trackercontrol", "output", "ip", "daddr", ip_address, "drop"]
                success, out = self._run_cmd(cmd)
                return {"success": success, "backend": "nftables", "rule_name": rule_name, "output": out}

            elif self.backend == "iptables" or shutil.which("iptables"):
                self._run_cmd(["iptables", "-D", "OUTPUT", "-d", ip_address, "-m", "comment", "--comment", "TrackerControl_IP", "-j", "DROP"])
                self._run_cmd(["iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"])
                cmd = ["iptables", "-A", "OUTPUT", "-d", ip_address, "-m", "comment", "--comment", "TrackerControl_IP", "-j", "DROP"]
                success, out = self._run_cmd(cmd)
                return {"success": success, "backend": "iptables", "rule_name": rule_name, "output": out}

            elif self.backend == "ufw" or shutil.which("ufw"):
                success, out = self._run_cmd(["ufw", "deny", "out", "to", ip_address])
                return {"success": success, "backend": "ufw", "output": out}

        logger.warning(f"No supported firewall backend found to block IP: {ip_address}")
        return {"success": False, "backend": "none", "error": "No supported firewall backend found"}

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        rule_name = f"{self.rule_prefix}IP_{ip_address.replace('.', '_')}"

        if IS_WINDOWS:
            success, out = self._run_cmd(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
            return {"success": success, "output": out}
        elif IS_LINUX:
            if self.backend == "nftables" or (not shutil.which("iptables") and shutil.which("nft")):
                success, out = self._run_cmd(["nft", "-a", "list", "chain", "inet", "trackercontrol", "output"])
                if success and out:
                    for line in out.splitlines():
                        if ip_address in line and "handle" in line:
                            parts = line.strip().split()
                            if "handle" in parts:
                                h_idx = parts.index("handle")
                                if h_idx + 1 < len(parts):
                                    h_num = parts[h_idx + 1]
                                    self._run_cmd(["nft", "delete", "rule", "inet", "trackercontrol", "output", "handle", h_num])
                return {"success": True, "backend": "nftables", "output": "Rule removed"}

            elif self.backend == "iptables" or shutil.which("iptables"):
                self._run_cmd(["iptables", "-D", "OUTPUT", "-d", ip_address, "-m", "comment", "--comment", "TrackerControl_IP", "-j", "DROP"])
                success, out = self._run_cmd(["iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"])
                return {"success": success, "output": out}

            elif self.backend == "ufw" or shutil.which("ufw"):
                success, out = self._run_cmd(["ufw", "delete", "deny", "out", "to", ip_address])
                return {"success": success, "output": out}

        logger.warning(f"No supported firewall backend found to unblock IP: {ip_address}")
        return {"success": False, "backend": "none", "error": "No supported firewall backend found"}

    # ==================== OS Privacy & Telemetry Debloater ====================

    def get_os_privacy_status(self) -> Dict[str, Any]:
        """Returns the privacy debloater status according to the host OS."""
        if IS_WINDOWS:
            return self.get_windows_privacy_status()
        elif IS_LINUX:
            return self.get_linux_privacy_status()
        return {"os": "Unknown", "telemetry_services": []}

    def get_windows_privacy_status(self) -> Dict[str, Any]:
        """Queries the current status of Windows telemetry services and registry keys."""
        status = {"os": "Windows"}

        if not IS_WINDOWS:
            status["diagtrack_running"] = False
            status["dmwappushservice_running"] = False
            status["advertising_id_enabled"] = False
            return status

        # 1. DiagTrack Service
        success, out = self._run_cmd(["sc", "query", "DiagTrack"])
        status["diagtrack_running"] = "RUNNING" in out
        
        # 2. dmwappushservice
        success, out = self._run_cmd(["sc", "query", "dmwappushservice"])
        status["dmwappushservice_running"] = "RUNNING" in out

        # 3. Advertising ID
        if winreg:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo") as key:
                    val, _ = winreg.QueryValueEx(key, "Enabled")
                    status["advertising_id_enabled"] = bool(val)
            except Exception:
                status["advertising_id_enabled"] = False
        else:
            status["advertising_id_enabled"] = False

        return status

    def get_linux_privacy_status(self) -> Dict[str, Any]:
        """Queries status of known Linux telemetry and crash report submitters."""
        distro_info = PlatformHelper.get_linux_distro_info()
        status = {
            "os": "Linux",
            "distro": distro_info["pretty_name"],
            "distro_family": distro_info["family"],
            "services": {}
        }

        # Known Linux telemetry daemons
        telemetry_daemons = [
            ("whoopsie", "Ubuntu Crash Database Submitter (daisy.ubuntu.com)"),
            ("apport", "Ubuntu Automated Crash Reporting System"),
            ("popularity-contest", "Debian/Ubuntu Package Usage Survey (popcon)"),
            ("ubuntu-report", "Canonical Metrics & Hardware Profiler"),
            ("abrt-journal-core", "Fedora/RHEL Automated Bug Reporting"),
            ("insights-client", "Red Hat Insights Telemetry Agent"),
            ("systemd-coredump", "Systemd Core Dump Archiver")
        ]

        for s_name, desc in telemetry_daemons:
            is_active = False
            is_installed = False

            if shutil.which("systemctl"):
                s_code, out = self._run_cmd(["systemctl", "is-active", s_name])
                is_active = (s_code and "active" in out.strip())
                # Check if unit file exists
                u_code, u_out = self._run_cmd(["systemctl", "list-unit-files", f"{s_name}*"])
                is_installed = s_name in u_out
            elif shutil.which("service"):
                s_code, out = self._run_cmd(["service", s_name, "status"])
                is_active = "running" in out.lower()
                is_installed = True

            # If binary exists in path
            if shutil.which(s_name) or shutil.which(s_name.replace(".service", "")):
                is_installed = True

            status["services"][s_name] = {
                "name": s_name,
                "description": desc,
                "installed": is_installed,
                "running": is_active,
                "blocked": not is_active if is_installed else True
            }

        return status

    def toggle_linux_telemetry(self, service_name: str, disable: bool) -> Dict[str, Any]:
        """Disables or enables a Linux telemetry service via systemctl."""
        if not IS_LINUX:
            return {"success": False, "error": "Not on Linux"}

        if shutil.which("systemctl"):
            if disable:
                self._run_cmd(["systemctl", "stop", service_name])
                self._run_cmd(["systemctl", "disable", service_name])
                self._run_cmd(["systemctl", "mask", service_name])
                return {"success": True, "service": service_name, "status": "Disabled & Masked"}
            else:
                self._run_cmd(["systemctl", "unmask", service_name])
                self._run_cmd(["systemctl", "enable", service_name])
                self._run_cmd(["systemctl", "start", service_name])
                return {"success": True, "service": service_name, "status": "Enabled & Started"}

        return {"success": False, "error": "systemctl not available"}

    def toggle_diagtrack(self, disable: bool) -> Dict[str, Any]:
        if not IS_WINDOWS:
            return {"success": True, "message": "Not on Windows"}
        if disable:
            self._run_cmd(["sc", "stop", "DiagTrack"])
            success, out = self._run_cmd(["sc", "config", "DiagTrack", "start=disabled"])
        else:
            success, out = self._run_cmd(["sc", "config", "DiagTrack", "start=auto"])
            self._run_cmd(["sc", "start", "DiagTrack"])
        return {"success": success, "output": out}

    def toggle_advertising_id(self, disable: bool) -> Dict[str, Any]:
        if not IS_WINDOWS or not winreg:
            return {"success": True, "message": "Not on Windows"}
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
                winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, 0 if disable else 1)
            return {"success": True}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def flush_all_tc_rules(self) -> Dict[str, Any]:
        """Flushes only rules created by TrackerControl without flushing or affecting other system firewall rules."""
        if IS_WINDOWS:
            cmd = ["powershell", "-Command", f"Get-NetFirewallRule -DisplayName '{self.rule_prefix}*' | Remove-NetFirewallRule"]
            success, out = self._run_cmd(cmd)
            return {"success": success, "output": out}
        elif IS_LINUX:
            flushed_count = 0
            # 1. Clean up TrackerControl rules from iptables OUTPUT chain without flushing the system
            if shutil.which("iptables"):
                success, out = self._run_cmd(["iptables", "-S", "OUTPUT"])
                if success and out:
                    for line in out.splitlines():
                        if "TrackerControl" in line:
                            tokens = shlex.split(line.strip())
                            if tokens and tokens[0] == "-A" and len(tokens) >= 2:
                                del_cmd = ["iptables", "-D"] + tokens[1:]
                                del_ok, _ = self._run_cmd(del_cmd)
                                if del_ok:
                                    flushed_count += 1

                # Secondary safety pass: check line numbers and delete any remaining TrackerControl rules in reverse order
                success_l, out_l = self._run_cmd(["iptables", "-L", "OUTPUT", "--line-numbers", "-n"])
                if success_l and out_l:
                    matched_nums = []
                    for line in out_l.splitlines():
                        if "TrackerControl" in line:
                            parts = line.strip().split()
                            if parts and parts[0].isdigit():
                                matched_nums.append(int(parts[0]))
                    for num in sorted(matched_nums, reverse=True):
                        del_ok, _ = self._run_cmd(["iptables", "-D", "OUTPUT", str(num)])
                        if del_ok:
                            flushed_count += 1

            # 2. Clean up nftables trackercontrol table if present
            if shutil.which("nft"):
                self._run_cmd(["nft", "flush", "table", "inet", "trackercontrol"])
                self._run_cmd(["nft", "delete", "table", "inet", "trackercontrol"])

            return {"success": True, "output": f"Flushed TrackerControl rules ({flushed_count} iptables rules removed)"}
        return {"success": True, "output": "No rules to flush"}
