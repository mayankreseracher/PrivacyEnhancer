"""
Cross-Platform & Linux Distro Intelligence Helper for TrackerControl PC.
Provides operating system detection, Linux distribution identification (/etc/os-release),
firewall backend detection (nftables, iptables, ufw, firewalld),
and Linux OS telemetry / analytics service neutralization.
"""

import os
import sys
import platform
import shutil
import subprocess
from typing import Dict, Any, List, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"

class PlatformHelper:
    @staticmethod
    def get_os_type() -> str:
        if IS_WINDOWS:
            return "Windows"
        elif IS_LINUX:
            return "Linux"
        elif IS_MACOS:
            return "macOS"
        return sys.platform

    @staticmethod
    def get_resource_path(relative_path: str = "") -> str:
        """Resolves file paths for bundled assets (works in dev and PyInstaller frozen binary)."""
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            base = sys._MEIPASS
        else:
            base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        return os.path.join(base, relative_path) if relative_path else base

    @staticmethod
    def get_data_dir() -> str:
        """Returns the persistent writable data directory."""
        if getattr(sys, "frozen", False):
            if IS_MACOS:
                data_dir = os.path.expanduser("~/Library/Application Support/TrackerControl")
            else:
                base = os.path.dirname(sys.executable)
                data_dir = os.path.join(base, "data")
        else:
            data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
        os.makedirs(data_dir, exist_ok=True)

        # Seed initial static JSON files if missing
        for fname in ["trackers.json", "companies.json", "windows_telemetry.json"]:
            target = os.path.join(data_dir, fname)
            if not os.path.exists(target):
                src = PlatformHelper.get_resource_path(os.path.join("data", fname))
                if os.path.exists(src):
                    try:
                        shutil.copy2(src, target)
                    except Exception:
                        pass
        return data_dir

    @staticmethod
    def get_linux_distro_info() -> Dict[str, Any]:
        """Parses /etc/os-release to detect exact Linux distribution and family."""
        info = {
            "distro_id": "generic_linux",
            "distro_name": "Linux",
            "version": "",
            "family": "linux",
            "pretty_name": "Linux Standard Base",
            "package_manager": "unknown",
            "firewall_backend": "none",
            "init_system": "unknown"
        }

        if not IS_LINUX:
            return info

        # Parse /etc/os-release or /usr/lib/os-release
        os_release_paths = ["/etc/os-release", "/usr/lib/os-release"]
        for p in os_release_paths:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if "=" in line and not line.startswith("#"):
                                k, v = line.split("=", 1)
                                v = v.strip('"').strip("'")
                                if k == "ID":
                                    info["distro_id"] = v.lower()
                                elif k == "NAME":
                                    info["distro_name"] = v
                                elif k == "VERSION_ID":
                                    info["version"] = v
                                elif k == "PRETTY_NAME":
                                    info["pretty_name"] = v
                                elif k == "ID_LIKE":
                                    info["family"] = v.lower()
                except Exception:
                    pass
                break

        # Refine family
        distro_id = info["distro_id"]
        family_str = f"{distro_id} {info.get('family', '')}".lower()
        if any(d in family_str for d in ["ubuntu", "debian", "mint", "pop", "kali"]):
            info["family"] = "debian"
            info["package_manager"] = "apt"
        elif any(d in family_str for d in ["fedora", "rhel", "centos", "rocky", "alma"]):
            info["family"] = "redhat"
            info["package_manager"] = "dnf" if shutil.which("dnf") else "yum"
        elif any(d in family_str for d in ["arch", "manjaro", "endeavouros", "artix"]):
            info["family"] = "arch"
            info["package_manager"] = "pacman"
        elif any(d in family_str for d in ["suse", "opensuse"]):
            info["family"] = "suse"
            info["package_manager"] = "zypper"
        elif "alpine" in family_str:
            info["family"] = "alpine"
            info["package_manager"] = "apk"
        elif "void" in family_str:
            info["family"] = "void"
            info["package_manager"] = "xbps"

        # Detect Firewall Tool
        if shutil.which("nft"):
            info["firewall_backend"] = "nftables"
        elif shutil.which("iptables"):
            info["firewall_backend"] = "iptables"
        elif shutil.which("ufw"):
            info["firewall_backend"] = "ufw"
        elif shutil.which("firewall-cmd"):
            info["firewall_backend"] = "firewalld"

        # Detect Init System
        if os.path.exists("/run/systemd/system"):
            info["init_system"] = "systemd"
        elif shutil.which("openrc") or os.path.exists("/run/openrc"):
            info["init_system"] = "openrc"
        elif shutil.which("runit") or os.path.exists("/etc/runit"):
            info["init_system"] = "runit"
        else:
            info["init_system"] = "sysvinit"

        return info

    @staticmethod
    def get_system_summary() -> Dict[str, Any]:
        """Provides an enriched OS summary object for the frontend dashboard."""
        os_type = PlatformHelper.get_os_type()
        arch = platform.machine()
        summary = {
            "os_type": os_type,
            "architecture": arch,
            "python_version": platform.python_version(),
            "is_windows": IS_WINDOWS,
            "is_linux": IS_LINUX,
            "is_macos": IS_MACOS,
        }

        if IS_WINDOWS:
            summary["platform_name"] = f"Windows {platform.release()} ({platform.version()})"
            summary["firewall_backend"] = "Windows Advanced Firewall (netsh)"
            summary["wireguard_driver"] = "Wintun / WireGuard Service"
        elif IS_LINUX:
            distro = PlatformHelper.get_linux_distro_info()
            summary["platform_name"] = distro["pretty_name"]
            summary["distro_id"] = distro["distro_id"]
            summary["distro_family"] = distro["family"]
            summary["package_manager"] = distro["package_manager"]
            summary["firewall_backend"] = distro["firewall_backend"]
            summary["init_system"] = distro["init_system"]
            summary["has_wg_quick"] = bool(shutil.which("wg-quick"))
            summary["has_iptables"] = bool(shutil.which("iptables"))
            summary["has_nft"] = bool(shutil.which("nft"))
        elif IS_MACOS:
            mac_ver, _, _ = platform.mac_ver()
            ver_str = mac_ver if mac_ver else platform.release()
            summary["platform_name"] = f"macOS {ver_str} ({arch})"
            summary["firewall_backend"] = "BSD Packet Filter (pfctl) & ALFI"
            summary["wireguard_driver"] = "wireguard-go / utun"
            summary["has_pfctl"] = bool(shutil.which("pfctl"))
            summary["has_networksetup"] = bool(shutil.which("networksetup"))
            summary["has_wg_quick"] = bool(shutil.which("wg-quick"))
            summary["has_socketfilterfw"] = os.path.exists("/usr/libexec/ApplicationFirewall/socketfilterfw")
        else:
            summary["platform_name"] = f"Unix / {platform.system()} {platform.release()}"

        return summary
