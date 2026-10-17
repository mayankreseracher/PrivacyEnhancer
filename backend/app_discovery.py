"""
Cross-Platform System Application Discovery Module for TrackerControl PC.
Discovers installed and running applications across Windows and all Linux Distributions:
- Linux: Freedesktop XDG .desktop entries (/usr/share/applications, ~/.local/share/applications,
  Flatpaks, Snaps), userland binaries (/usr/bin, /opt), and running processes.
- Windows: Registry Uninstall Keys (64/32-bit HKLM & HKCU), %LocalAppData% Programs,
  Start Menu shortcuts, and active running processes.
"""

import os
import sys
import shutil
import plistlib
import psutil
from typing import Dict, Any, List, Set, Optional

try:
    import winreg
except ImportError:
    winreg = None

from .platform_helper import IS_WINDOWS, IS_LINUX, IS_MACOS

SYSTEM_PROCESSES_WIN = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "fontdrvhost.exe", "dwm.exe", "sihost.exe"
}

SYSTEM_PROCESSES_LINUX = {
    "systemd", "kthreadd", "rcu_gp", "ksoftirqd", "migration", "cpuhp",
    "kworker", "idle_inject", "systemd-journal", "systemd-udevd", "cron", "dbus-daemon"
}

SYSTEM_PROCESSES_MACOS = {
    "launchd", "kernel_task", "kextd", "logd", "syslogd", "UserEventAgent",
    "fseventsd", "mediaremoted", "coreaudiod", "WindowServer", "loginwindow",
    "diskarbitrationd", "notifyd", "securityd", "powerd", "analyticsd", "diagnosticd"
}

LINUX_DESKTOP_DIRS = [
    "/usr/share/applications",
    "/usr/local/share/applications",
    os.path.expanduser("~/.local/share/applications"),
    "/var/lib/flatpak/exports/share/applications",
    os.path.expanduser("~/.local/share/flatpak/exports/share/applications"),
    "/var/lib/snapd/desktop/applications",
]

MACOS_APP_DIRS = [
    "/Applications",
    "/System/Applications",
    "/System/Applications/Utilities",
    os.path.expanduser("~/Applications")
]

def guess_app_category(name: str, exe: str, categories_str: str = "") -> str:
    combined = f"{name} {exe} {categories_str}".lower()
    if any(k in combined for k in ["browser", "webbrowser", "chrome", "brave", "firefox", "edge", "opera", "chromium", "vivaldi", "epiphany", "tor-browser", "freetube"]):
        return "Browser"
    if any(k in combined for k in ["chat", "instantmessaging", "irc", "email", "discord", "slack", "teams", "telegram", "zoom", "skype", "whatsapp", "signal", "thunderbird", "element"]):
        return "Communication"
    if any(k in combined for k in ["audiovideo", "audio", "video", "player", "recorder", "spotify", "vlc", "music", "audacity", "obs", "mpv", "kodi", "rhythmbox", "gimp", "inkscape"]):
        return "Media"
    if any(k in combined for k in ["game", "steam", "epic", "riot", "lutris", "heroic", "retroarch", "minecraft", "unity", "unreal", "blizzard"]):
        return "Gaming"
    if any(k in combined for k in ["development", "ide", "texteditor", "code", "cursor", "devenv", "git", "python", "node", "rust", "studio", "sublime", "kate", "gedit", "vim", "emacs"]):
        return "Development"
    if any(k in combined for k in ["security", "vpn", "antivirus", "defender", "proton", "nord", "express", "wireguard", "tor", "orbot", "firewall", "keepass", "bitwarden"]):
        return "Security & VPN"
    if any(k in combined for k in ["system", "utility", "settings", "monitor", "terminal", "bash", "zsh", "konsole", "gnome-terminal", "alacritty", "kitty"]):
        return "System"
    return "Application"

def get_category_icon(category: str) -> str:
    icons = {
        "Browser": "🌐",
        "Communication": "💬",
        "Media": "🎵",
        "Gaming": "🎮",
        "Development": "💻",
        "Security & VPN": "🔒",
        "System": "⚙️",
        "Application": "📦"
    }
    return icons.get(category, "📦")

class AppDiscovery:
    def __init__(self, database):
        self.database = database

    # ==================== Linux Application Discovery ====================

    def scan_linux_desktop_apps(self) -> List[Dict[str, Any]]:
        """Parses Freedesktop .desktop files for Debian, Ubuntu, Fedora, Arch, Alpine, etc."""
        apps = []
        seen_names = set()

        for dir_path in LINUX_DESKTOP_DIRS:
            if not os.path.isdir(dir_path):
                continue

            try:
                for fname in os.listdir(dir_path):
                    if not fname.endswith(".desktop"):
                        continue

                    full_path = os.path.join(dir_path, fname)
                    try:
                        entry = self._parse_desktop_file(full_path)
                        if not entry:
                            continue

                        name = entry.get("Name")
                        if not name or name.lower() in seen_names:
                            continue

                        seen_names.add(name.lower())
                        raw_exec = entry.get("Exec", "")
                        clean_exec = self._clean_linux_exec(raw_exec)
                        proc_name = os.path.basename(clean_exec.split()[0]) if clean_exec else fname.replace(".desktop", "")
                        
                        category = guess_app_category(name, proc_name, entry.get("Categories", ""))
                        publisher = "Native Linux Package"
                        if "flatpak" in full_path:
                            publisher = "Flatpak Package"
                        elif "snap" in full_path:
                            publisher = "Snap Package"
                        elif "~/.local" in full_path or "/home/" in full_path:
                            publisher = "User Local Application"

                        apps.append({
                            "name": name,
                            "process_name": proc_name,
                            "exe_path": clean_exec or full_path,
                            "publisher": publisher,
                            "version": entry.get("Version", ""),
                            "category": category,
                            "icon": get_category_icon(category),
                            "source": "linux_desktop"
                        })
                    except Exception:
                        continue
            except Exception:
                continue

        return apps

    def _parse_desktop_file(self, file_path: str) -> Optional[Dict[str, str]]:
        entry = {}
        in_entry = False
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line == "[Desktop Entry]":
                        in_entry = True
                        continue
                    elif line.startswith("[") and line.endswith("]"):
                        in_entry = False
                        continue

                    if in_entry and "=" in line:
                        k, v = line.split("=", 1)
                        entry[k.strip()] = v.strip()

            if entry.get("Type") != "Application":
                return None
            if entry.get("NoDisplay", "").lower() == "true":
                return None
            return entry
        except Exception:
            return None

    def _clean_linux_exec(self, raw_exec: str) -> str:
        """Removes %u, %U, %f, %F, %k, %i argument placeholders from Exec line."""
        tokens = raw_exec.split()
        clean = [t for t in tokens if not (t.startswith("%") and len(t) <= 3)]
        return " ".join(clean)

    # ==================== Windows Application Discovery ====================

    def scan_registry_apps(self) -> List[Dict[str, Any]]:
        if not winreg or not IS_WINDOWS:
            return []

        apps = []
        reg_targets = [
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]

        for hkey, subkey in reg_targets:
            try:
                with winreg.OpenKey(hkey, subkey) as root_key:
                    num_subkeys = winreg.QueryInfoKey(root_key)[0]
                    for i in range(num_subkeys):
                        try:
                            app_sub_name = winreg.EnumKey(root_key, i)
                            with winreg.OpenKey(root_key, app_sub_name) as app_key:
                                values = {}
                                num_values = winreg.QueryInfoKey(app_key)[1]
                                for v_idx in range(num_values):
                                    v_name, v_val, _ = winreg.EnumValue(app_key, v_idx)
                                    values[v_name] = v_val

                                display_name = values.get("DisplayName")
                                if not display_name or not isinstance(display_name, str):
                                    continue

                                if "KB" in display_name and len(display_name.split()) == 1:
                                    continue

                                publisher = values.get("Publisher") or "Unknown Publisher"
                                install_loc = values.get("InstallLocation") or ""
                                display_icon = values.get("DisplayIcon") or ""
                                version = values.get("DisplayVersion") or ""

                                exe_path = self._resolve_windows_executable(install_loc, display_icon)
                                proc_name = os.path.basename(exe_path) if exe_path else f"{display_name}.exe"
                                category = guess_app_category(display_name, proc_name)

                                apps.append({
                                    "name": display_name,
                                    "process_name": proc_name,
                                    "exe_path": exe_path or install_loc or "System Managed",
                                    "publisher": publisher,
                                    "version": version,
                                    "category": category,
                                    "icon": get_category_icon(category),
                                    "source": "registry"
                                })
                        except Exception:
                            pass
            except Exception:
                pass

        return apps

    def scan_appdata_programs(self) -> List[Dict[str, Any]]:
        if not IS_WINDOWS:
            return []

        discovered = []
        local_programs = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs")
        if os.path.isdir(local_programs):
            try:
                for entry in os.listdir(local_programs):
                    folder_path = os.path.join(local_programs, entry)
                    if os.path.isdir(folder_path):
                        for f in os.listdir(folder_path):
                            if f.lower().endswith(".exe") and not any(x in f.lower() for x in ["update", "unins", "helper"]):
                                exe_full = os.path.join(folder_path, f)
                                cat = guess_app_category(entry, f)
                                discovered.append({
                                    "name": entry.capitalize(),
                                    "process_name": f,
                                    "exe_path": exe_full,
                                    "publisher": "User Local Programs",
                                    "version": "",
                                    "category": cat,
                                    "icon": get_category_icon(cat),
                                    "source": "local_programs"
                                })
                                break
            except Exception:
                pass
        return discovered

    # ==================== macOS Application Discovery ====================

    def scan_macos_apps(self) -> List[Dict[str, Any]]:
        """Scans macOS /Applications, /System/Applications, and ~/Applications for .app bundles."""
        if not IS_MACOS and not os.path.exists("/Applications"):
            return []

        apps = []
        seen_paths = set()

        for base_dir in MACOS_APP_DIRS:
            if not os.path.isdir(base_dir):
                continue

            try:
                for item in os.listdir(base_dir):
                    if item.endswith(".app"):
                        app_bundle = os.path.join(base_dir, item)
                        if app_bundle in seen_paths:
                            continue
                        seen_paths.add(app_bundle)

                        app_info = self._parse_macos_app_bundle(app_bundle)
                        if app_info:
                            apps.append(app_info)
            except Exception:
                continue

        return apps

    def _parse_macos_app_bundle(self, bundle_path: str) -> Optional[Dict[str, Any]]:
        """Extracts metadata from a macOS .app bundle's Info.plist."""
        plist_path = os.path.join(bundle_path, "Contents", "Info.plist")
        folder_name = os.path.basename(bundle_path)[:-4]  # strip .app

        name = folder_name
        version = ""
        category_str = ""
        executable_name = ""

        if os.path.exists(plist_path):
            try:
                with open(plist_path, "rb") as f:
                    plist_data = plistlib.load(f)
                    name = plist_data.get("CFBundleDisplayName") or plist_data.get("CFBundleName") or folder_name
                    version = plist_data.get("CFBundleShortVersionString") or plist_data.get("CFBundleVersion") or ""
                    category_str = plist_data.get("LSApplicationCategoryType") or ""
                    executable_name = plist_data.get("CFBundleExecutable") or ""
            except Exception:
                pass

        if not executable_name:
            executable_name = folder_name

        macos_bin_path = os.path.join(bundle_path, "Contents", "MacOS", executable_name)
        exe_path = macos_bin_path if os.path.exists(macos_bin_path) else bundle_path

        category = guess_app_category(name, executable_name, category_str)
        publisher = "Apple System Application" if "/System/" in bundle_path else "macOS Application"

        return {
            "name": name,
            "process_name": executable_name,
            "exe_path": exe_path,
            "bundle_path": bundle_path,
            "publisher": publisher,
            "version": version,
            "category": category,
            "icon": get_category_icon(category),
            "source": "macos_apps"
        }

    # ==================== Running Process Discovery (Cross-Platform) ====================

    def scan_running_processes(self) -> List[Dict[str, Any]]:
        running_apps = []
        seen_names = set()

        for proc in psutil.process_iter(["name", "exe", "pid", "ppid"]):
            try:
                p_name = proc.info.get("name")
                p_exe = proc.info.get("exe")
                ppid = proc.info.get("ppid") or 0

                if not p_name:
                    continue

                p_lower = p_name.lower()
                # Windows system process filter
                if IS_WINDOWS and p_lower in SYSTEM_PROCESSES_WIN:
                    continue
                # Linux kernel thread / system filter (PID 2 is kthreadd)
                if IS_LINUX:
                    if ppid == 2 or p_name.startswith("[") or p_lower in SYSTEM_PROCESSES_LINUX:
                        continue
                # macOS system process filter
                if IS_MACOS and p_lower in SYSTEM_PROCESSES_MACOS:
                    continue

                if p_lower in seen_names:
                    continue
                seen_names.add(p_lower)

                clean_name = os.path.splitext(p_name)[0].capitalize()
                category = guess_app_category(clean_name, p_name)

                running_apps.append({
                    "name": clean_name,
                    "process_name": p_name,
                    "exe_path": p_exe or p_name,
                    "publisher": "Active Running Process",
                    "version": "Live",
                    "category": category,
                    "icon": get_category_icon(category),
                    "source": "running"
                })
            except Exception:
                pass

        return running_apps

    # ==================== Unified Aggregation ====================

    def get_all_system_apps(self, query: str = "") -> List[Dict[str, Any]]:
        """
        Gathers installed software across system catalogs (Linux Desktop / Windows Registry),
        local directories, and running processes.
        """
        all_apps: Dict[str, Dict[str, Any]] = {}

        # 1. Running processes first (highest certainty)
        for app in self.scan_running_processes():
            key = app["process_name"].lower()
            app["is_running"] = True
            all_apps[key] = app

        # 2. Linux Desktop apps if on Linux
        if IS_LINUX:
            for app in self.scan_linux_desktop_apps():
                key = app["process_name"].lower()
                if key not in all_apps:
                    app["is_running"] = False
                    all_apps[key] = app
                else:
                    all_apps[key]["name"] = app["name"]
                    all_apps[key]["publisher"] = app["publisher"]
                    if app.get("version"):
                        all_apps[key]["version"] = app["version"]

        # 3. Windows Registry & AppData if on Windows
        if IS_WINDOWS:
            for app in self.scan_appdata_programs():
                key = app["process_name"].lower()
                if key not in all_apps:
                    app["is_running"] = False
                    all_apps[key] = app

            for app in self.scan_registry_apps():
                key = app["process_name"].lower()
                if key not in all_apps:
                    app["is_running"] = False
                    all_apps[key] = app
                else:
                    all_apps[key]["name"] = app["name"]
                    all_apps[key]["publisher"] = app["publisher"]
                    if app.get("version"):
                        all_apps[key]["version"] = app["version"]

        # 4. macOS .app bundles if on macOS
        if IS_MACOS or (not IS_WINDOWS and not IS_LINUX and os.path.exists("/Applications")):
            for app in self.scan_macos_apps():
                key = app["process_name"].lower()
                if key not in all_apps:
                    app["is_running"] = False
                    all_apps[key] = app
                else:
                    all_apps[key]["name"] = app["name"]
                    all_apps[key]["publisher"] = app["publisher"]
                    if app.get("version"):
                        all_apps[key]["version"] = app["version"]
                    if app.get("bundle_path"):
                        all_apps[key]["bundle_path"] = app["bundle_path"]

        # 5. Check existing apps in TrackerControl DB
        existing_apps = {a["process_name"].lower(): a for a in self.database.get_all_apps()}

        result_list = []
        q = (query or "").lower().strip()

        for key, app in all_apps.items():
            app["is_managed"] = key in existing_apps
            app["current_mode"] = existing_apps[key]["control_mode"] if key in existing_apps else "unmanaged"

            if q:
                searchable = f"{app['name']} {app['process_name']} {app['publisher']} {app['category']}".lower()
                if q not in searchable:
                    continue

            result_list.append(app)

        # Sort: Running first, then Alphabetical
        result_list.sort(key=lambda x: (not x.get("is_running", False), x["name"].lower()))
        return result_list

    def _resolve_windows_executable(self, install_loc: str, display_icon: str) -> Optional[str]:
        if display_icon:
            clean = display_icon.split(",")[0].strip(' "').strip()
            if clean.lower().endswith(".exe") and os.path.exists(clean):
                return clean

        if install_loc and os.path.isdir(install_loc):
            try:
                for f in os.listdir(install_loc):
                    if f.lower().endswith(".exe") and not any(x in f.lower() for x in ["unins", "update", "helper", "crash"]):
                        cand = os.path.join(install_loc, f)
                        if os.path.isfile(cand):
                            return cand
            except Exception:
                pass
        return None
