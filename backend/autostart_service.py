"""
Cross-Platform Autostart & Background Persistence Service for TrackerControl PC.
Enables starting TrackerControl silently in the background on system boot
(Windows Registry Run key, Linux XDG autostart, macOS LaunchAgent).
"""

import sys
import os
import shutil
from typing import Dict, Any

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"

APP_NAME = "TrackerControlPC"


class AutostartService:
    @staticmethod
    def get_launch_command() -> str:
        """Constructs the appropriate background launch command for the current platform."""
        if getattr(sys, "frozen", False):
            return f'"{sys.executable}" --background'
        else:
            python_exe = sys.executable
            if IS_WINDOWS:
                pythonw = os.path.join(os.path.dirname(python_exe), "pythonw.exe")
                if os.path.exists(pythonw):
                    python_exe = pythonw
            main_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "main.py"))
            return f'"{python_exe}" "{main_py}" --background'

    @staticmethod
    def is_enabled() -> bool:
        """Returns True if TrackerControl is configured to launch on system startup."""
        if IS_WINDOWS:
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as k:
                    try:
                        winreg.QueryValueEx(k, APP_NAME)
                        return True
                    except FileNotFoundError:
                        return False
            except Exception:
                return False

        elif IS_LINUX:
            desktop_file = os.path.expanduser(f"~/.config/autostart/{APP_NAME.lower()}.desktop")
            return os.path.exists(desktop_file)

        elif IS_MACOS:
            plist_file = os.path.expanduser("~/Library/LaunchAgents/org.trackercontrol.pc.plist")
            return os.path.exists(plist_file)

        return False

    @classmethod
    def enable(cls) -> bool:
        """Registers TrackerControl to launch silently in background on system startup."""
        cmd = cls.get_launch_command()

        if IS_WINDOWS:
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, cmd)
                return True
            except Exception as e:
                print(f"[Autostart] Failed to set Windows Run key: {e}")
                return False

        elif IS_LINUX:
            try:
                autostart_dir = os.path.expanduser("~/.config/autostart")
                os.makedirs(autostart_dir, exist_ok=True)
                desktop_file = os.path.join(autostart_dir, f"{APP_NAME.lower()}.desktop")
                content = f"""[Desktop Entry]
Type=Application
Version=1.0
Name=TrackerControl PC
Comment=Sovereign Desktop Privacy Guard & Threat Neutralizer
Exec={cmd}
Icon=trackercontrol
Terminal=false
StartupNotify=false
Categories=Security;Network;
X-GNOME-Autostart-enabled=true
"""
                with open(desktop_file, "w", encoding="utf-8") as f:
                    f.write(content)
                os.chmod(desktop_file, 0o755)
                return True
            except Exception as e:
                print(f"[Autostart] Failed to write Linux autostart file: {e}")
                return False

        elif IS_MACOS:
            try:
                agents_dir = os.path.expanduser("~/Library/LaunchAgents")
                os.makedirs(agents_dir, exist_ok=True)
                plist_file = os.path.join(agents_dir, "org.trackercontrol.pc.plist")
                
                # Split cmd into parts for plist array
                import shlex
                tokens = shlex.split(cmd)
                prog_args = "\n".join(f"        <string>{token}</string>" for token in tokens)

                content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.trackercontrol.pc</string>
    <key>ProgramArguments</key>
    <array>
{prog_args}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
"""
                with open(plist_file, "w", encoding="utf-8") as f:
                    f.write(content)
                return True
            except Exception as e:
                print(f"[Autostart] Failed to write macOS LaunchAgent plist: {e}")
                return False

        return False

    @classmethod
    def disable(cls) -> bool:
        """Unregisters TrackerControl from system startup."""
        if IS_WINDOWS:
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as k:
                    try:
                        winreg.DeleteValue(k, APP_NAME)
                    except FileNotFoundError:
                        pass
                return True
            except Exception as e:
                print(f"[Autostart] Failed to remove Windows Run key: {e}")
                return False

        elif IS_LINUX:
            try:
                desktop_file = os.path.expanduser(f"~/.config/autostart/{APP_NAME.lower()}.desktop")
                if os.path.exists(desktop_file):
                    os.remove(desktop_file)
                return True
            except Exception as e:
                print(f"[Autostart] Failed to remove Linux autostart file: {e}")
                return False

        elif IS_MACOS:
            try:
                plist_file = os.path.expanduser("~/Library/LaunchAgents/org.trackercontrol.pc.plist")
                if os.path.exists(plist_file):
                    os.remove(plist_file)
                return True
            except Exception as e:
                print(f"[Autostart] Failed to remove macOS LaunchAgent plist: {e}")
                return False

        return False

    @classmethod
    def toggle(cls, enable: bool) -> bool:
        if enable:
            return cls.enable()
        else:
            return cls.disable()

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        return {
            "autostart_supported": True,
            "autostart_enabled": cls.is_enabled(),
            "launch_command": cls.get_launch_command(),
            "platform": sys.platform
        }
