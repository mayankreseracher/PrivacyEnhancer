"""
System Tray Sentry & Background Persistence Service for TrackerControl PC.
Keeps TrackerControl running continuously in the background like a sovereign VPN provider,
providing quick tray access, shield toggles, tunnel status, and graceful exit.
"""

import sys
import os
import threading
import time
import webbrowser
from typing import Optional, Callable, Any

try:
    import pystray
    from PIL import Image, ImageDraw
    PYSTRAY_AVAILABLE = True
except ImportError:
    PYSTRAY_AVAILABLE = False


def create_tray_shield_icon(active: bool = True):
    """Dynamically generates a 64x64 high-contrast privacy shield icon."""
    width = 64
    height = 64
    image = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    dc = ImageDraw.Draw(image)

    # Outer Shield Polygon
    shield_pts = [
        (32, 4),
        (58, 14),
        (58, 38),
        (32, 60),
        (6, 38),
        (6, 14)
    ]
    fill_col = (10, 25, 20, 255) if active else (40, 15, 20, 255)
    outline_col = (0, 255, 157, 255) if active else (255, 0, 85, 255)
    dc.polygon(shield_pts, fill=fill_col, outline=outline_col, width=3)

    # Inner Core Polygon / Checkmark
    inner_pts = [
        (32, 14),
        (48, 22),
        (48, 36),
        (32, 50),
        (16, 36),
        (16, 22)
    ]
    core_col = (0, 255, 157, 255) if active else (255, 0, 85, 255)
    dc.polygon(inner_pts, fill=core_col)

    return image


class TrayService:
    def __init__(self, engine=None, on_open_dashboard: Optional[Callable[[], None]] = None, on_quit: Optional[Callable[[], None]] = None):
        self.engine = engine
        self.on_open_dashboard = on_open_dashboard
        self.on_quit = on_quit
        self.icon: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        if not PYSTRAY_AVAILABLE:
            print("[TrayService] Notice: pystray or Pillow not available. Tray icon skipped (background service remains active).")
            return

        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run_tray_loop, daemon=True)
        self._thread.start()
        print("[TrayService] Background System Tray Sentry active.")

    def _run_tray_loop(self):
        try:
            image = create_tray_shield_icon(active=True)
            menu = pystray.Menu(
                pystray.MenuItem("🛡️ TrackerControl PC — Sovereign Guard", lambda: None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("🖥️ Open Dashboard", self._action_open_dashboard, default=True),
                pystray.MenuItem("⚡ Toggle Privacy Shield", self._action_toggle_shield),
                pystray.MenuItem("🔒 Multi-VPN Split Tunneling", self._action_open_vpn),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("🛑 Quit & Shutdown Engine", self._action_quit)
            )

            self.icon = pystray.Icon(
                "TrackerControlPC",
                image,
                "TrackerControl PC — Sovereign Privacy Guard",
                menu
            )
            self.icon.run()
        except Exception as e:
            print(f"[TrayService] Error in tray loop: {e}")

    def notify(self, title: str, message: str):
        """Displays a desktop tray notification if supported."""
        if self.icon and hasattr(self.icon, "notify"):
            try:
                self.icon.notify(message, title)
            except Exception:
                pass

    def _action_open_dashboard(self, icon=None, item=None):
        if self.on_open_dashboard:
            try:
                self.on_open_dashboard()
                return
            except Exception:
                pass
        webbrowser.open("http://127.0.0.1:8000")

    def _action_open_vpn(self, icon=None, item=None):
        webbrowser.open("http://127.0.0.1:8000/#vpnTab")

    def _action_toggle_shield(self, icon=None, item=None):
        if self.engine:
            current = getattr(self.engine, "shield_active", True)
            self.engine.toggle_shield(not current)
            status = "Activated" if not current else "Paused"
            self.notify("Privacy Shield", f"TrackerControl Shield {status}.")

    def _action_quit(self, icon=None, item=None):
        print("\n[TrayService] Quit selected from System Tray menu.")
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
        if self.on_quit:
            self.on_quit()
        else:
            sys.exit(0)

    def stop(self):
        self._running = False
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass
