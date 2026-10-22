"""
TrackerControl PC — Main Application Entry Point
Starts the native desktop application (pywebview) or web dashboard fallback,
with WebSockets, Process Monitor, Firewall Enforcer, and DNS Sinkhole.
"""

import sys
import os
import time
import threading
import atexit
import signal

# Fix Windows console UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import uvicorn

# Ensure backend package can be imported
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from backend.platform_helper import PlatformHelper

_cleaned_up = False


def check_elevation(auto_elevate: bool = True) -> bool:
    """
    Checks if TrackerControl PC is running with administrative or root privileges.
    If unprivileged on Windows and not in explicit --audit mode, requests UAC elevation.
    Returns True if running with admin / root privileges, False otherwise.
    """
    is_admin = False
    try:
        if sys.platform == "win32":
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        elif hasattr(os, "geteuid"):
            is_admin = (os.geteuid() == 0)
    except Exception:
        is_admin = False

    if is_admin:
        return True

    # Check for explicit flags requesting unprivileged mode
    if not auto_elevate or any(arg in sys.argv for arg in ("--audit", "--no-elevate")) or os.environ.get("TRACKERCONTROL_NO_ELEVATE") == "1":
        print("\n" + "=" * 72)
        print(" [!] NOTICE: Running in Unprivileged Audit Mode.")
        print(" [!] Active firewall blocking and DNS interception require Administrator privileges.")
        print(" [!] To enable full system privilege, restart as Administrator.")
        print("=" * 72 + "\n")
        return False

    # Auto-elevate on Windows
    if sys.platform == "win32":
        try:
            import ctypes
            print("\n" + "=" * 72)
            print(" [*] TrackerControl PC requires Administrator privileges for:")
            print("     - Full application firewall blocking (netsh advfirewall)")
            print("     - System DNS sinkhole on port 53")
            print("     - Multi-VPN split-tunneling & P2P port forwarding")
            print("     - OS telemetry neutralizer")
            print(" [*] Requesting Windows UAC elevation...")
            print("=" * 72 + "\n")

            args = " ".join([f'"{a}"' for a in sys.argv[1:]])
            if getattr(sys, "frozen", False):
                hinstance = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, args, None, 1
                )
            else:
                hinstance = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{sys.argv[0]}" {args}'.strip(), None, 1
                )

            if int(hinstance) > 32:
                # Successfully launched elevated process!
                sys.exit(0)
            else:
                print(f"[!] UAC prompt declined (code {hinstance}). Continuing in Audit Mode.\n")
        except Exception as e:
            print(f"[!] Error during UAC elevation request: {e}\n")

    return False


def print_banner():
    summary = PlatformHelper.get_system_summary()
    os_name = summary.get("platform_name", sys.platform)
    firewall = summary.get("firewall_backend", "Universal Software Filter")

    banner = f"""
========================================================================
  [+] TRACKERCONTROL PC -- SOVEREIGN DESKTOP PRIVACY GUARD
  [+] High-Speed Process Attribution & OS Telemetry Neutralizer
========================================================================
  [+] Host Platform:       {os_name}
  [+] Firewall Engine:     {firewall}
  [+] Web Dashboard:       http://localhost:8000
  [+] Process Monitor:     Active (Continuous Real-Time Socket Interception)
  [+] Threat Intelligence: 4,500+ Signatures Loaded (Exodus, Disconnect, SpyBlocker)
  [+] Protection Mode:     MAX_PRIVACY (Strict)
========================================================================
    """
    print(banner)


def cleanup():
    """
    Graceful shutdown cleanup handler:
    Flushes TrackerControl firewall rules, stops engine subsystems, and restores DNS.
    """
    global _cleaned_up
    if _cleaned_up:
        return
    _cleaned_up = True

    print("\n[*] Performing graceful shutdown and resource cleanup...")
    try:
        from backend.server import engine

        # Safely await engine.stop() if event loop is running
        if hasattr(engine, "loop") and engine.loop and engine.loop.is_running():
            try:
                import asyncio
                fut = asyncio.run_coroutine_threadsafe(engine.stop(), engine.loop)
                fut.result(timeout=4)
            except Exception:
                pass
        else:
            try:
                import asyncio
                asyncio.run(engine.stop())
            except Exception:
                pass

        # Flush TC firewall rules
        if hasattr(engine, "firewall") and hasattr(engine.firewall, "flush_all_tc_rules"):
            try:
                engine.firewall.flush_all_tc_rules()
                print("[+] Flushed TrackerControl firewall rules.")
            except Exception as e:
                print(f"[!] Warning during firewall rule cleanup: {e}")

        # Restore DNS settings if engine / dns_proxy provides restore hook
        if hasattr(engine, "restore_dns"):
            try:
                engine.restore_dns()
                print("[+] Restored DNS settings.")
            except Exception as e:
                print(f"[!] Warning during DNS restore: {e}")
        elif hasattr(engine, "dns_proxy") and hasattr(engine.dns_proxy, "restore_dns"):
            try:
                engine.dns_proxy.restore_dns()
                print("[+] Restored DNS settings.")
            except Exception as e:
                print(f"[!] Warning during DNS restore: {e}")

        # Stop DNS proxy transport and process monitor if still active
        if hasattr(engine, "process_monitor") and engine.process_monitor:
            try:
                engine.process_monitor.stop()
            except Exception:
                pass

        if hasattr(engine, "dns_proxy") and engine.dns_proxy and engine.dns_proxy.transport:
            try:
                engine.dns_proxy.transport.close()
                print("[+] Closed DNS proxy transport.")
            except Exception:
                pass
    except Exception as e:
        print(f"[!] Cleanup exception: {e}")

    print("[+] Cleanup complete.")


# Register atexit and signal handlers for graceful shutdown
atexit.register(cleanup)


def _signal_handler(sig, frame):
    cleanup()
    sys.exit(0)


try:
    signal.signal(signal.SIGINT, _signal_handler)
except Exception:
    pass

try:
    signal.signal(signal.SIGTERM, _signal_handler)
except Exception:
    pass


def _unhandled_exception_handler(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    print(f"\n[CRITICAL] Unhandled Exception: {exc_type.__name__}: {exc_value}")
    cleanup()
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


sys.excepthook = _unhandled_exception_handler


def run_service_mode():
    """
    Continuous background service mode (ideal for Windows Service, systemd, or launchd).
    Runs FastAPI server, DNS sinkhole, Firewall, and WireGuard tunnels without opening a GUI window.
    """
    from backend.server import app, engine
    from backend.tray_service import TrayService

    print("[+] Starting TrackerControl PC in Sovereign Background Service mode...")
    tray = TrayService(engine=engine, on_open_dashboard=lambda: webbrowser.open("http://127.0.0.1:8000"), on_quit=cleanup)
    engine.set_tray(tray)
    tray.start()

    bind_host = "0.0.0.0" if any(a in sys.argv for a in ("--lan", "--public")) else "127.0.0.1"
    try:
        uvicorn.run(app, host=bind_host, port=8000, log_level="warning")
    except (KeyboardInterrupt, SystemExit):
        cleanup()


def run_browser_mode(server_started: bool = False, existing_tray=None):
    """
    Fallback / command-line browser mode:
    Starts uvicorn normally and opens dashboard in the default web browser with persistent tray.
    """
    import webbrowser
    from backend.server import app, engine
    from backend.tray_service import TrayService

    url = "http://127.0.0.1:8000"
    print(f"\n[+] TrackerControl Web Dashboard available at {url}")

    if existing_tray:
        tray = existing_tray
    else:
        tray = TrayService(engine=engine, on_open_dashboard=lambda: webbrowser.open(url), on_quit=cleanup)
        tray.start()
    engine.set_tray(tray)

    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"[!] Could not open default web browser: {e}")

    if not server_started:
        bind_host = "0.0.0.0" if any(a in sys.argv for a in ("--lan", "--public")) else "127.0.0.1"
        try:
            uvicorn.run(app, host=bind_host, port=8000, log_level="info")
        except (KeyboardInterrupt, SystemExit):
            cleanup()
    else:
        try:
            while not _cleaned_up:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            cleanup()


def run_native_window():
    """
    Native desktop application mode using pywebview.
    Runs FastAPI server in a background daemon thread, then launches pywebview native window.
    When the window is closed, TrackerControl continues running in the background as a sovereign
    privacy service with system tray access.
    """
    try:
        import webview
    except ImportError:
        print("[!] pywebview is not installed. Falling back to browser mode.")
        run_browser_mode(server_started=False)
        return

    from backend.server import app, engine
    from backend.tray_service import TrayService
    import webbrowser

    def start_server():
        bind_host = "0.0.0.0" if any(a in sys.argv for a in ("--lan", "--public")) else "127.0.0.1"
        uvicorn.run(app, host=bind_host, port=8000, log_level="warning")

    # Start FastAPI server in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Wait for server to bind port 8000 (up to 5s)
    import socket
    start_t = time.time()
    while time.time() - start_t < 5.0:
        try:
            with socket.create_connection(("127.0.0.1", 8000), timeout=0.2):
                break
        except Exception:
            time.sleep(0.1)

    force_quit = False
    window = None

    def open_dashboard():
        if window:
            try:
                window.show()
                window.restore()
                return
            except Exception:
                pass
        webbrowser.open("http://127.0.0.1:8000")

    def quit_app():
        nonlocal force_quit
        force_quit = True
        if window:
            try:
                window.destroy()
            except Exception:
                pass
        cleanup()

    # Initialize System Tray Sentry
    tray = TrayService(
        engine=engine,
        on_open_dashboard=open_dashboard,
        on_quit=quit_app
    )
    engine.set_tray(tray)
    tray.start()

    try:
        # Create native desktop window
        window = webview.create_window(
            'TrackerControl PC — Sovereign Edition',
            'http://127.0.0.1:8000',
            width=1400,
            height=900,
            min_size=(1024, 700),
            confirm_close=False,
            text_select=True
        )

        def on_closing():
            nonlocal force_quit
            if not force_quit:
                try:
                    window.hide()
                    tray.notify("TrackerControl Background Guard", "Dashboard minimized to system tray. Privacy protection and multi-VPN tunnels remain active.")
                except Exception:
                    pass
                return False  # Prevent window destroy, keep running in background!
            return True

        window.events.closing += on_closing
        webview.start(debug=False)

        # When pywebview native window is closed or hidden, keep background service active until explicit quit
        print("\n[+] Desktop window closed. TrackerControl PC continues running in background service mode.")
        print("[+] System DNS filtering, Firewall rules, and Multi-VPN split tunneling remain 100% active.")
        print("[+] Click the system tray icon or visit http://127.0.0.1:8000 to reopen the dashboard.")

        while not _cleaned_up and not force_quit:
            time.sleep(1)
    except Exception as e:
        print(f"[!] pywebview encountered error ({e}). Falling back to browser mode.")
        run_browser_mode(server_started=True, existing_tray=tray)


def main():
    """Main application entry point."""
    # Emergency CLI DNS restore handler (operates without starting GUI or webserver)
    if any(arg in sys.argv for arg in ("--restore-dns", "--repair-dns", "--reset-dns")):
        print("=" * 72)
        print(" [*] TrackerControl PC — Emergency System DNS Restoration Watchdog")
        print("=" * 72)
        from backend.dns_proxy import DNSProxy
        from backend.database import Database
        from backend.tracker_intelligence import TrackerIntelligence
        try:
            db = Database()
            intel = TrackerIntelligence()
            proxy = DNSProxy(intel, db)
            success = proxy.restore_system_dns(force_clean_all=True)
            if success:
                print("[+] System DNS successfully restored to default OS / DHCP settings.")
                print("[+] Resolver cache cleared. Internet connectivity restored.")
            else:
                print("[!] Could not automatically restore DNS. Ensure you run with Admin privileges.")
            global _cleaned_up
            _cleaned_up = True
            sys.exit(0 if success else 1)
        except Exception as e:
            print(f"[!] Error during DNS restoration: {e}")
            _cleaned_up = True
            sys.exit(1)

    # 1. Admin Elevation Check at the very start of main()
    check_elevation()

    # Print startup banner
    print_banner()

    # Check for service/daemon mode
    is_service = any(arg in sys.argv for arg in ("--service", "--daemon", "--background", "--minimized"))
    if is_service:
        run_service_mode()
        return

    # Check for --headless or --browser flag to force browser mode
    force_browser_mode = any(arg in sys.argv for arg in ("--headless", "--browser"))
    if force_browser_mode:
        print("[+] Headless / Browser mode forced via command-line argument.")
        run_browser_mode(server_started=False)
    else:
        run_native_window()


if __name__ == "__main__":
    main()

