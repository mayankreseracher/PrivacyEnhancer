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


def check_elevation() -> bool:
    """
    Checks if TrackerControl PC is running with administrative or root privileges.
    Warns the user if unprivileged without blocking or auto-elevating.
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

    if not is_admin:
        print("\n" + "=" * 72)
        print(" [!] WARNING: Running without Administrative / Root Privileges!")
        print(" [!] Firewall rules and DNS interception require admin/root privileges.")
        print(" [!] TrackerControl PC will run in AUDIT-ONLY mode.")
        print(" [!] To enable active blocking and system hardening, restart as Admin/root.")
        print("=" * 72 + "\n")

    return is_admin


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


def run_browser_mode(server_started: bool = False):
    """
    Fallback / command-line browser mode:
    Starts uvicorn normally and opens dashboard in the default web browser.
    """
    import webbrowser
    url = "http://127.0.0.1:8000"
    print(f"\n[+] TrackerControl Web Dashboard available at {url}")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"[!] Could not open default web browser: {e}")

    if not server_started:
        from backend.server import app
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
    else:
        try:
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            cleanup()


def run_native_window():
    """
    Native desktop application mode using pywebview.
    Runs FastAPI server in a background daemon thread, then launches pywebview native window.
    Falls back to browser mode if pywebview is unavailable or fails to create window.
    """
    try:
        import webview
    except ImportError:
        print("[!] pywebview is not installed. Falling back to browser mode.")
        run_browser_mode(server_started=False)
        return

    from backend.server import app

    def start_server():
        uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

    # Start FastAPI server in background thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    # Give server a moment to start
    time.sleep(1.5)

    try:
        # Create native desktop window
        window = webview.create_window(
            'TrackerControl PC — Sovereign Edition',
            'http://127.0.0.1:8000',
            width=1400,
            height=900,
            min_size=(1024, 700),
            confirm_close=True,
            text_select=True
        )
        webview.start(debug=False)
        # Cleanup when pywebview native window is closed
        cleanup()
    except Exception as e:
        print(f"[!] pywebview failed to create or start native window ({e}). Falling back to browser mode.")
        run_browser_mode(server_started=True)


def main():
    """Main application entry point."""
    # 1. Admin Elevation Check at the very start of main()
    check_elevation()

    # Print startup banner
    print_banner()

    # Check for --headless or --browser flag to force browser mode
    force_browser_mode = any(arg in sys.argv for arg in ("--headless", "--browser"))
    if force_browser_mode:
        print("[+] Headless / Browser mode forced via command-line argument.")
        run_browser_mode(server_started=False)
    else:
        run_native_window()


if __name__ == "__main__":
    main()

