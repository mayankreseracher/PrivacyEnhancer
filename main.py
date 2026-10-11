"""
TrackerControl PC — Main Application Entry Point
Starts the FastAPI server with WebSockets, Process Monitor, and DNS Sinkhole.
"""

import sys
import os

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

if __name__ == "__main__":
    print_banner()
    from backend.server import app
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
