#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — macOS Launcher Script
# Starts TrackerControl PC with pywebview native desktop GUI and pfctl support.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "========================================================================"
echo "  [+] TrackerControl PC — macOS Sovereign Privacy Suite"
echo "========================================================================"

# Check for Python 3.10+
PYTHON_BIN=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "${PYTHON_BIN}" ]; then
    echo "[-] Error: Python 3.10+ is required."
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Tip: Run with 'sudo ./start_trackercontrol_mac.sh' to arm the BSD Packet Filter (pfctl)."
    echo "[!] Running in standard user mode (Audit & DNS sinkhole only)..."
fi

# Ensure requirements installed
if ! "$PYTHON_BIN" -c "import fastapi, uvicorn, psutil, dnslib" >/dev/null 2>&1; then
    echo "[+] Installing required Python packages..."
    "$PYTHON_BIN" -m pip install -r requirements.txt
fi

exec "$PYTHON_BIN" main.py "$@"
