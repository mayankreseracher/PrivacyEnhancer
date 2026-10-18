#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — Terminal / Root Launcher for macOS
# Arm BSD Packet Filter (pfctl) with administrative privileges.
# ==============================================================================
set -e
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "========================================================================"
echo "  🛡️ TrackerControl PC — macOS Sovereign Privacy Suite"
echo "========================================================================"

if [ "$EUID" -ne 0 ]; then
    echo "[!] Tip: Run with 'sudo ./run_trackercontrol.sh' to arm the BSD Packet Filter (pfctl)."
    echo "[!] Running in standard user mode (Audit & DNS sinkhole only)..."
fi

if [ -d "${DIR}/TrackerControl.app" ]; then
    exec "${DIR}/TrackerControl.app/Contents/MacOS/TrackerControl" "$@"
elif [ -f "${DIR}/main.py" ]; then
    python3 "${DIR}/main.py" "$@"
else
    echo "[-] TrackerControl application not found in ${DIR}"
    exit 1
fi
