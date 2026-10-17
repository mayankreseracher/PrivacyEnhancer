#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[+] Launching TrackerControl PC on macOS..."
if [ -d "${DIR}/TrackerControl.app" ]; then
    open "${DIR}/TrackerControl.app"
elif [ -f "${DIR}/TrackerControl" ]; then
    "${DIR}/TrackerControl" "$@"
else
    python3 main.py "$@"
fi
