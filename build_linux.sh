#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — Native Linux Standalone Binary Compiler
# Builds a self-contained Linux executable ('trackercontrol-linux') using PyInstaller.
# Compatible with: Ubuntu, Debian, Arch, Fedora, openSUSE, Alpine, etc.
# ==============================================================================

set -e

BOLD="\033[1m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "    🐧 TRACKERCONTROL PC — NATIVE LINUX BINARY COMPILER"
echo "========================================================================"
echo -e "${RESET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 1. Setup Build Environment
echo -e "${CYAN}[1/3] Preparing Linux Build Environment...${RESET}"
BUILD_VENV="/tmp/tc_linux_build_venv"
if [ ! -d "$BUILD_VENV" ]; then
    python3 -m venv "$BUILD_VENV"
fi
source "$BUILD_VENV/bin/activate"

# 2. Check Build Dependencies
if ! command -v pyinstaller &> /dev/null; then
    echo -e "${CYAN}[2/3] Installing Python Build Prerequisites & PyInstaller...${RESET}"
    pip install --find-links ~/.cache/pip pyinstaller -r requirements.txt
else
    echo -e "${GREEN}[2/3] PyInstaller and build dependencies already prepared.${RESET}"
fi

# 3. Compile Standalone ELF Executable
echo -e "${CYAN}[3/3] Compiling Standalone Linux Binary via PyInstaller...${RESET}"

pyinstaller --clean --noconfirm \
    --name="trackercontrol-linux" \
    --add-data="frontend:frontend" \
    --add-data="data/trackers.json:data" \
    --add-data="data/companies.json:data" \
    --add-data="data/windows_telemetry.json:data" \
    --add-data="data/port_forwarding.json:data" \
    --add-data="data/wireguard_tunnels.json:data" \
    --add-data="data/app_vpn_bindings.json:data" \
    --hidden-import="uvicorn" \
    --hidden-import="uvicorn.logging" \
    --hidden-import="uvicorn.loops" \
    --hidden-import="uvicorn.loops.auto" \
    --hidden-import="uvicorn.protocols" \
    --hidden-import="uvicorn.protocols.http" \
    --hidden-import="uvicorn.protocols.http.auto" \
    --hidden-import="uvicorn.protocols.http.h11_impl" \
    --hidden-import="uvicorn.protocols.websockets" \
    --hidden-import="uvicorn.protocols.websockets.auto" \
    --hidden-import="uvicorn.protocols.websockets.wsproto_impl" \
    --hidden-import="uvicorn.lifespan" \
    --hidden-import="uvicorn.lifespan.on" \
    --hidden-import="fastapi" \
    --hidden-import="fastapi.staticfiles" \
    --hidden-import="fastapi.responses" \
    --hidden-import="fastapi.middleware.cors" \
    --hidden-import="pydantic" \
    --hidden-import="pydantic_core" \
    --hidden-import="psutil" \
    --hidden-import="dnslib" \
    --hidden-import="stem" \
    --hidden-import="stem.control" \
    --hidden-import="requests" \
    --distpath="dist/linux" \
    --workpath="/tmp/tc_linux_build" \
    --onefile \
    main.py

chmod +x dist/linux/trackercontrol-linux

# 4. Success Summary
echo -e "\n${GREEN}${BOLD}========================================================================${RESET}"
echo -e "${GREEN}${BOLD}  ✓ LINUX STANDALONE BINARY BUILT SUCCESSFULLY!${RESET}"
echo -e "${GREEN}${BOLD}========================================================================${RESET}"
echo -e "  Binary Location: ${CYAN}${SCRIPT_DIR}/dist/linux/trackercontrol-linux${RESET}"
ls -lh dist/linux/trackercontrol-linux
echo -e "  To run on Linux: ${CYAN}sudo ./dist/linux/trackercontrol-linux${RESET}\n"

rm -rf /tmp/tc_linux_build
