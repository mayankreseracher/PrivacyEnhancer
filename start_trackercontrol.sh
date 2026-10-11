#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — Universal Linux Launcher & Distro Orchestrator
# Compatible with: Ubuntu, Debian, Linux Mint, Pop!_OS, Fedora, CentOS, RHEL,
#                  Arch Linux, Manjaro, openSUSE, Alpine, Void Linux.
# ==============================================================================

set -e

# ANSI Color codes
BOLD="\033[1m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
YELLOW="\033[1;33m"
RED="\033[1;31m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "========================================================================"
echo "    🛡️  TRACKERCONTROL PC — UNIVERSAL LINUX PRIVACY SUITE"
echo "    Process-Level Tracker Neutralization, Multi-WireGuard & Orbot"
echo "========================================================================"
echo -e "${RESET}"

# 1. Distro Detection
DISTRO_NAME="Linux"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_NAME="${PRETTY_NAME:-$NAME}"
fi
echo -e "${GREEN}[+] Detected OS:${RESET} ${DISTRO_NAME} ($(uname -m))"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 2. Check Privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Notice: Running without root/sudo.${RESET}"
    echo -e "${YELLOW}    Process socket attribution will be limited to current user processes.${RESET}"
    echo -e "${YELLOW}    For full kernel socket inspection and iptables/nftables control, re-run:${RESET}"
    echo -e "${BOLD}    sudo ./start_trackercontrol.sh${RESET}\n"
fi

# 3. Prefer Standalone Compiled Binary if present
if [ -f "dist/linux/trackercontrol-linux" ]; then
    echo -e "${GREEN}[+] Launching compiled standalone Linux binary...${RESET}"
    chmod +x dist/linux/trackercontrol-linux
    exec ./dist/linux/trackercontrol-linux "$@"
fi

# 4. Fallback: Python Runtime Check
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] python3 could not be found.${RESET}"
    echo "Please install python3 using your package manager or compile binary via ./build_linux.sh"
    exit 1
fi

# 5. Virtual Environment Setup
if [ ! -d ".venv" ]; then
    echo -e "${CYAN}[+] Creating Python virtual environment in .venv...${RESET}"
    python3 -m venv .venv || {
        echo -e "${YELLOW}[!] Could not create venv. Attempting system python directly...${RESET}"
    }
fi

if [ -d ".venv" ]; then
    source .venv/bin/activate
fi

# 6. Install Dependencies
echo -e "${CYAN}[+] Verifying Python dependencies...${RESET}"
pip install -q -r requirements.txt || {
    echo -e "${RED}[!] Failed to install dependencies. Please run 'pip install -r requirements.txt' manually.${RESET}"
}

echo -e "\n${GREEN}[+] Launching TrackerControl PC server on http://localhost:8000...${RESET}"
exec python3 main.py "$@"
