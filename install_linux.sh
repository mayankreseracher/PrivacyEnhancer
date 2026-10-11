#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — Linux Auto-Installer & System Daemon Setup
# Supports: Ubuntu, Debian, Linux Mint, Fedora, CentOS, RHEL, Arch, openSUSE, Alpine
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
echo "    📦 TRACKERCONTROL PC — LINUX SYSTEM INSTALLER"
echo "========================================================================"
echo -e "${RESET}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run this installer as root or with sudo:${RESET}"
    echo "    sudo ./install_linux.sh"
    exit 1
fi

INSTALL_DIR="/opt/trackercontrol-pc"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${CYAN}[1/4] Detecting Package Manager & Installing System Prerequisites...${RESET}"
if command -v apt-get &> /dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3 python3-pip python3-venv wireguard-tools iptables
elif command -v dnf &> /dev/null; then
    dnf install -y python3 python3-pip wireguard-tools iptables
elif command -v pacman &> /dev/null; then
    pacman -Sy --noconfirm python python-pip wireguard-tools iptables
elif command -v zypper &> /dev/null; then
    zypper install -y python3 python3-pip wireguard-tools iptables
elif command -v apk &> /dev/null; then
    apk add python3 py3-pip wireguard-tools iptables bash
fi

echo -e "${CYAN}[2/4] Deploying TrackerControl PC to ${INSTALL_DIR}...${RESET}"
mkdir -p "${INSTALL_DIR}"
cp -ru "${SCRIPT_DIR}"/* "${INSTALL_DIR}/" || cp -r "${SCRIPT_DIR}"/* "${INSTALL_DIR}/"

echo -e "${CYAN}[3/4] Creating Virtual Environment & Installing Requirements...${RESET}"
cd "${INSTALL_DIR}"
python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt

echo -e "${CYAN}[4/4] Configuring Systemd Service...${RESET}"
if [ -d "/etc/systemd/system" ]; then
    cat <<EOF > /etc/systemd/system/trackercontrol.service
[Unit]
Description=TrackerControl PC — Sovereign Linux Privacy Guard & VPN Router
After=network.target network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python3 ${INSTALL_DIR}/main.py
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable trackercontrol.service
    systemctl restart trackercontrol.service
    echo -e "${GREEN}[✓] Systemd service 'trackercontrol' enabled and started!${RESET}"
    echo -e "${GREEN}[✓] Status check: sudo systemctl status trackercontrol${RESET}"
fi

echo -e "\n${GREEN}${BOLD}========================================================================${RESET}"
echo -e "${GREEN}${BOLD}  ✓ TRACKERCONTROL PC INSTALLED SUCCESSFULLY!${RESET}"
echo -e "${GREEN}${BOLD}========================================================================${RESET}"
echo -e "  Dashboard URL:  ${CYAN}http://localhost:8000${RESET}"
echo -e "  To manage:      ${CYAN}sudo systemctl [status|restart|stop] trackercontrol${RESET}"
echo -e "  Standalone run: ${CYAN}cd ${INSTALL_DIR} && sudo ./start_trackercontrol.sh${RESET}\n"
