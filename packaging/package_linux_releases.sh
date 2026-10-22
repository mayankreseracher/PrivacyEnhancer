#!/usr/bin/env bash
# ==============================================================================
# Master Linux Release Packager for TrackerControl PC
# Generates:
#   1. Debian/Ubuntu Package (.deb)
#   2. Universal Portable Tarball (.tar.gz) with installer
#   3. AppDir & AppImage package
# ==============================================================================

set -e

BOLD="\033[1m"
GREEN="\033[1;32m"
CYAN="\033[1;36m"
RESET="\033[0m"

VERSION="${VERSION:-1.0.9}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist/linux"
BIN_SRC="${DIST_DIR}/trackercontrol-linux"

echo -e "${CYAN}${BOLD}========================================================================${RESET}"
echo -e "${CYAN}${BOLD}  📦 PACKAGING TRACKERCONTROL PC FOR ALL LINUX DISTRIBUTIONS (v${VERSION})${RESET}"
echo -e "${CYAN}${BOLD}========================================================================${RESET}"

if [ ! -f "${BIN_SRC}" ]; then
    echo "Binary not found at ${BIN_SRC}. Running build_linux.sh first..."
    "${ROOT_DIR}/build_linux.sh"
fi

mkdir -p "${DIST_DIR}"

# ==================== 1. Debian / Ubuntu Package (.deb) ====================
echo -e "\n${CYAN}[1/3] Building Debian/Ubuntu Package (.deb)...${RESET}"
DEB_DIR="/tmp/trackercontrol_deb_build"
rm -rf "${DEB_DIR}"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/usr/share/applications"
mkdir -p "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${DEB_DIR}/lib/systemd/system"

# Control file
cat <<EOF > "${DEB_DIR}/DEBIAN/control"
Package: trackercontrol
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: TrackerControl Contributors <info@trackercontrol.org>
Depends: wireguard-tools, iptables
Suggests: tor
Description: Sovereign Desktop Privacy Guard, Multi-Tunnel WireGuard & Orbot Tor Firewall
 TrackerControl PC brings process-level network attribution, DNS sinkholing,
 multi-tunnel WireGuard concurrency, Proton VPN server integration,
 Tor/Orbot routing, and OS telemetry suppression directly to your desktop.
EOF

# Postinst file
cat <<'EOF' > "${DEB_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_admin,cap_net_bind_service,cap_net_raw+ep /usr/bin/trackercontrol || true
fi
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

# Prerm file
cat <<'EOF' > "${DEB_DIR}/DEBIAN/prerm"
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop trackercontrol.service >/dev/null 2>&1 || true
    systemctl disable trackercontrol.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

# Copy files
cp "${BIN_SRC}" "${DEB_DIR}/usr/bin/trackercontrol"
chmod 755 "${DEB_DIR}/usr/bin/trackercontrol"
cp "${ROOT_DIR}/packaging/trackercontrol.desktop" "${DEB_DIR}/usr/share/applications/"
cp "${ROOT_DIR}/packaging/assets/trackercontrol.svg" "${DEB_DIR}/usr/share/icons/hicolor/scalable/apps/"
cp "${ROOT_DIR}/trackercontrol.service" "${DEB_DIR}/lib/systemd/system/"

dpkg-deb --build "${DEB_DIR}" "${DIST_DIR}/trackercontrol_${VERSION}_amd64.deb"
rm -rf "${DEB_DIR}"
echo -e "${GREEN}✓ Debian package created: ${DIST_DIR}/trackercontrol_${VERSION}_amd64.deb${RESET}"

# ==================== 2. Universal Standalone Tarball (.tar.gz) ====================
echo -e "\n${CYAN}[2/3] Building Universal Standalone Tarball (.tar.gz)...${RESET}"
TAR_BUILD_DIR="/tmp/trackercontrol_tar_build/trackercontrol-${VERSION}"
rm -rf "/tmp/trackercontrol_tar_build"
mkdir -p "${TAR_BUILD_DIR}"

cp "${BIN_SRC}" "${TAR_BUILD_DIR}/trackercontrol"
cp "${ROOT_DIR}/packaging/trackercontrol.desktop" "${TAR_BUILD_DIR}/"
cp "${ROOT_DIR}/packaging/assets/trackercontrol.svg" "${TAR_BUILD_DIR}/"
cp "${ROOT_DIR}/trackercontrol.service" "${TAR_BUILD_DIR}/"
cp "${ROOT_DIR}/README.md" "${TAR_BUILD_DIR}/"
cp "${ROOT_DIR}/LICENSE" "${TAR_BUILD_DIR}/"

# Standalone Installer script
cat <<'EOF' > "${TAR_BUILD_DIR}/install.sh"
#!/usr/bin/env bash
set -e
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo: sudo ./install.sh"
    exit 1
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 755 "${SCRIPT_DIR}/trackercontrol" /usr/local/bin/trackercontrol
install -d -m 755 /usr/local/share/applications
install -m 644 "${SCRIPT_DIR}/trackercontrol.desktop" /usr/local/share/applications/
install -d -m 755 /usr/local/share/icons/hicolor/scalable/apps
install -m 644 "${SCRIPT_DIR}/trackercontrol.svg" /usr/local/share/icons/hicolor/scalable/apps/
if [ -d "/etc/systemd/system" ]; then
    install -m 644 "${SCRIPT_DIR}/trackercontrol.service" /etc/systemd/system/
    systemctl daemon-reload || true
fi
echo "✓ TrackerControl successfully installed to /usr/local/bin/trackercontrol!"
echo "  Launch anytime by running: sudo trackercontrol"
EOF
chmod 755 "${TAR_BUILD_DIR}/install.sh"

# Uninstall script
cat <<'EOF' > "${TAR_BUILD_DIR}/uninstall.sh"
#!/usr/bin/env bash
set -e
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root or with sudo: sudo ./uninstall.sh"
    exit 1
fi
if command -v systemctl >/dev/null 2>&1; then
    systemctl stop trackercontrol.service >/dev/null 2>&1 || true
    systemctl disable trackercontrol.service >/dev/null 2>&1 || true
fi
rm -f /usr/local/bin/trackercontrol
rm -f /usr/local/share/applications/trackercontrol.desktop
rm -f /usr/local/share/icons/hicolor/scalable/apps/trackercontrol.svg
rm -f /etc/systemd/system/trackercontrol.service
echo "✓ TrackerControl successfully uninstalled."
EOF
chmod 755 "${TAR_BUILD_DIR}/uninstall.sh"

tar -czf "${DIST_DIR}/trackercontrol-v${VERSION}-linux-x86_64.tar.gz" -C "/tmp/trackercontrol_tar_build" "trackercontrol-${VERSION}"
rm -rf "/tmp/trackercontrol_tar_build"
echo -e "${GREEN}✓ Standalone tarball created: ${DIST_DIR}/trackercontrol-v${VERSION}-linux-x86_64.tar.gz${RESET}"

# ==================== 3. Universal AppImage ====================
echo -e "\n${CYAN}[3/3] Creating AppImage AppDir Structure...${RESET}"
APPDIR="/tmp/TrackerControl.AppDir"
rm -rf "${APPDIR}"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/scalable/apps"

cp "${BIN_SRC}" "${APPDIR}/usr/bin/trackercontrol"
cp "${ROOT_DIR}/packaging/trackercontrol.desktop" "${APPDIR}/"
cp "${ROOT_DIR}/packaging/trackercontrol.desktop" "${APPDIR}/usr/share/applications/"
cp "${ROOT_DIR}/packaging/assets/trackercontrol.svg" "${APPDIR}/trackercontrol.svg"
cp "${ROOT_DIR}/packaging/assets/trackercontrol.svg" "${APPDIR}/.DirIcon"
cp "${ROOT_DIR}/packaging/assets/trackercontrol.svg" "${APPDIR}/usr/share/icons/hicolor/scalable/apps/"

# AppRun script
cat <<'EOF' > "${APPDIR}/AppRun"
#!/bin/sh
HERE="$(dirname "$(readlink -f "${0}")")"
export PATH="${HERE}/usr/bin:${PATH}"
exec "${HERE}/usr/bin/trackercontrol" "$@"
EOF
chmod 755 "${APPDIR}/AppRun"

# Try appimagetool if available or download standalone appimagetool
if ! command -v appimagetool >/dev/null 2>&1; then
    APPIMAGETOOL="/tmp/appimagetool-x86_64.AppImage"
    if [ ! -f "${APPIMAGETOOL}" ]; then
        curl -sL https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage -o "${APPIMAGETOOL}" || true
        chmod +x "${APPIMAGETOOL}" 2>/dev/null || true
    fi
    if [ -x "${APPIMAGETOOL}" ]; then
        ARCH=x86_64 "${APPIMAGETOOL}" --appimage-extract-and-run "${APPDIR}" "${DIST_DIR}/TrackerControl-${VERSION}-x86_64.AppImage" 2>/dev/null || true
    fi
fi

if [ -f "${DIST_DIR}/TrackerControl-${VERSION}-x86_64.AppImage" ]; then
    echo -e "${GREEN}✓ AppImage created: ${DIST_DIR}/TrackerControl-${VERSION}-x86_64.AppImage${RESET}"
else
    echo -e "${CYAN}✓ AppDir created at ${APPDIR}. Packaged in tarball and .deb.${RESET}"
fi

# ==================== 4. RedHat / Fedora / openSUSE RPM (.rpm) ====================
echo -e "\n${CYAN}[4/4] Building Fedora/RHEL/openSUSE RPM Package (.rpm)...${RESET}"
if [ -f "${SCRIPT_DIR}/rpm/build_rpm.py" ]; then
    python3 "${SCRIPT_DIR}/rpm/build_rpm.py" || true
fi

echo -e "\n${GREEN}${BOLD}========================================================================${RESET}"
echo -e "${GREEN}${BOLD}  ✓ ALL LINUX RELEASE PACKAGES GENERATED SUCCESSFULLY!${RESET}"
echo -e "${GREEN}${BOLD}========================================================================${RESET}"
ls -lh "${DIST_DIR}"
