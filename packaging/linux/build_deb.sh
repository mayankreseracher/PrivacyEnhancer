#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — Debian / Ubuntu Package (.deb) Builder
# Builds a standard installable .deb package for Ubuntu, Debian, Mint, Pop!_OS.
# ==============================================================================

set -e

VERSION="1.0.0"
ARCH="amd64"
PKG_NAME="trackercontrol"
PKG_DIR="/tmp/${PKG_NAME}_${VERSION}_${ARCH}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$SCRIPT_DIR"

echo "[+] Building Debian package for ${PKG_NAME} v${VERSION} (${ARCH})..."

# Ensure binary exists
if [ ! -f "dist/linux/trackercontrol-linux" ]; then
    echo "[!] Compiling Linux binary first..."
    ./build_linux.sh
fi

rm -rf "$PKG_DIR"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/usr/share/applications"
mkdir -p "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${PKG_DIR}/etc/systemd/system"

# 1. Control file
cat <<EOF > "${PKG_DIR}/DEBIAN/control"
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: iptables, wireguard-tools
Maintainer: TrackerControl Contributors <contact@trackercontrol.org>
Description: Sovereign Desktop Privacy Guard, Multi-Tunnel WireGuard & Tor Router
 TrackerControl PC monitors and neutralizes in-app trackers, ads, and OS telemetry
 across all desktop software with deep socket attribution and real-time dashboard.
EOF

# 2. Post-installation script
cat <<EOF > "${PKG_DIR}/DEBIAN/postinst"
#!/bin/sh
set -e
chmod +x /usr/local/bin/trackercontrol-linux
systemctl daemon-reload || true
EOF
chmod 755 "${PKG_DIR}/DEBIAN/postinst"

# 3. Copy Payload files
cp "dist/linux/trackercontrol-linux" "${PKG_DIR}/usr/local/bin/trackercontrol-linux"
chmod +x "${PKG_DIR}/usr/local/bin/trackercontrol-linux"

cp "packaging/linux/trackercontrol.desktop" "${PKG_DIR}/usr/share/applications/trackercontrol.desktop"
cp "packaging/linux/trackercontrol.svg" "${PKG_DIR}/usr/share/icons/hicolor/scalable/apps/trackercontrol.svg"
cp "trackercontrol.service" "${PKG_DIR}/etc/systemd/system/trackercontrol.service"

# 4. Build .deb package
mkdir -p "dist/linux"
dpkg-deb --root-owner-group --build "$PKG_DIR" "dist/linux/${PKG_NAME}_${VERSION}_${ARCH}.deb"
rm -rf "$PKG_DIR"

echo "[✓] Debian package generated: dist/linux/${PKG_NAME}_${VERSION}_${ARCH}.deb"
ls -lh "dist/linux/${PKG_NAME}_${VERSION}_${ARCH}.deb"
