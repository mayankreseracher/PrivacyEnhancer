#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — macOS Application & Release Packaging Script
# Compiles TrackerControl into a standalone native macOS .app bundle and distributable archive.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist/macos"
VERSION="${VERSION:-1.0.6}"

echo "========================================================================"
echo "  [+] Building TrackerControl PC for macOS (v${VERSION})"
echo "========================================================================"

mkdir -p "${DIST_DIR}"
cd "${ROOT_DIR}"

# 1. Run pure-Python macOS packager to create complete .app bundle, scripts, tarball & zip
echo "[+] Assembling macOS Application Bundle (.app), Tarball and ZIP..."
python3 packaging/macos/create_dist_bundle.py

# 2. Extract TrackerControl.app into dist/macos for DMG creation if not already there
if [ ! -d "${DIST_DIR}/TrackerControl.app" ]; then
    tar -xzf "${DIST_DIR}/TrackerControl-v${VERSION}-macOS-universal.tar.gz" -C "${DIST_DIR}" TrackerControl.app 2>/dev/null || true
fi

# 3. Create DMG disk image if hdiutil is available (standard macOS system tool)
if command -v hdiutil >/dev/null 2>&1 && [ -d "${DIST_DIR}/TrackerControl.app" ]; then
    echo "[+] Creating macOS DMG Disk Image..."
    DMG_PATH="${DIST_DIR}/TrackerControl-v${VERSION}-macOS.dmg"
    rm -f "${DMG_PATH}"
    hdiutil create -volname "TrackerControl PC" -srcfolder "${DIST_DIR}/TrackerControl.app" -ov -format UDZO "${DMG_PATH}" || true
    if [ -f "${DMG_PATH}" ]; then
        echo "[+] DMG created at: ${DMG_PATH}"
    fi
fi

echo "========================================================================"
echo "  [+] macOS Build & Packaging Complete!"
echo "========================================================================"
ls -lh "${DIST_DIR}"
