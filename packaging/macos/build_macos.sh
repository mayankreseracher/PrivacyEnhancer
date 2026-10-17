#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — macOS Application & Release Packaging Script
# Compiles TrackerControl into a standalone native macOS .app bundle and distributable archive.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist/macos"
VERSION="1.0.0"

echo "========================================================================"
echo "  [+] Building TrackerControl PC for macOS (v${VERSION})"
echo "========================================================================"

mkdir -p "${DIST_DIR}"

cd "${ROOT_DIR}"

# 1. Check Python version
PYTHON_BIN=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" >/dev/null 2>&1; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "${PYTHON_BIN}" ]; then
    echo "[-] Error: Python 3.10+ is required to build TrackerControl on macOS."
    exit 1
fi

echo "[+] Using Python: $($PYTHON_BIN --version)"

# 2. Install requirements if pyinstaller is missing
if ! "$PYTHON_BIN" -m pyinstaller --version >/dev/null 2>&1; then
    echo "[+] Installing PyInstaller and dependencies..."
    "$PYTHON_BIN" -m pip install --upgrade pip
    "$PYTHON_BIN" -m pip install pyinstaller -r requirements.txt
fi

# 3. Compile standalone binary and app bundle using PyInstaller
echo "[+] Running PyInstaller with TrackerControl.spec..."
"$PYTHON_BIN" -m pyinstaller TrackerControl.spec --noconfirm --clean

# 4. Assemble macOS App Bundle
APP_NAME="TrackerControl.app"
APP_DIR="${DIST_DIR}/${APP_NAME}"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_BIN_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"

echo "[+] Assembling macOS Application Bundle at ${APP_DIR}..."
rm -rf "${APP_DIR}"
mkdir -p "${MACOS_BIN_DIR}" "${RESOURCES_DIR}"

# Copy binary
if [ -f "dist/TrackerControl-mac" ]; then
    cp "dist/TrackerControl-mac" "${MACOS_BIN_DIR}/TrackerControl"
elif [ -f "dist/TrackerControl" ]; then
    cp "dist/TrackerControl" "${MACOS_BIN_DIR}/TrackerControl"
elif [ -d "dist/TrackerControl-PC" ]; then
    cp -R dist/TrackerControl-PC/* "${MACOS_BIN_DIR}/"
    if [ -f "${MACOS_BIN_DIR}/TrackerControl" ]; then
        chmod +x "${MACOS_BIN_DIR}/TrackerControl"
    fi
fi

chmod +x "${MACOS_BIN_DIR}/TrackerControl"

# Copy Info.plist
cp "${SCRIPT_DIR}/Info.plist" "${CONTENTS_DIR}/Info.plist"

# Copy Assets and SVG
if [ -f "packaging/assets/trackercontrol.svg" ]; then
    cp "packaging/assets/trackercontrol.svg" "${RESOURCES_DIR}/"
fi

# 5. Create Standalone Launch Script
cat << 'EOF' > "${DIST_DIR}/run_trackercontrol.sh"
#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "${DIR}/TrackerControl.app" ]; then
    echo "[+] Launching TrackerControl.app..."
    open "${DIR}/TrackerControl.app"
elif [ -f "${DIR}/TrackerControl" ]; then
    "${DIR}/TrackerControl" "$@"
else
    echo "[-] TrackerControl binary not found in ${DIR}"
fi
EOF
chmod +x "${DIST_DIR}/run_trackercontrol.sh"

# 6. Package Tarball Distribution
echo "[+] Packaging universal macOS distribution tarball..."
TARBALL="${DIST_DIR}/TrackerControl-v${VERSION}-macOS-universal.tar.gz"
tar -czf "${TARBALL}" -C "${DIST_DIR}" "${APP_NAME}" "run_trackercontrol.sh"

# 7. Create DMG if hdiutil is available (standard macOS tool)
if command -v hdiutil >/dev/null 2>&1; then
    echo "[+] Creating macOS DMG Disk Image..."
    DMG_PATH="${DIST_DIR}/TrackerControl-v${VERSION}-macOS.dmg"
    rm -f "${DMG_PATH}"
    hdiutil create -volname "TrackerControl PC" -srcfolder "${DIST_DIR}/${APP_NAME}" -ov -format UDZO "${DMG_PATH}" || true
    if [ -f "${DMG_PATH}" ]; then
        echo "[+] DMG created at: ${DMG_PATH}"
    fi
fi

echo "========================================================================"
echo "  [+] macOS Build & Packaging Complete!"
echo "  [+] App Bundle:  ${APP_DIR}"
echo "  [+] Tarball:     ${TARBALL}"
echo "========================================================================"
