#!/usr/bin/env python3
"""
Master macOS Distribution Packager for TrackerControl PC
Assembles a complete, self-contained macOS Application Bundle (.app),
universal runnable scripts, system installer, and compressed archives (.tar.gz and .zip).
"""

import os
import tarfile
import zipfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "../.."))
DIST_MAC = os.path.join(ROOT_DIR, "dist/macos")
os.makedirs(DIST_MAC, exist_ok=True)

# 1. Native macOS Application Executable Script for Contents/MacOS/TrackerControl
APP_EXECUTABLE = """#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — Native macOS Application Executable
# Runs the bundled application with pywebview native window or browser fallback.
# ==============================================================================
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
APP_DIR="${DIR}/../Resources/app"
cd "${APP_DIR}"

# Locate Python 3.10+
PYTHON_BIN=""
for p in python3.12 python3.11 python3.10 python3 /opt/homebrew/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
    if command -v "$p" >/dev/null 2>&1; then
        PYTHON_BIN="$p"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    if command -v osascript >/dev/null 2>&1; then
        osascript -e 'display dialog "TrackerControl PC requires Python 3.10+.\\nPlease install Python via https://python.org or Homebrew (brew install python)." buttons {"OK"} default button 1 with icon stop with title "TrackerControl PC"'
    else
        echo "[-] Error: Python 3.10+ is required to launch TrackerControl PC."
    fi
    exit 1
fi

# Auto-install minimal requirements if missing
if ! "$PYTHON_BIN" -c "import fastapi, uvicorn, psutil, dnslib, requests" >/dev/null 2>&1; then
    echo "[+] Installing required Python packages for TrackerControl..."
    "$PYTHON_BIN" -m pip install -r requirements.txt --quiet || true
fi

# Launch application
exec "$PYTHON_BIN" main.py "$@"
"""

# 2. Standalone root/terminal launcher (run_trackercontrol.sh)
STANDALONE_LAUNCHER = """#!/usr/bin/env bash
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
"""

# 3. Installer Script (install_mac.sh)
INSTALL_SCRIPT = """#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — macOS Installer
# Installs TrackerControl.app into /Applications/ and configures permissions.
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="/Applications/TrackerControl.app"

echo "========================================================================"
echo "  📦 Installing TrackerControl PC to /Applications/..."
echo "========================================================================"

if [ ! -d "${SCRIPT_DIR}/TrackerControl.app" ]; then
    echo "[-] TrackerControl.app not found in ${SCRIPT_DIR}"
    exit 1
fi

rm -rf "${TARGET}"
cp -R "${SCRIPT_DIR}/TrackerControl.app" "/Applications/"
chmod +x "${TARGET}/Contents/MacOS/TrackerControl"

# Also symlink to /usr/local/bin if directory exists
if [ -d "/usr/local/bin" ] && [ -w "/usr/local/bin" ]; then
    ln -sf "${TARGET}/Contents/MacOS/TrackerControl" "/usr/local/bin/trackercontrol" || true
    echo "[+] Symlinked command 'trackercontrol' to /usr/local/bin/trackercontrol"
fi

echo "[✓] TrackerControl PC installed successfully!"
echo "    Launch from Launchpad, Finder (/Applications), or run: open /Applications/TrackerControl.app"
"""

# 4. Uninstaller Script (uninstall_mac.sh)
UNINSTALL_SCRIPT = """#!/usr/bin/env bash
# ==============================================================================
# TrackerControl PC — macOS Uninstaller
# ==============================================================================
set -e

echo "Uninstalling TrackerControl PC..."
rm -rf "/Applications/TrackerControl.app"
rm -f "/usr/local/bin/trackercontrol"
echo "[✓] TrackerControl PC uninstalled cleanly."
"""

# Write standalone launcher to dist/macos/run_trackercontrol.sh
with open(os.path.join(DIST_MAC, "run_trackercontrol.sh"), "w", encoding="utf-8") as f:
    f.write(STANDALONE_LAUNCHER)

# Collect files to bundle into app
app_files = []

# Core entry point and requirements
app_files.append(("main.py", os.path.join(ROOT_DIR, "main.py")))
app_files.append(("requirements.txt", os.path.join(ROOT_DIR, "requirements.txt")))
app_files.append(("start_trackercontrol_mac.sh", os.path.join(ROOT_DIR, "start_trackercontrol_mac.sh")))

# Backend modules
backend_dir = os.path.join(ROOT_DIR, "backend")
for f in os.listdir(backend_dir):
    if f.endswith(".py"):
        app_files.append((f"backend/{f}", os.path.join(backend_dir, f)))

# Frontend assets
frontend_dir = os.path.join(ROOT_DIR, "frontend")
for f in os.listdir(frontend_dir):
    if f.endswith((".html", ".css", ".js", ".svg", ".png", ".ico")):
        app_files.append((f"frontend/{f}", os.path.join(frontend_dir, f)))

# Data intelligence files
data_dir = os.path.join(ROOT_DIR, "data")
for f in os.listdir(data_dir):
    if f.endswith(".json"):
        app_files.append((f"data/{f}", os.path.join(data_dir, f)))

# Create temporary app directory structure in memory/tar
tar_path = os.path.join(DIST_MAC, "TrackerControl-v1.0.0-macOS-universal.tar.gz")
zip_path = os.path.join(DIST_MAC, "TrackerControl-v1.0.0-macOS-universal.zip")

print("[+] Creating universal macOS Tarball package...")
with tarfile.open(tar_path, "w:gz") as tar:
    # 1. Info.plist
    tar.add(os.path.join(ROOT_DIR, "packaging/macos/Info.plist"), arcname="TrackerControl.app/Contents/Info.plist")
    
    # 2. SVG Icon
    tar.add(os.path.join(ROOT_DIR, "packaging/assets/trackercontrol.svg"), arcname="TrackerControl.app/Contents/Resources/trackercontrol.svg")
    
    # 3. Native executable
    exec_info = tarfile.TarInfo(name="TrackerControl.app/Contents/MacOS/TrackerControl")
    exec_bytes = APP_EXECUTABLE.encode("utf-8")
    exec_info.size = len(exec_bytes)
    exec_info.mode = 0o755
    import io
    tar.addfile(exec_info, io.BytesIO(exec_bytes))
    
    # 4. App payload (source files)
    for rel_path, abs_path in app_files:
        tar.add(abs_path, arcname=f"TrackerControl.app/Contents/Resources/app/{rel_path}")
        
    # 5. Top-level convenience scripts
    launch_info = tarfile.TarInfo(name="run_trackercontrol.sh")
    launch_bytes = STANDALONE_LAUNCHER.encode("utf-8")
    launch_info.size = len(launch_bytes)
    launch_info.mode = 0o755
    tar.addfile(launch_info, io.BytesIO(launch_bytes))
    
    inst_info = tarfile.TarInfo(name="install_mac.sh")
    inst_bytes = INSTALL_SCRIPT.encode("utf-8")
    inst_info.size = len(inst_bytes)
    inst_info.mode = 0o755
    tar.addfile(inst_info, io.BytesIO(inst_bytes))
    
    uninst_info = tarfile.TarInfo(name="uninstall_mac.sh")
    uninst_bytes = UNINSTALL_SCRIPT.encode("utf-8")
    uninst_info.size = len(uninst_bytes)
    uninst_info.mode = 0o755
    tar.addfile(uninst_info, io.BytesIO(uninst_bytes))
    
    # 6. Documentation & License
    tar.add(os.path.join(ROOT_DIR, "README.md"), arcname="README.md")
    tar.add(os.path.join(ROOT_DIR, "LICENSE"), arcname="LICENSE")

print(f"[+] Assembled {tar_path} ({os.path.getsize(tar_path):,} bytes)")

# Also create universal ZIP distribution for macOS
print("[+] Creating universal macOS ZIP package...")
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zip_f:
    zip_f.write(os.path.join(ROOT_DIR, "packaging/macos/Info.plist"), arcname="TrackerControl.app/Contents/Info.plist")
    zip_f.write(os.path.join(ROOT_DIR, "packaging/assets/trackercontrol.svg"), arcname="TrackerControl.app/Contents/Resources/trackercontrol.svg")
    zip_f.writestr("TrackerControl.app/Contents/MacOS/TrackerControl", APP_EXECUTABLE)
    
    for rel_path, abs_path in app_files:
        zip_f.write(abs_path, arcname=f"TrackerControl.app/Contents/Resources/app/{rel_path}")
        
    zip_f.writestr("run_trackercontrol.sh", STANDALONE_LAUNCHER)
    zip_f.writestr("install_mac.sh", INSTALL_SCRIPT)
    zip_f.writestr("uninstall_mac.sh", UNINSTALL_SCRIPT)
    zip_f.write(os.path.join(ROOT_DIR, "README.md"), arcname="README.md")
    zip_f.write(os.path.join(ROOT_DIR, "LICENSE"), arcname="LICENSE")

print(f"[+] Assembled {zip_path} ({os.path.getsize(zip_path):,} bytes)")
