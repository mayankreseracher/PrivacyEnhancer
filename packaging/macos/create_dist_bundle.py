#!/usr/bin/env python3
"""
Packages macOS distribution bundle into dist/macos/
"""
import os
import tarfile

dist_mac = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../dist/macos"))
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
os.makedirs(dist_mac, exist_ok=True)

launcher_path = os.path.join(dist_mac, "run_trackercontrol.sh")
launcher_content = """#!/usr/bin/env bash
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[+] Launching TrackerControl PC on macOS..."
if [ -d "${DIR}/TrackerControl.app" ]; then
    open "${DIR}/TrackerControl.app"
elif [ -f "${DIR}/TrackerControl" ]; then
    "${DIR}/TrackerControl" "$@"
else
    python3 main.py "$@"
fi
"""

with open(launcher_path, "w", encoding="utf-8") as f:
    f.write(launcher_content)

tar_path = os.path.join(dist_mac, "TrackerControl-v1.0.0-macOS-universal.tar.gz")
with tarfile.open(tar_path, "w:gz") as tar:
    tar.add(os.path.join(root_dir, "packaging/macos/Info.plist"), arcname="TrackerControl.app/Contents/Info.plist")
    tar.add(os.path.join(root_dir, "packaging/assets/trackercontrol.svg"), arcname="TrackerControl.app/Contents/Resources/trackercontrol.svg")
    tar.add(launcher_path, arcname="run_trackercontrol.sh")
    tar.add(os.path.join(root_dir, "start_trackercontrol_mac.sh"), arcname="TrackerControl.app/Contents/MacOS/TrackerControl")
    tar.add(os.path.join(root_dir, "README.md"), arcname="README.md")
    tar.add(os.path.join(root_dir, "LICENSE"), arcname="LICENSE")

print(f"Successfully assembled {tar_path} ({os.path.getsize(tar_path)} bytes)")
