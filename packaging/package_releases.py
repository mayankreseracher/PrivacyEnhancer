"""
Automated GitHub Release Bundler for TrackerControl PC & Linux.
Packages standalone executables into release-ready distributions:
1. TrackerControl-PC-v1.0.0-Windows-x64.zip
2. trackercontrol-v1.0.0-linux-x86_64.tar.gz
3. trackercontrol_1.0.0_amd64.deb
"""

import os
import shutil
import zipfile
import tarfile

VERSION = "1.0.0"
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIST_DIR = os.path.join(BASE_DIR, "dist")
LINUX_DIST = os.path.join(DIST_DIR, "linux")

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

def package_windows_release():
    print("[+] Packaging Windows Release...")
    win_exe = os.path.join(DIST_DIR, "TrackerControl-PC.exe")
    if not os.path.exists(win_exe):
        print(f"[!] Windows executable not found at {win_exe}. Skipping zip.")
        return

    zip_path = os.path.join(DIST_DIR, f"TrackerControl-PC-v{VERSION}-Windows-x64.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(win_exe, "TrackerControl-PC.exe")
        for f in ["start_trackercontrol.bat", "README.md", "LICENSE"]:
            src = os.path.join(BASE_DIR, f)
            if os.path.exists(src):
                z.write(src, f)

    print(f"[OK] Windows Release Bundle created: {zip_path} ({os.path.getsize(zip_path) / (1024*1024):.1f} MB)")

def package_linux_release():
    print("[+] Packaging Linux Release...")
    linux_bin = os.path.join(LINUX_DIST, "trackercontrol-linux")
    if not os.path.exists(linux_bin):
        print(f"[!] Linux binary not found at {linux_bin}. Skipping tar.gz.")
        return

    tar_path = os.path.join(DIST_DIR, f"trackercontrol-v{VERSION}-linux-x86_64.tar.gz")
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(linux_bin, arcname="trackercontrol/trackercontrol-linux")
        for f in ["start_trackercontrol.sh", "install_linux.sh", "trackercontrol.service", "README.md", "LICENSE"]:
            src = os.path.join(BASE_DIR, f)
            if os.path.exists(src):
                tar.add(src, arcname=f"trackercontrol/{f}")
        # Add desktop integration
        desktop_src = os.path.join(BASE_DIR, "packaging", "linux", "trackercontrol.desktop")
        if os.path.exists(desktop_src):
            tar.add(desktop_src, arcname="trackercontrol/trackercontrol.desktop")
        svg_src = os.path.join(BASE_DIR, "packaging", "linux", "trackercontrol.svg")
        if os.path.exists(svg_src):
            tar.add(svg_src, arcname="trackercontrol/trackercontrol.svg")

    print(f"[OK] Linux Release Tarball created: {tar_path} ({os.path.getsize(tar_path) / (1024*1024):.1f} MB)")

if __name__ == "__main__":
    package_windows_release()
    package_linux_release()
    print("[+] All release packages bundled in dist/")
