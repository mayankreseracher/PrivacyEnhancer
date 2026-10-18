#!/usr/bin/env python3
"""
Windows Release Packaging Script for TrackerControl PC.
Assembles the standalone binary, launcher scripts, documentation, and creates
the distribution zip archive in dist/TrackerControl-PC-Windows-x64.zip.
"""

import os
import sys
import zipfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
DIST_DIR = os.path.join(ROOT_DIR, "dist")
ZIP_PATH = os.path.join(DIST_DIR, "TrackerControl-PC-Windows-x64.zip")
EXE_PATH = os.path.join(DIST_DIR, "TrackerControl-PC.exe")

print("========================================================================")
print("  [+] Packaging TrackerControl PC Windows Release Archive")
print("========================================================================")

if not os.path.exists(EXE_PATH):
    print(f"[-] ERROR: Executable not found at {EXE_PATH}")
    print("[-] Please run PyInstaller first (e.g. pyinstaller TrackerControl.spec)")
    sys.exit(1)

os.makedirs(DIST_DIR, exist_ok=True)

files_to_pack = [
    (EXE_PATH, "TrackerControl-PC.exe"),
    (os.path.join(ROOT_DIR, "start_trackercontrol.bat"), "start_trackercontrol.bat"),
    (os.path.join(ROOT_DIR, "README.md"), "README.md"),
    (os.path.join(ROOT_DIR, "LICENSE"), "LICENSE")
]

# Verify all source files exist
for src, arc in files_to_pack:
    if not os.path.exists(src):
        print(f"[-] ERROR: Required packaging file missing: {src}")
        sys.exit(1)

print(f"[+] Writing compressed ZIP archive to: {ZIP_PATH}")
with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED) as z:
    for src, arc in files_to_pack:
        z.write(src, arc)
        size_kb = round(os.path.getsize(src) / 1024, 1)
        print(f"  -> Added {arc} ({size_kb} KB)")

zip_size_mb = round(os.path.getsize(ZIP_PATH) / (1024 * 1024), 2)
print(f"[+] Package created successfully: {ZIP_PATH} ({zip_size_mb} MB)")
