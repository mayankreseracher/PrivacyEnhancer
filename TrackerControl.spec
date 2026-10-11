# -*- mode: python ; coding: utf-8 -*-
"""
Universal PyInstaller Build Specification for TrackerControl PC
Builds standalone binary executable for Windows (.exe) and Linux (ELF binary).
Bundles all frontend assets, threat intelligence databases, and required dynamic modules.
"""

import sys
import os

block_cipher = None

# Host OS identification
IS_WIN = sys.platform == "win32"
BINARY_NAME = "TrackerControl-PC.exe" if IS_WIN else "trackercontrol-linux"

# Path separator for datas: ';' on Windows, ':' on Linux
DATA_SEP = ";" if IS_WIN else ":"

datas = [
    ('frontend', 'frontend'),
    ('data', 'data'),
]

hidden_imports = [
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.http.h11_impl',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.protocols.websockets.wsproto_impl',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',
    'fastapi',
    'fastapi.staticfiles',
    'fastapi.responses',
    'fastapi.middleware.cors',
    'pydantic',
    'pydantic_core',
    'psutil',
    'dnslib',
    'stem',
    'stem.control',
    'requests',
    'asyncio',
    'sqlite3',
    'platform',
    'shutil',
    'subprocess',
]

if IS_WIN:
    hidden_imports.append('winreg')

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'scipy', 'numpy'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# 1. Directory distribution bundle (fastest startup, easily inspectable)
exe_dir = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='TrackerControl',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe_dir,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='TrackerControl-PC',
)

# 2. Standalone Single-File Executable
exe_single = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=BINARY_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
