#!/usr/bin/env python3
"""
Pure Python RPM Package Builder for TrackerControl PC
Builds standard RPM v3/v4 packages (.rpm) without requiring rpmbuild.
Target: Fedora, RHEL, CentOS, openSUSE, AlmaLinux, Rocky Linux
"""

import os
import sys
import struct
import hashlib
import gzip
import time

RPM_MAGIC = b"\xed\xab\xee\xdb"
HEADER_MAGIC = b"\x8e\xad\xe8\x01"

# RPM Data Types
TYPE_NULL = 0
TYPE_CHAR = 1
TYPE_INT8 = 2
TYPE_INT16 = 3
TYPE_INT32 = 4
TYPE_INT64 = 5
TYPE_STRING = 6
TYPE_BIN = 7
TYPE_STRING_ARRAY = 8
TYPE_I18NSTRING = 9

# RPM Tags
TAG_NAME = 1000
TAG_VERSION = 1001
TAG_RELEASE = 1002
TAG_SUMMARY = 1004
TAG_DESCRIPTION = 1005
TAG_BUILDTIME = 1006
TAG_SIZE = 1009
TAG_DISTRIBUTION = 1010
TAG_VENDOR = 1011
TAG_LICENSE = 1014
TAG_PACKAGER = 1015
TAG_GROUP = 1016
TAG_URL = 1020
TAG_OS = 1021
TAG_ARCH = 1022
TAG_POSTIN = 1023
TAG_PREUN = 1025
TAG_POSTUN = 1026
TAG_FILESIZES = 1028
TAG_FILEMODES = 1030
TAG_FILERDEVS = 1033
TAG_FILEMTIMES = 1034
TAG_FILEMD5S = 1035
TAG_FILELINKTOS = 1036
TAG_FILEFLAGS = 1037
TAG_FILEUSERNAME = 1039
TAG_FILEGROUPNAME = 1040
TAG_SOURCERPM = 1044
TAG_FILEVERIFYFLAGS = 1045
TAG_DIRINDEXES = 1116
TAG_BASENAMES = 1117
TAG_DIRNAMES = 1118
TAG_PAYLOADFORMAT = 1124
TAG_PAYLOADCOMPRESSOR = 1125
TAG_PAYLOADFLAGS = 1126

# Signature Tags
SIGTAG_SIZE = 1000
SIGTAG_MD5 = 1004
SIGTAG_PAYLOADSIZE = 1007
SIGTAG_SHA256 = 269


def create_cpio_entry(path, content, mode=0o100755, mtime=None):
    if mtime is None:
        mtime = int(time.time())
    if isinstance(content, str):
        content = content.encode("utf-8")
    
    # Clean leading slash for cpio
    clean_path = path.lstrip("/")
    path_bytes = clean_path.encode("utf-8") + b"\x00"
    
    # CPIO newc header: 110 bytes
    ino = 1
    uid = 0
    gid = 0
    nlink = 1
    filesize = len(content)
    devmajor = 0
    devminor = 0
    rdevmajor = 0
    rdevminor = 0
    namesize = len(path_bytes)
    check = 0
    
    header = (
        f"070701{ino:08X}{mode:08X}{uid:08X}{gid:08X}{nlink:08X}"
        f"{mtime:08X}{filesize:08X}{devmajor:08X}{devminor:08X}"
        f"{rdevmajor:08X}{rdevminor:08X}{namesize:08X}{check:08X}"
    ).encode("ascii")
    
    # Pad header + path to 4 bytes
    pad1 = b"\x00" * ((4 - ((len(header) + len(path_bytes)) % 4)) % 4)
    # Pad content to 4 bytes
    pad2 = b"\x00" * ((4 - (len(content) % 4)) % 4)
    
    return header + path_bytes + pad1 + content + pad2


def create_cpio_trailer():
    path_bytes = b"TRAILER!!!\x00"
    header = (
        f"070701{0:08X}{0:08X}{0:08X}{0:08X}{1:08X}"
        f"{0:08X}{0:08X}{0:08X}{0:08X}"
        f"{0:08X}{0:08X}{len(path_bytes):08X}{0:08X}"
    ).encode("ascii")
    pad1 = b"\x00" * ((4 - ((len(header) + len(path_bytes)) % 4)) % 4)
    return header + path_bytes + pad1


class RPMHeaderBuilder:
    def __init__(self):
        self.entries = []
        self.data = bytearray()

    def add_entry(self, tag, entry_type, value):
        offset = len(self.data)
        count = 1

        if entry_type in (TYPE_STRING, TYPE_I18NSTRING):
            val_bytes = value.encode("utf-8") + b"\x00" if isinstance(value, str) else value + b"\x00"
            self.data.extend(val_bytes)
            count = 1
        elif entry_type == TYPE_STRING_ARRAY:
            count = len(value)
            for item in value:
                val_bytes = item.encode("utf-8") + b"\x00" if isinstance(item, str) else item + b"\x00"
                self.data.extend(val_bytes)
        elif entry_type == TYPE_INT16:
            if isinstance(value, (list, tuple)):
                count = len(value)
                for v in value:
                    self.data.extend(struct.pack(">H", v & 0xFFFF))
            else:
                self.data.extend(struct.pack(">H", value & 0xFFFF))
        elif entry_type == TYPE_INT32:
            if isinstance(value, (list, tuple)):
                count = len(value)
                for v in value:
                    self.data.extend(struct.pack(">i", v))
            else:
                self.data.extend(struct.pack(">i", value))
        elif entry_type == TYPE_BIN:
            count = len(value)
            self.data.extend(value)

        self.entries.append((tag, entry_type, offset, count))

    def build(self):
        # Sort entries by tag
        self.entries.sort(key=lambda x: x[0])
        
        index_bytes = bytearray()
        for tag, entry_type, offset, count in self.entries:
            index_bytes.extend(struct.pack(">iiii", tag, entry_type, offset, count))
            
        header = HEADER_MAGIC + b"\x00\x00\x00\x00" + struct.pack(">ii", len(self.entries), len(self.data))
        return bytes(header + index_bytes + self.data)


def build_rpm_package(files, metadata, output_rpm_path):
    # 1. Build CPIO archive
    cpio_data = bytearray()
    for f in files:
        cpio_data.extend(create_cpio_entry(f["path"], f["content"], f.get("mode", 0o100755), f.get("mtime")))
    cpio_data.extend(create_cpio_trailer())
    
    # 2. Compress CPIO payload with GZIP
    payload = gzip.compress(bytes(cpio_data), mtime=0)
    
    # 3. Build Main Metadata Header
    builder = RPMHeaderBuilder()
    builder.add_entry(TAG_NAME, TYPE_STRING, metadata["name"])
    builder.add_entry(TAG_VERSION, TYPE_STRING, metadata["version"])
    builder.add_entry(TAG_RELEASE, TYPE_STRING, metadata["release"])
    builder.add_entry(TAG_SUMMARY, TYPE_I18NSTRING, metadata["summary"])
    builder.add_entry(TAG_DESCRIPTION, TYPE_I18NSTRING, metadata["description"])
    builder.add_entry(TAG_BUILDTIME, TYPE_INT32, int(time.time()))
    builder.add_entry(TAG_SIZE, TYPE_INT32, sum(len(f["content"]) for f in files))
    builder.add_entry(TAG_DISTRIBUTION, TYPE_STRING, "Universal Linux")
    builder.add_entry(TAG_VENDOR, TYPE_STRING, "TrackerControl Contributors")
    builder.add_entry(TAG_LICENSE, TYPE_STRING, metadata.get("license", "MIT"))
    builder.add_entry(TAG_GROUP, TYPE_I18NSTRING, "Applications/System")
    builder.add_entry(TAG_URL, TYPE_STRING, metadata.get("url", "https://github.com/mayankreseracher/PrivacyEnhancer"))
    builder.add_entry(TAG_OS, TYPE_STRING, "linux")
    builder.add_entry(TAG_ARCH, TYPE_STRING, "x86_64")
    builder.add_entry(TAG_SOURCERPM, TYPE_STRING, f"{metadata['name']}-{metadata['version']}-{metadata['release']}.src.rpm")
    builder.add_entry(TAG_PAYLOADFORMAT, TYPE_STRING, "cpio")
    builder.add_entry(TAG_PAYLOADCOMPRESSOR, TYPE_STRING, "gzip")
    builder.add_entry(TAG_PAYLOADFLAGS, TYPE_STRING, "6")
    
    # Post-install & pre-uninstall systemd hooks
    postin_script = """if [ $1 -eq 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
"""
    preun_script = """if [ $1 -eq 0 ]; then
    systemctl --no-reload disable --now trackercontrol.service >/dev/null 2>&1 || true
fi
"""
    postun_script = """if [ $1 -ge 1 ]; then
    systemctl try-restart trackercontrol.service >/dev/null 2>&1 || true
fi
"""
    builder.add_entry(TAG_POSTIN, TYPE_STRING, postin_script)
    builder.add_entry(TAG_PREUN, TYPE_STRING, preun_script)
    builder.add_entry(TAG_POSTUN, TYPE_STRING, postun_script)
    
    # File lists
    dirnames = []
    dir_to_idx = {}
    basenames = []
    dirindexes = []
    filesizes = []
    filemodes = []
    filemtimes = []
    filemd5s = []
    filelinktos = []
    fileflags = []
    fileusernames = []
    filegroupnames = []
    fileverifyflags = []
    filerdevs = []
    
    for f in files:
        dname = os.path.dirname(f["path"]) + "/"
        if not dname.startswith("/"):
            dname = "/" + dname
        if dname not in dir_to_idx:
            dir_to_idx[dname] = len(dirnames)
            dirnames.append(dname)
        
        dirindexes.append(dir_to_idx[dname])
        basenames.append(os.path.basename(f["path"]))
        filesizes.append(len(f["content"]))
        filemodes.append(f.get("mode", 0o100755))
        filemtimes.append(f.get("mtime", int(time.time())))
        filemd5s.append(hashlib.md5(f["content"] if isinstance(f["content"], bytes) else f["content"].encode("utf-8")).hexdigest())
        filelinktos.append("")
        fileflags.append(0)
        fileusernames.append("root")
        filegroupnames.append("root")
        fileverifyflags.append(-1)
        filerdevs.append(0)
        
    builder.add_entry(TAG_DIRNAMES, TYPE_STRING_ARRAY, dirnames)
    builder.add_entry(TAG_BASENAMES, TYPE_STRING_ARRAY, basenames)
    builder.add_entry(TAG_DIRINDEXES, TYPE_INT32, dirindexes)
    builder.add_entry(TAG_FILESIZES, TYPE_INT32, filesizes)
    builder.add_entry(TAG_FILEMODES, TYPE_INT16, filemodes)
    builder.add_entry(TAG_FILEMTIMES, TYPE_INT32, filemtimes)
    builder.add_entry(TAG_FILEMD5S, TYPE_STRING_ARRAY, filemd5s)
    builder.add_entry(TAG_FILELINKTOS, TYPE_STRING_ARRAY, filelinktos)
    builder.add_entry(TAG_FILEFLAGS, TYPE_INT32, fileflags)
    builder.add_entry(TAG_FILEUSERNAME, TYPE_STRING_ARRAY, fileusernames)
    builder.add_entry(TAG_FILEGROUPNAME, TYPE_STRING_ARRAY, filegroupnames)
    builder.add_entry(TAG_FILEVERIFYFLAGS, TYPE_INT32, fileverifyflags)
    builder.add_entry(TAG_FILERDEVS, TYPE_INT16, filerdevs)
    
    header_bytes = builder.build()
    
    # 4. Build Signature Header
    sig_builder = RPMHeaderBuilder()
    sig_builder.add_entry(SIGTAG_SIZE, TYPE_INT32, len(header_bytes) + len(payload))
    sig_builder.add_entry(SIGTAG_PAYLOADSIZE, TYPE_INT32, len(payload))
    sig_builder.add_entry(SIGTAG_MD5, TYPE_BIN, hashlib.md5(header_bytes + payload).digest())
    sig_builder.add_entry(SIGTAG_SHA256, TYPE_STRING, hashlib.sha256(header_bytes).hexdigest())
    sig_bytes = sig_builder.build()
    
    # Align signature header to 8 bytes
    pad_len = (8 - (len(sig_bytes) % 8)) % 8
    sig_bytes += b"\x00" * pad_len
    
    # 5. Build 96-byte RPM Lead
    pkg_name = f"{metadata['name']}-{metadata['version']}-{metadata['release']}".encode("ascii")[:65]
    pkg_name_padded = pkg_name.ljust(66, b"\x00")
    
    lead = (
        RPM_MAGIC +
        b"\x03\x00" +          # RPM version 3.0
        b"\x00\x00" +          # Type: binary (0)
        b"\x00\x01" +          # Arch: 1 (x86)
        pkg_name_padded +      # 66 bytes name
        b"\x00\x01" +          # OS: Linux (1)
        b"\x00\x05" +          # Signature type: 5 (Header style)
        b"\x00" * 16           # Reserved 16 bytes
    )
    assert len(lead) == 96, f"Lead length is {len(lead)}, expected 96"
    
    # 6. Write final RPM file
    os.makedirs(os.path.dirname(os.path.abspath(output_rpm_path)), exist_ok=True)
    with open(output_rpm_path, "wb") as f:
        f.write(lead)
        f.write(sig_bytes)
        f.write(header_bytes)
        f.write(payload)
        
    print(f"[+] Successfully generated RPM package: {output_rpm_path} ({os.path.getsize(output_rpm_path):,} bytes)")


def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    bin_path = os.path.join(root, "dist/linux/trackercontrol-linux")
    
    if not os.path.exists(bin_path):
        print(f"[-] Binary not found: {bin_path}")
        sys.exit(1)
        
    with open(bin_path, "rb") as f:
        bin_content = f.read()
        
    desktop_path = os.path.join(root, "packaging/trackercontrol.desktop")
    with open(desktop_path, "rb") as f:
        desktop_content = f.read()
        
    svg_path = os.path.join(root, "packaging/assets/trackercontrol.svg")
    with open(svg_path, "rb") as f:
        svg_content = f.read()
        
    service_path = os.path.join(root, "trackercontrol.service")
    with open(service_path, "rb") as f:
        service_content = f.read()
        
    files = [
        {"path": "/usr/bin/trackercontrol", "content": bin_content, "mode": 0o100755},
        {"path": "/usr/share/applications/trackercontrol.desktop", "content": desktop_content, "mode": 0o100644},
        {"path": "/usr/share/icons/hicolor/scalable/apps/trackercontrol.svg", "content": svg_content, "mode": 0o100644},
        {"path": "/lib/systemd/system/trackercontrol.service", "content": service_content, "mode": 0o100644},
    ]
    
    metadata = {
        "name": "trackercontrol",
        "version": "1.0.0",
        "release": "1",
        "summary": "Sovereign Desktop Privacy Guard, Multi-Tunnel WireGuard & Orbot Tor Firewall",
        "description": "TrackerControl PC is a specialized desktop privacy guard providing sub-second network attribution, DNS sinkholing, multi-tunnel WireGuard concurrency, Proton VPN server integration, Tor/Orbot routing, and OS telemetry suppression.",
        "license": "MIT",
        "url": "https://github.com/mayankreseracher/PrivacyEnhancer"
    }
    
    output_path = os.path.join(root, "dist/linux/trackercontrol-1.0.0-1.x86_64.rpm")
    build_rpm_package(files, metadata, output_path)


if __name__ == "__main__":
    main()
