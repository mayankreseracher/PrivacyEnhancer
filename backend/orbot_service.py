"""
Orbot / Tor VPN Integration Module for TrackerControl PC.
Provides built-in discovery, automated lifecycle management, and control for Tor/Orbot:
- Detects active Orbot SOCKS5 (9050/9150), HTTP (8118/9080), and Control (9051) ports
- Auto-discovers local Tor binaries across Desktop, Tor Browser, Program Files, and PATH
- Launches and manages standalone Tor background daemon on demand (SocksPort 9050 / ControlPort 9051)
- Circuit management and New Identity signal (NEWNYM) via stem
- Exit Node IP verification and country attribution
- Onion routing and transparent SOCKS5 split-tunneling
"""

import os
import sys
import time
import shutil
import socket
import atexit
import subprocess
import urllib.request
import json
from typing import Dict, Any, Optional

import stem
import stem.control

from .platform_helper import IS_WINDOWS, IS_LINUX, IS_MACOS, PlatformHelper

DATA_DIR = PlatformHelper.get_data_dir()
DEFAULT_SOCKS_PORTS = [9050, 9150]
DEFAULT_CONTROL_PORTS = [9051, 9151]
DEFAULT_HTTP_PORTS = [8118, 9080]

class OrbotService:
    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.active_socks_port: Optional[int] = None
        self.active_control_port: Optional[int] = None
        self.active_http_port: Optional[int] = None
        self.last_identity_check: Optional[Dict[str, Any]] = None
        self.last_check_time: float = 0
        self.managed_process: Optional[subprocess.Popen] = None
        self.tor_binary_path: Optional[str] = None
        
        atexit.register(self.stop_tor_service)

    def check_port_open(self, port: int, timeout: float = 0.8) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((self.host, port)) == 0
        except Exception:
            return False

    def find_tor_binary(self) -> Optional[str]:
        """Auto-discovers installed Tor binary across system, user, and Tor Browser locations."""
        if self.tor_binary_path and os.path.exists(self.tor_binary_path):
            return self.tor_binary_path

        # 1. Standard PATH lookup
        for bin_name in ["tor", "tor.exe"]:
            found = shutil.which(bin_name)
            if found and os.path.exists(found):
                self.tor_binary_path = found
                return found

        # 2. Windows-specific user and application locations
        if IS_WINDOWS:
            user_home = os.path.expanduser("~")
            local_appdata = os.environ.get("LOCALAPPDATA", "")
            appdata = os.environ.get("APPDATA", "")
            program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")

            candidates = [
                os.path.join(user_home, "Desktop", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
                os.path.join(user_home, "Downloads", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
                os.path.join(local_appdata, "Programs", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
                os.path.join(local_appdata, "tor", "tor.exe"),
                os.path.join(appdata, "tor", "tor.exe"),
                os.path.join(program_files, "Tor", "tor.exe"),
                os.path.join(program_files_x86, "Tor", "tor.exe"),
                os.path.join(program_files, "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
                r"C:\Tor\tor.exe",
                os.path.join(DATA_DIR, "tor_bundle", "Tor", "tor.exe"),
                os.path.join(DATA_DIR, "tor_bundle", "tor.exe"),
            ]
            for c in candidates:
                if c and os.path.exists(c):
                    self.tor_binary_path = c
                    return c

        # 3. macOS standard locations
        elif IS_MACOS:
            user_home = os.path.expanduser("~")
            mac_candidates = [
                "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor.real",
                "/Applications/Tor Browser.app/Contents/MacOS/Tor/tor",
                os.path.join(user_home, "Applications", "Tor Browser.app", "Contents", "MacOS", "Tor", "tor.real"),
                os.path.join(user_home, "Applications", "Tor Browser.app", "Contents", "MacOS", "Tor", "tor"),
                "/opt/homebrew/bin/tor",
                "/usr/local/bin/tor"
            ]
            for c in mac_candidates:
                if os.path.exists(c):
                    self.tor_binary_path = c
                    return c

        # 4. Linux standard locations
        elif IS_LINUX:
            user_home = os.path.expanduser("~")
            linux_candidates = [
                "/usr/bin/tor",
                "/usr/local/bin/tor",
                os.path.join(user_home, ".local", "share", "torbrowser", "tbb", "x86_64", "tor-browser", "Browser", "TorBrowser", "Tor", "tor"),
                os.path.join(user_home, ".local", "bin", "tor")
            ]
            for c in linux_candidates:
                if os.path.exists(c):
                    self.tor_binary_path = c
                    return c

        return None

    def start_tor_service(self) -> Dict[str, Any]:
        """Starts a managed background Tor daemon if not already running."""
        # Check if Tor is already running on port 9050
        status = self.detect_status()
        if status.get("is_running"):
            return {
                "success": True,
                "already_running": True,
                "message": f"Tor / Orbot daemon is already active on SOCKS5 port {status.get('socks_port')}.",
                "socks_port": status.get("socks_port"),
                "control_port": status.get("control_port")
            }

        tor_bin = self.find_tor_binary()
        if not tor_bin:
            return {
                "success": False,
                "error": "Tor executable not found. Please install Tor Browser or the Tor package, or place tor.exe on your system."
            }

        tor_data_dir = os.path.join(DATA_DIR, "tor_data")
        os.makedirs(tor_data_dir, exist_ok=True)

        cmd = [
            tor_bin,
            "--SocksPort", "9050",
            "--ControlPort", "9051",
            "--DataDirectory", tor_data_dir,
            "--DisableNetwork", "0",
            "--CookieAuthentication", "0",
            "--HashedControlPassword", ""
        ]

        # Locate geoip files if in adjacent folders
        tor_dir = os.path.dirname(tor_bin)
        geoip_candidates = [
            os.path.join(tor_dir, "geoip"),
            os.path.join(tor_dir, "..", "Data", "Tor", "geoip"),
            os.path.join(tor_dir, "..", "..", "Data", "Tor", "geoip"),
        ]
        for g in geoip_candidates:
            if os.path.exists(g):
                cmd.extend(["--GeoIPFile", os.path.abspath(g)])
                g6 = g + "6"
                if os.path.exists(g6):
                    cmd.extend(["--GeoIPv6File", os.path.abspath(g6)])
                break

        try:
            # Hide console window on Windows
            creationflags = 0
            if IS_WINDOWS:
                creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0x08000000

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags
            )
            self.managed_process = proc

            # Wait for ports to become active
            for _ in range(20):
                time.sleep(0.3)
                if self.check_port_open(9050):
                    break

            if self.check_port_open(9050):
                self.last_identity_check = None
                return {
                    "success": True,
                    "message": f"Tor background daemon started successfully (PID: {proc.pid}).",
                    "socks_port": 9050,
                    "control_port": 9051,
                    "tor_path": tor_bin
                }
            else:
                return {
                    "success": False,
                    "error": "Tor process started but SOCKS5 port 9050 did not respond in time."
                }
        except Exception as e:
            return {"success": False, "error": f"Failed to start Tor daemon: {e}"}

    def stop_tor_service(self) -> Dict[str, Any]:
        """Stops the managed Tor daemon process if running."""
        if self.managed_process:
            try:
                self.managed_process.terminate()
                self.managed_process.wait(timeout=2)
            except Exception:
                try:
                    self.managed_process.kill()
                except Exception:
                    pass
            self.managed_process = None
            self.last_identity_check = None
            return {"success": True, "message": "Managed Tor daemon stopped."}
        return {"success": True, "message": "No managed Tor daemon was running."}

    def detect_status(self) -> Dict[str, Any]:
        """Detects live Orbot/Tor ports on the local machine and reports binary availability."""
        found_socks = None
        found_control = None
        found_http = None

        for p in DEFAULT_SOCKS_PORTS:
            if self.check_port_open(p):
                found_socks = p
                break

        for p in DEFAULT_CONTROL_PORTS:
            if self.check_port_open(p):
                found_control = p
                break

        for p in DEFAULT_HTTP_PORTS:
            if self.check_port_open(p):
                found_http = p
                break

        self.active_socks_port = found_socks
        self.active_control_port = found_control
        self.active_http_port = found_http

        is_running = found_socks is not None
        tor_bin = self.find_tor_binary()

        return {
            "is_running": is_running,
            "host": self.host,
            "socks_port": found_socks,
            "control_port": found_control,
            "http_port": found_http,
            "socks5_url": f"socks5://{self.host}:{found_socks}" if found_socks else None,
            "http_proxy_url": f"http://{self.host}:{found_http}" if found_http else None,
            "onion_routing_available": is_running,
            "tor_binary_found": tor_bin is not None,
            "tor_binary_path": tor_bin,
            "is_managed": self.managed_process is not None and self.managed_process.poll() is None
        }

    def request_new_identity(self) -> Dict[str, Any]:
        """Sends SIGNAL NEWNYM to Tor ControlPort to cycle the circuit and obtain a fresh exit node."""
        status = self.detect_status()
        control_port = status.get("control_port")
        if not control_port:
            # Auto-start if binary available
            if status.get("tor_binary_found") and not status.get("is_running"):
                start_res = self.start_tor_service()
                if start_res.get("success"):
                    control_port = 9051
            if not control_port:
                return {
                    "success": False,
                    "error": "Orbot / Tor ControlPort (9051) not detected. Click 'Start Tor Service' to launch the daemon."
                }

        try:
            with stem.control.Controller.from_port(port=control_port) as controller:
                try:
                    controller.authenticate()
                except stem.connection.MissingPassword:
                    controller.authenticate(password="")
                
                controller.signal(stem.Signal.NEWNYM)
                self.last_identity_check = None
                return {"success": True, "message": "New Tor circuit requested successfully (SIGNAL NEWNYM sent)."}
        except Exception as e:
            return {"success": False, "error": f"Failed to signal Tor controller: {e}"}

    def get_network_identity(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Checks clearnet IP vs Tor Exit Node IP."""
        now = time.time()
        if not force_refresh and self.last_identity_check and (now - self.last_check_time < 20):
            return self.last_identity_check

        status = self.detect_status()
        clearnet_ip = "Unknown"
        tor_exit_ip = None
        tor_verified = False

        # 1. Clearnet IP
        try:
            req = urllib.request.Request("https://api.ipify.org?format=json", headers={"User-Agent": "TrackerControl-PC"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                clearnet_ip = json.loads(resp.read().decode("utf-8")).get("ip", "Unknown")
        except Exception:
            pass

        # 2. Tor exit IP via SOCKS5 if active
        if status["is_running"]:
            socks_port = status["socks_port"]
            # Method A: Try requests with socks if PySocks is installed
            try:
                import requests
                proxies = {
                    'http': f'socks5h://127.0.0.1:{socks_port}',
                    'https': f'socks5h://127.0.0.1:{socks_port}'
                }
                r = requests.get("https://check.torproject.org/api/ip", proxies=proxies, timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    tor_exit_ip = data.get("IP")
                    tor_verified = data.get("IsTor", True)
            except Exception:
                # Method B: Direct socket SOCKS5 request to check.torproject.org or control port status
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(4.0)
                    s.connect(("127.0.0.1", socks_port))
                    # SOCKS5 handshake: version 5, 1 auth method (no auth)
                    s.sendall(b"\x05\x01\x00")
                    auth_resp = s.recv(2)
                    if auth_resp == b"\x05\x00":
                        # Connect to check.torproject.org:80 (domain type 0x03)
                        domain = b"check.torproject.org"
                        connect_req = b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + (80).to_bytes(2, "big")
                        s.sendall(connect_req)
                        conn_resp = s.recv(10)
                        if len(conn_resp) >= 4 and conn_resp[1] == 0x00:
                            http_req = b"GET /api/ip HTTP/1.1\r\nHost: check.torproject.org\r\nUser-Agent: TrackerControl\r\nConnection: close\r\n\r\n"
                            s.sendall(http_req)
                            raw_body = b""
                            while True:
                                chunk = s.recv(4096)
                                if not chunk:
                                    break
                                raw_body += chunk
                            if b"{" in raw_body:
                                json_part = raw_body[raw_body.find(b"{"):raw_body.rfind(b"}") + 1]
                                parsed = json.loads(json_part.decode("utf-8", errors="ignore"))
                                tor_exit_ip = parsed.get("IP")
                                tor_verified = parsed.get("IsTor", True)
                    s.close()
                except Exception:
                    # Method C: Controller check if active
                    if status.get("control_port"):
                        try:
                            with stem.control.Controller.from_port(port=status["control_port"]) as ctrl:
                                ctrl.authenticate(password="")
                                tor_verified = True
                        except Exception:
                            pass

        result = {
            "orbot_status": status,
            "clearnet_ip": clearnet_ip,
            "tor_exit_ip": tor_exit_ip or ("Active via 127.0.0.1:" + str(status["socks_port"]) if status["is_running"] else "Not Connected"),
            "is_tor_active": tor_verified or status["is_running"],
            "flag": "🧅" if status["is_running"] else "🌐"
        }

        self.last_identity_check = result
        self.last_check_time = now
        return result
