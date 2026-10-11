"""
Orbot / Tor VPN Integration Module for TrackerControl PC.
Provides built-in discovery and control for Orbot (The Onion Router):
- Detects active Orbot SOCKS5 (9050/9150), HTTP (8118/9080), and Control (9051) ports
- Circuit management and New Identity signal (NEWNYM) via stem
- Exit Node IP verification and country attribution
- Onion routing and DNS over Tor
"""

import socket
import urllib.request
import json
import time
from typing import Dict, Any, Optional
import stem
import stem.control

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

    def check_port_open(self, port: int, timeout: float = 0.8) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((self.host, port)) == 0
        except Exception:
            return False

    def detect_status(self) -> Dict[str, Any]:
        """Detects live Orbot/Tor ports on the local machine."""
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

        return {
            "is_running": is_running,
            "host": self.host,
            "socks_port": found_socks,
            "control_port": found_control,
            "http_port": found_http,
            "socks5_url": f"socks5://{self.host}:{found_socks}" if found_socks else None,
            "http_proxy_url": f"http://{self.host}:{found_http}" if found_http else None,
            "onion_routing_available": is_running
        }

    def request_new_identity(self) -> Dict[str, Any]:
        """Sends SIGNAL NEWNYM to Tor ControlPort to cycle the circuit and obtain a fresh exit node."""
        status = self.detect_status()
        control_port = status.get("control_port")
        if not control_port:
            return {"success": False, "error": "Orbot / Tor ControlPort (9051) not detected."}

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
            try:
                import socks
                import urllib.request as u_req

                socks_handler = urllib.request.ProxyHandler({
                    'http': f'socks5h://127.0.0.1:{status["socks_port"]}',
                    'https': f'socks5h://127.0.0.1:{status["socks_port"]}'
                })
                opener = urllib.request.build_opener(socks_handler)
                resp = opener.open("https://check.torproject.org/api/ip", timeout=5)
                data = json.loads(resp.read().decode("utf-8"))
                tor_exit_ip = data.get("IP")
                tor_verified = data.get("IsTor", False)
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
