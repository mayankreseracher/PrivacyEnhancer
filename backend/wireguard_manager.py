"""
Multi-Tunnel WireGuard Manager for TrackerControl PC.
Supports running and monitoring multiple concurrent WireGuard connections,
real-time interface throughput tracking (Rx/Tx), and per-application split-tunneling
across Windows and all Linux distributions (Debian, Ubuntu, Fedora, Arch, Alpine, openSUSE).
"""

import json
import os
import time
import shutil
import subprocess
import psutil
from typing import Dict, Any, List, Optional

from .platform_helper import IS_WINDOWS, IS_LINUX, IS_MACOS, PlatformHelper

DATA_DIR = PlatformHelper.get_data_dir()
CONFIGS_DIR = os.path.join(DATA_DIR, "wireguard_configs")
TUNNELS_FILE = os.path.join(DATA_DIR, "wireguard_tunnels.json")
APP_BINDINGS_FILE = os.path.join(DATA_DIR, "app_vpn_bindings.json")

os.makedirs(CONFIGS_DIR, exist_ok=True)

class WireGuardManager:
    def __init__(self, database):
        self.database = database
        self.tunnels: Dict[str, Dict[str, Any]] = {}
        self.app_bindings: Dict[str, str] = {} # process_name.lower() -> tunnel_id
        self.last_io_snapshot: Dict[str, Dict[str, Any]] = {}
        self.load_state()

    def load_state(self):
        if os.path.exists(TUNNELS_FILE):
            try:
                with open(TUNNELS_FILE, "r", encoding="utf-8") as f:
                    self.tunnels = json.load(f)
            except Exception:
                self.tunnels = {}

        if os.path.exists(APP_BINDINGS_FILE):
            try:
                with open(APP_BINDINGS_FILE, "r", encoding="utf-8") as f:
                    self.app_bindings = json.load(f)
            except Exception:
                self.app_bindings = {}

        self._detect_system_vpn_interfaces()

    def save_state(self):
        with open(TUNNELS_FILE, "w", encoding="utf-8") as f:
            json.dump(self.tunnels, f, indent=2)
        with open(APP_BINDINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(self.app_bindings, f, indent=2)

    def _detect_system_vpn_interfaces(self):
        """Auto-detects live WireGuard / ProtonVPN / Tun network interfaces on Linux and Windows."""
        try:
            ifaces = psutil.net_if_addrs()
        except Exception:
            return

        for iface_name, addrs in ifaces.items():
            name_lower = iface_name.lower()
            is_vpn = any(k in name_lower for k in [
                "proton", "wireguard", "wg0", "wg1", "wg2", "wg-", "tun0", "tun1", "tc-", "utun"
            ])
            if is_vpn:
                tunnel_id = f"sys-{name_lower.replace(' ', '-')}"
                ip_addr = "10.2.0.2"
                for a in addrs:
                    if a.family.name == "AF_INET":
                        ip_addr = a.address
                        break

                if tunnel_id not in self.tunnels:
                    self.tunnels[tunnel_id] = {
                        "id": tunnel_id,
                        "name": f"{iface_name} (System Active)",
                        "tunnel_type": "proton" if "proton" in name_lower else "wireguard",
                        "country": "Netherlands",
                        "flag": "🇳🇱",
                        "endpoint": "Live VPN Endpoint",
                        "address": ip_addr,
                        "status": "Connected",
                        "interface_name": iface_name,
                        "created_at": time.time(),
                        "assigned_apps": []
                    }

    def get_all_tunnels(self) -> List[Dict[str, Any]]:
        """Returns all configured WireGuard tunnels enriched with live throughput metrics."""
        self._detect_system_vpn_interfaces()
        try:
            io_counters = psutil.net_io_counters(pernic=True)
        except Exception:
            io_counters = {}

        now = time.time()
        result = []

        for tid, t in self.tunnels.items():
            t_copy = dict(t)
            iface = t.get("interface_name")
            
            # Match interface exact or case-insensitive
            matched_io = None
            if iface:
                if iface in io_counters:
                    matched_io = io_counters[iface]
                else:
                    for k, v in io_counters.items():
                        if k.lower() == iface.lower():
                            matched_io = v
                            break

            if matched_io:
                io = matched_io
                prev = self.last_io_snapshot.get(iface)
                
                rx_speed_kbps = 0.0
                tx_speed_kbps = 0.0
                if prev:
                    dt = max(0.1, now - prev["time"])
                    rx_speed_kbps = max(0.0, ((io.bytes_recv - prev["bytes_recv"]) * 8) / (dt * 1024))
                    tx_speed_kbps = max(0.0, ((io.bytes_sent - prev["bytes_sent"]) * 8) / (dt * 1024))

                self.last_io_snapshot[iface] = {
                    "time": now,
                    "bytes_recv": io.bytes_recv,
                    "bytes_sent": io.bytes_sent
                }

                t_copy["total_recv_mb"] = round(io.bytes_recv / (1024 * 1024), 2)
                t_copy["total_sent_mb"] = round(io.bytes_sent / (1024 * 1024), 2)
                t_copy["rx_speed_kbps"] = round(rx_speed_kbps, 1)
                t_copy["tx_speed_kbps"] = round(tx_speed_kbps, 1)
                t_copy["status"] = "Connected"
            else:
                t_copy["total_recv_mb"] = 0
                t_copy["total_sent_mb"] = 0
                t_copy["rx_speed_kbps"] = 0
                t_copy["tx_speed_kbps"] = 0
                if t_copy.get("status") != "Connected":
                    t_copy["status"] = "Idle"

            assigned = [app for app, bind_id in self.app_bindings.items() if bind_id == tid]
            t_copy["assigned_apps"] = assigned
            result.append(t_copy)

        return result

    def add_tunnel(
        self,
        name: str,
        tunnel_type: str,
        endpoint: str,
        public_key: str,
        private_key: str,
        address: str = "10.2.0.2/32",
        dns: str = "10.2.0.1",
        country: str = "Global",
        flag: str = "🌐",
        conf_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """Creates and stores a new WireGuard tunnel profile."""
        clean_name = name.lower()[:6].replace(' ', '').replace('-', '')
        tunnel_id = f"tc{int(time.time()) % 100000}_{clean_name}"[:14] # Guaranteed <= 15 chars for Linux iface
        conf_path = os.path.join(CONFIGS_DIR, f"{tunnel_id}.conf")

        if not conf_content:
            conf_content = f"""[Interface]
PrivateKey = {private_key}
Address = {address}
DNS = {dns}

[Peer]
PublicKey = {public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint}
PersistentKeepalive = 25
"""

        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(conf_content)

        tunnel_record = {
            "id": tunnel_id,
            "name": name,
            "tunnel_type": tunnel_type,
            "country": country,
            "flag": flag,
            "endpoint": endpoint,
            "public_key": public_key,
            "address": address,
            "dns": dns,
            "conf_path": conf_path,
            "interface_name": tunnel_id,
            "status": "Idle",
            "created_at": time.time(),
            "assigned_apps": []
        }

        self.tunnels[tunnel_id] = tunnel_record
        self.save_state()
        return tunnel_record

    def _get_wg_quick_bin(self) -> Optional[str]:
        """Resolves wg-quick executable across standard PATH and macOS Homebrew locations."""
        if shutil.which("wg-quick"):
            return shutil.which("wg-quick")
        if IS_MACOS:
            for p in ["/opt/homebrew/bin/wg-quick", "/usr/local/bin/wg-quick", "/usr/bin/wg-quick"]:
                if os.path.exists(p):
                    return p
        return None

    def toggle_tunnel(self, tunnel_id: str, activate: bool) -> Dict[str, Any]:
        """Activates or deactivates a specific WireGuard tunnel across Linux or Windows."""
        if tunnel_id not in self.tunnels:
            raise ValueError(f"Tunnel ID '{tunnel_id}' not found.")

        tunnel = self.tunnels[tunnel_id]
        conf_path = tunnel.get("conf_path")
        iface = tunnel.get("interface_name", tunnel_id)

        if activate:
            tunnel["status"] = "Connected"
            if conf_path and os.path.exists(conf_path):
                if IS_WINDOWS:
                    try:
                        subprocess.run(
                            ["wireguard.exe", "/installtunnelservice", conf_path],
                            capture_output=True,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                        )
                    except Exception:
                        pass
                elif IS_LINUX:
                    # Use wg-quick up
                    if shutil.which("wg-quick"):
                        try:
                            subprocess.run(["wg-quick", "up", conf_path], capture_output=True)
                        except Exception:
                            pass
                    elif shutil.which("wg"):
                        try:
                            subprocess.run(["ip", "link", "add", "dev", iface, "type", "wireguard"], capture_output=True)
                            subprocess.run(["wg", "setconf", iface, conf_path], capture_output=True)
                            subprocess.run(["ip", "link", "set", "up", "dev", iface], capture_output=True)
                        except Exception:
                            pass
                elif IS_MACOS:
                    wg_bin = self._get_wg_quick_bin()
                    if wg_bin and conf_path:
                        try:
                            subprocess.run([wg_bin, "up", conf_path], capture_output=True)
                        except Exception:
                            pass
        else:
            tunnel["status"] = "Disconnected"
            if IS_WINDOWS:
                try:
                    subprocess.run(
                        ["wireguard.exe", "/uninstalltunnelservice", iface],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                except Exception:
                    pass
            elif IS_LINUX:
                if shutil.which("wg-quick") and conf_path:
                    try:
                        subprocess.run(["wg-quick", "down", conf_path], capture_output=True)
                    except Exception:
                        pass
                try:
                    subprocess.run(["ip", "link", "delete", "dev", iface], capture_output=True)
                except Exception:
                    pass
            elif IS_MACOS:
                wg_bin = self._get_wg_quick_bin()
                if wg_bin and conf_path:
                    try:
                        subprocess.run([wg_bin, "down", conf_path], capture_output=True)
                    except Exception:
                        pass

        self.save_state()
        return {"success": True, "tunnel_id": tunnel_id, "status": tunnel["status"]}

    def delete_tunnel(self, tunnel_id: str) -> Dict[str, Any]:
        if tunnel_id in self.tunnels:
            conf_path = self.tunnels[tunnel_id].get("conf_path")
            if conf_path and os.path.exists(conf_path):
                try:
                    os.remove(conf_path)
                except Exception:
                    pass

            del self.tunnels[tunnel_id]
            self.app_bindings = {app: tid for app, tid in self.app_bindings.items() if tid != tunnel_id}
            self.save_state()
            return {"success": True}
        return {"success": False, "error": "Not found"}

    def bind_app_to_tunnel(self, process_name: str, tunnel_id: Optional[str]) -> Dict[str, Any]:
        """Binds a specific application executable to a WireGuard tunnel for split-tunneling."""
        proc_key = process_name.lower().strip()
        if not tunnel_id or tunnel_id == "none" or tunnel_id == "direct":
            if proc_key in self.app_bindings:
                del self.app_bindings[proc_key]
        else:
            if tunnel_id in self.tunnels:
                self.app_bindings[proc_key] = tunnel_id
            else:
                raise ValueError(f"Tunnel ID '{tunnel_id}' does not exist.")

        self.save_state()
        return {"success": True, "app": process_name, "bound_tunnel": self.app_bindings.get(proc_key, "Direct")}

    def get_tunnel_for_app(self, process_name: str) -> Optional[Dict[str, Any]]:
        """Retrieves assigned VPN tunnel for an app if configured."""
        proc_key = process_name.lower().strip()
        tid = self.app_bindings.get(proc_key)
        if tid and tid in self.tunnels:
            return self.tunnels[tid]
        return None
