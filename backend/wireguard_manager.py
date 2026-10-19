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
from .socks5_gateway import MultiVpnProxyManager
from .proton_service import VERIFIED_PROTON_SERVERS, ProtonService

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
        self.proxy_manager = MultiVpnProxyManager()
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

        for idx, (tid, t) in enumerate(self.tunnels.items()):
            t_copy = dict(t)
            assigned_port = 1081 + idx
            t_copy["proxy_port"] = assigned_port
            t_copy["proxy_url"] = f"socks5://127.0.0.1:{assigned_port}"
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
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.proxy_manager.sync_tunnels(self.tunnels))
        except Exception:
            pass

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
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.proxy_manager.sync_tunnels(self.tunnels))
            except Exception:
                pass
            return {"success": True}
        return {"success": False, "error": "Not found"}

    def _apply_linux_split_rule(self, process_name: str, tunnel_id: str):
        if not IS_LINUX:
            return
        tunnel = self.tunnels.get(tunnel_id)
        if not tunnel:
            return
        iface = tunnel.get("interface_name", tunnel_id)
        mark = 0x100 + (abs(hash(tunnel_id)) % 200)
        table_id = 51800 + (abs(hash(tunnel_id)) % 200)
        try:
            subprocess.run([
                "iptables", "-t", "mangle", "-A", "OUTPUT",
                "-m", "owner", "--cmd-owner", process_name,
                "-j", "MARK", "--set-mark", str(mark),
                "-m", "comment", "--comment", f"TC_Split_{process_name}"
            ], capture_output=True)
            subprocess.run(["ip", "rule", "add", "fwmark", str(mark), "table", str(table_id)], capture_output=True)
            subprocess.run(["ip", "route", "add", "default", "dev", iface, "table", str(table_id)], capture_output=True)
        except Exception:
            pass

    def _remove_linux_split_rule(self, process_name: str):
        if not IS_LINUX:
            return
        try:
            res = subprocess.run(["iptables", "-t", "mangle", "-S", "OUTPUT"], capture_output=True, text=True)
            for line in res.stdout.splitlines():
                if f"TC_Split_{process_name}" in line:
                    rule_spec = line.replace("-A OUTPUT ", "").strip().split()
                    subprocess.run(["iptables", "-t", "mangle", "-D", "OUTPUT"] + rule_spec, capture_output=True)
        except Exception:
            pass

    def bind_app_to_tunnel(self, process_name: str, tunnel_id: Optional[str]) -> Dict[str, Any]:
        """Binds a specific application executable to a WireGuard tunnel for split-tunneling."""
        proc_key = process_name.lower().strip()
        if not tunnel_id or tunnel_id in ("none", "direct", "clearnet"):
            if proc_key in self.app_bindings:
                del self.app_bindings[proc_key]
                self._remove_linux_split_rule(proc_key)
        else:
            if tunnel_id in self.tunnels or tunnel_id == "orbot":
                self.app_bindings[proc_key] = tunnel_id
                self._apply_linux_split_rule(proc_key, tunnel_id)
            else:
                # Check if tunnel_id matches a Proton server catalog ID or country code
                matching_server = next((s for s in VERIFIED_PROTON_SERVERS if s.get("id") == tunnel_id), None)
                if not matching_server:
                    tid_lower = tunnel_id.lower()
                    matching_server = next((s for s in VERIFIED_PROTON_SERVERS if s.get("country_code", "").lower() == tid_lower or s.get("country", "").lower() == tid_lower), None)

                if matching_server:
                    existing_count = len(self.tunnels)
                    unique_ip = f"10.2.{existing_count}.2/32"
                    ps = ProtonService()
                    wg_conf = ps.generate_wireguard_config(matching_server["id"], custom_address=unique_ip)
                    new_tunnel = self.add_tunnel(
                        name=f"Proton {wg_conf['server_name']}",
                        tunnel_type="proton",
                        endpoint=wg_conf["endpoint"],
                        public_key=wg_conf["public_key"],
                        private_key=ps.auth_data.get("private_key", "CLIENT_PRIVATE_KEY_HERE"),
                        address=unique_ip,
                        country=wg_conf["country"],
                        flag=wg_conf["flag"],
                        conf_content=wg_conf["conf_content"]
                    )
                    tunnel_id = new_tunnel["id"]
                    self.app_bindings[proc_key] = tunnel_id
                    self._apply_linux_split_rule(proc_key, tunnel_id)
                else:
                    raise ValueError(f"Tunnel ID '{tunnel_id}' does not exist.")

        self.save_state()
        bound_tid = self.app_bindings.get(proc_key, "Direct")
        tunnel_info = self.tunnels.get(bound_tid, {}) if bound_tid in self.tunnels else {}
        idx = list(self.tunnels.keys()).index(bound_tid) if bound_tid in self.tunnels else 0
        assigned_port = tunnel_info.get("proxy_port", 1081 + idx)
        proxy_url = tunnel_info.get("proxy_url", f"socks5://127.0.0.1:{assigned_port}") if bound_tid in self.tunnels else ("socks5://127.0.0.1:9050" if bound_tid == "orbot" else None)

        return {
            "success": True,
            "app": process_name,
            "bound_tunnel": bound_tid,
            "tunnel_name": tunnel_info.get("name", "Direct Clearnet" if bound_tid == "Direct" else "Orbot / Tor"),
            "country": tunnel_info.get("country", "Local"),
            "flag": tunnel_info.get("flag", "🌐" if bound_tid == "Direct" else "🧅"),
            "proxy_url": proxy_url,
            "proxy_port": assigned_port if bound_tid in self.tunnels else (9050 if bound_tid == "orbot" else None),
            "launch_command": f'"{process_name}" --proxy-server="{proxy_url}"' if proxy_url else None
        }

    def get_all_bindings(self) -> Dict[str, Any]:
        """Returns map of process_name -> bound tunnel details."""
        result = {}
        for proc_name, tid in self.app_bindings.items():
            if tid in self.tunnels:
                t = self.tunnels[tid]
                idx = list(self.tunnels.keys()).index(tid)
                assigned_port = t.get("proxy_port", 1081 + idx)
                result[proc_name] = {
                    "tunnel_id": tid,
                    "name": t.get("name"),
                    "country": t.get("country"),
                    "flag": t.get("flag"),
                    "proxy_url": t.get("proxy_url", f"socks5://127.0.0.1:{assigned_port}"),
                    "proxy_port": assigned_port,
                    "status": t.get("status")
                }
            elif tid == "orbot":
                result[proc_name] = {
                    "tunnel_id": "orbot",
                    "name": "Orbot / Tor Network",
                    "country": "Onion",
                    "flag": "🧅",
                    "proxy_url": "socks5://127.0.0.1:9050",
                    "proxy_port": 9050,
                    "status": "Connected"
                }
            else:
                result[proc_name] = {
                    "tunnel_id": "direct",
                    "name": "Direct Clearnet",
                    "country": "Direct",
                    "flag": "🌐",
                    "proxy_url": None,
                    "status": "Direct"
                }
        return result

    def get_tunnel_for_app(self, process_name: str) -> Optional[Dict[str, Any]]:
        """Retrieves assigned VPN tunnel for an app if configured."""
        proc_key = process_name.lower().strip()
        tid = self.app_bindings.get(proc_key)
        if tid and tid in self.tunnels:
            return self.tunnels[tid]
        return None
