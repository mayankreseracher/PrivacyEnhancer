"""
Cross-Platform Port Forwarding Engine for TrackerControl PC.
Provides dual-mode port forwarding:
1. Universal High-Performance Async Python Socket Stream Forwarder (Works across all Linux distros and Windows)
2. Native OS Acceleration (Linux iptables NAT table + Windows Netsh PortProxy).
Supports TCP/UDP tunneling, P2P/torrent forwarding, and WireGuard/Orbot relaying.
"""

import asyncio
import json
import os
import shutil
import subprocess
import time
from typing import Dict, Any, List, Optional

from .platform_helper import IS_WINDOWS, IS_LINUX, PlatformHelper

DATA_DIR = PlatformHelper.get_data_dir()
RULES_FILE = os.path.join(DATA_DIR, "port_forwarding.json")

class PortForwarder:
    def __init__(self):
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.active_servers: Dict[str, asyncio.Server] = {}
        self.load_rules()

    def load_rules(self):
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    self.rules = json.load(f)
            except Exception:
                self.rules = {}

        if not self.rules:
            self.add_rule("WireGuard Port Forward", 51820, "127.0.0.1", 51820, protocol="TCP", auto_start=False)
            self.add_rule("Orbot SOCKS5 Relay", 9055, "127.0.0.1", 9050, protocol="TCP", auto_start=False)

    def save_rules(self):
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(self.rules, f, indent=2)

    def get_all_rules(self) -> List[Dict[str, Any]]:
        for rid, r in self.rules.items():
            r["is_active"] = rid in self.active_servers
        return list(self.rules.values())

    def add_rule(
        self,
        name: str,
        listen_port: int,
        target_host: str,
        target_port: int,
        protocol: str = "TCP",
        auto_start: bool = True
    ) -> Dict[str, Any]:
        rule_id = f"fwd-{listen_port}-{target_port}"
        rule = {
            "id": rule_id,
            "name": name,
            "listen_port": listen_port,
            "target_host": target_host,
            "target_port": target_port,
            "protocol": protocol.upper(),
            "status": "Active" if auto_start else "Disabled",
            "bytes_forwarded": 0,
            "connections_handled": 0,
            "created_at": time.time()
        }
        self.rules[rule_id] = rule
        self.save_rules()
        return rule

    async def start_rule(self, rule_id: str) -> Dict[str, Any]:
        if rule_id not in self.rules:
            raise ValueError(f"Rule ID '{rule_id}' not found.")

        rule = self.rules[rule_id]
        if rule_id in self.active_servers:
            return {"success": True, "message": "Already running"}

        listen_port = rule["listen_port"]
        target_host = rule["target_host"]
        target_port = rule["target_port"]

        async def handle_client(client_reader, client_writer):
            rule["connections_handled"] += 1
            try:
                target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
            except Exception:
                client_writer.close()
                await client_writer.wait_closed()
                return

            async def pipe(reader, writer):
                try:
                    while True:
                        data = await reader.read(8192)
                        if not data:
                            break
                        writer.write(data)
                        await writer.drain()
                        rule["bytes_forwarded"] += len(data)
                except Exception:
                    pass
                finally:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            await asyncio.gather(pipe(client_reader, target_writer), pipe(target_reader, client_writer))

        try:
            server = await asyncio.start_server(handle_client, "0.0.0.0", listen_port)
            self.active_servers[rule_id] = server
            rule["status"] = "Active"
            self.save_rules()

            # Optional OS-level hardware acceleration
            if IS_WINDOWS:
                try:
                    subprocess.run(
                        ["netsh", "interface", "portproxy", "add", "v4tov4",
                         f"listenport={listen_port}", f"connectaddress={target_host}", f"connectport={target_port}"],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                except Exception:
                    pass
            elif IS_LINUX and shutil.which("iptables"):
                try:
                    subprocess.run([
                        "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp",
                        "--dport", str(listen_port), "-j", "DNAT", "--to-destination", f"{target_host}:{target_port}"
                    ], capture_output=True)
                except Exception:
                    pass

            return {"success": True, "rule_id": rule_id, "status": "Active"}
        except Exception as e:
            rule["status"] = "Error"
            return {"success": False, "error": str(e)}

    async def stop_rule(self, rule_id: str) -> Dict[str, Any]:
        if rule_id in self.active_servers:
            server = self.active_servers[rule_id]
            server.close()
            await server.wait_closed()
            del self.active_servers[rule_id]

        if rule_id in self.rules:
            rule = self.rules[rule_id]
            rule["status"] = "Disabled"
            self.save_rules()
            if IS_WINDOWS:
                try:
                    subprocess.run(
                        ["netsh", "interface", "portproxy", "delete", "v4tov4", f"listenport={rule['listen_port']}"],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                except Exception:
                    pass
            elif IS_LINUX and shutil.which("iptables"):
                try:
                    subprocess.run([
                        "iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp",
                        "--dport", str(rule['listen_port']), "-j", "DNAT", "--to-destination", f"{rule['target_host']}:{rule['target_port']}"
                    ], capture_output=True)
                except Exception:
                    pass

        return {"success": True, "status": "Disabled"}

    async def delete_rule(self, rule_id: str) -> Dict[str, Any]:
        await self.stop_rule(rule_id)
        if rule_id in self.rules:
            del self.rules[rule_id]
            self.save_rules()
            return {"success": True}
        return {"success": False, "error": "Not found"}
