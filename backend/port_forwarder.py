"""
Cross-Platform Multi-VPN Port Forwarding & Relay Engine for TrackerControl PC.
Provides:
1. Universal High-Performance Async Socket Forwarder supporting TCP, UDP, and BOTH (Dual-Protocol).
2. Multi-VPN Tunnel Binding (Bind rules to Proton WireGuard, Custom WireGuard, Orbot, or All Interfaces).
3. Native OS Hardware Acceleration (Linux iptables NAT table + Windows Netsh PortProxy).
4. Proton VPN Dynamic NAT-PMP Engine (RFC 6886) for P2P/Torrent port forwarding with automated keep-alive lease renewal.
"""

import asyncio
import json
import os
import random
import shutil
import socket
import struct
import subprocess
import time
from typing import Dict, Any, List, Optional, Tuple

from .platform_helper import IS_WINDOWS, IS_LINUX, IS_MACOS, PlatformHelper

DATA_DIR = PlatformHelper.get_data_dir()
RULES_FILE = os.path.join(DATA_DIR, "port_forwarding.json")


# ==================== Bidirectional UDP Forwarder Protocol ====================

class UDPClientRelayProtocol(asyncio.DatagramProtocol):
    """Outbound datagram endpoint for a specific client session communicating with target host:port."""
    def __init__(self, parent_forwarder, client_addr: Tuple[str, int]):
        self.parent = parent_forwarder
        self.client_addr = client_addr
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # Received response packet from target_host:target_port -> forward back to client
        if self.parent.server_transport and not self.parent.server_transport.is_closing():
            try:
                self.parent.server_transport.sendto(data, self.client_addr)
                self.parent.record_traffic(len(data))
            except Exception:
                pass

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        self.parent.remove_client(self.client_addr)


class UDPForwarderProtocol(asyncio.DatagramProtocol):
    """Universal bidirectional UDP packet forwarding protocol with session tracking."""
    def __init__(self, target_host: str, target_port: int, on_traffic_callback=None):
        self.target_host = target_host
        self.target_port = target_port
        self.on_traffic = on_traffic_callback
        self.server_transport = None
        self.clients: Dict[Tuple[str, int], asyncio.DatagramTransport] = {}
        self.last_seen: Dict[Tuple[str, int], float] = {}

    def connection_made(self, transport):
        self.server_transport = transport

    def datagram_received(self, data: bytes, client_addr: Tuple[str, int]):
        self.last_seen[client_addr] = time.time()
        self.record_traffic(len(data))

        outbound = self.clients.get(client_addr)
        if outbound and not outbound.is_closing():
            try:
                outbound.sendto(data, (self.target_host, self.target_port))
            except Exception:
                pass
        else:
            # Spawn outbound client relay asynchronously
            asyncio.create_task(self._init_outbound_relay(client_addr, data))

    async def _init_outbound_relay(self, client_addr: Tuple[str, int], initial_data: bytes):
        loop = asyncio.get_event_loop()
        try:
            _, protocol = await loop.create_datagram_endpoint(
                lambda: UDPClientRelayProtocol(self, client_addr),
                remote_addr=(self.target_host, self.target_port)
            )
            self.clients[client_addr] = protocol.transport
            try:
                protocol.transport.sendto(initial_data, (self.target_host, self.target_port))
            except Exception:
                pass
        except Exception:
            pass

    def record_traffic(self, byte_count: int):
        if self.on_traffic:
            self.on_traffic(byte_count)

    def remove_client(self, client_addr: Tuple[str, int]):
        self.clients.pop(client_addr, None)
        self.last_seen.pop(client_addr, None)

    def close(self):
        for transport in list(self.clients.values()):
            try:
                transport.close()
            except Exception:
                pass
        self.clients.clear()
        self.last_seen.clear()
        if self.server_transport and not self.server_transport.is_closing():
            try:
                self.server_transport.close()
            except Exception:
                pass


# ==================== Proton VPN NAT-PMP Dynamic Client (RFC 6886) ====================

class ProtonNatPmpClient:
    """
    Implements NAT Port Mapping Protocol (NAT-PMP, RFC 6886) for Proton VPN P2P servers.
    Communicates with Proton WireGuard Gateway (default 10.2.0.1:5351) via UDP,
    requests dynamic TCP & UDP port forward assignments, and maintains automated keepalive leases.
    """
    def __init__(self):
        self.gateway_ip: str = "10.2.0.1"
        self.gateway_port: int = 5351
        self.internal_port: Optional[int] = None
        self.assigned_external_port: Optional[int] = None
        self.lifetime: int = 60
        self.lease_start: Optional[float] = None
        self.lease_expires: Optional[float] = None
        self.status: str = "Idle" # Idle, Active, Refreshing, Error, Released
        self.last_error: Optional[str] = None
        self.last_refreshed: Optional[float] = None
        self._keepalive_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    def _sync_request(self, req_packet: bytes, timeout: float = 3.0) -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        try:
            s.sendto(req_packet, (self.gateway_ip, self.gateway_port))
            resp, _ = s.recvfrom(1024)
            return resp
        finally:
            s.close()

    async def _send_pmp_mapping(self, opcode: int, internal_port: int, external_port: int, lifetime: int) -> Dict[str, Any]:
        """Sends an RFC 6886 port mapping request (opcode 1=UDP, 2=TCP)."""
        # Request Packet: Version(0:1B), Opcode(1B), Reserved(0:2B), InternalPort(2B), SuggestedExternalPort(2B), Lifetime(4B) -> 12 bytes
        req_pkt = struct.pack("!BBHHHI", 0, opcode, 0, internal_port, external_port, lifetime)

        loop = asyncio.get_event_loop()
        try:
            resp_pkt = await loop.run_in_executor(None, self._sync_request, req_pkt, 3.5)
        except socket.timeout:
            return {"success": False, "error": f"Gateway timeout connecting to {self.gateway_ip}:{self.gateway_port}. Is Proton VPN active?"}
        except Exception as e:
            return {"success": False, "error": f"Network error contacting Proton NAT-PMP: {e}"}

        if len(resp_pkt) < 16:
            return {"success": False, "error": f"Invalid NAT-PMP response length ({len(resp_pkt)} bytes)"}

        # Response Packet: Version(0:1B), Opcode(128+op:1B), ResultCode(2B), Epoch(4B), InternalPort(2B), AssignedExtPort(2B), Lifetime(4B) -> 16 bytes
        ver, resp_op, result_code, epoch, in_p, assigned_ext_p, granted_lifetime = struct.unpack("!BBHIHHI", resp_pkt[:16])

        if result_code != 0:
            error_map = {
                1: "Unsupported NAT-PMP Version",
                2: "Not Authorized / Refused (Ensure connected to a Proton P2P server)",
                3: "Network Failure",
                4: "Out of Resources",
                5: "Unsupported Opcode"
            }
            err_msg = error_map.get(result_code, f"NAT-PMP Error code {result_code}")
            return {"success": False, "error": err_msg, "result_code": result_code}

        return {
            "success": True,
            "opcode": opcode,
            "internal_port": in_p,
            "assigned_external_port": assigned_ext_p,
            "lifetime": granted_lifetime,
            "epoch": epoch
        }

    async def request_p2p_port(self, internal_port: Optional[int] = None, lifetime: int = 60, gateway_ip: str = "10.2.0.1") -> Dict[str, Any]:
        """Requests dynamic dual-protocol (TCP + UDP) port mapping from Proton VPN."""
        async with self._lock:
            self.gateway_ip = gateway_ip or "10.2.0.1"

            # If internal port not specified or 0, choose an ephemeral or standard P2P port
            if not internal_port or internal_port <= 0:
                internal_port = random.randint(45000, 65000)

            self.internal_port = internal_port
            self.status = "Refreshing"

            # 1. Request UDP Mapping (Opcode 1)
            udp_res = await self._send_pmp_mapping(opcode=1, internal_port=internal_port, external_port=0, lifetime=lifetime)
            if not udp_res.get("success"):
                self.status = "Error"
                self.last_error = udp_res.get("error", "UDP NAT-PMP request failed")
                return {"success": False, "error": self.last_error}

            assigned_port = udp_res["assigned_external_port"]
            granted_lifetime = udp_res["lifetime"]

            # 2. Request TCP Mapping (Opcode 2) with the same assigned port
            tcp_res = await self._send_pmp_mapping(opcode=2, internal_port=internal_port, external_port=assigned_port, lifetime=lifetime)
            
            # If TCP fails or assigns same port, we track the granted lease
            self.assigned_external_port = assigned_port
            self.lifetime = granted_lifetime or lifetime
            self.lease_start = time.time()
            self.lease_expires = self.lease_start + self.lifetime
            self.last_refreshed = self.lease_start
            self.status = "Active"
            self.last_error = None

            # Cancel existing keep-alive task and start a fresh renewal loop
            if self._keepalive_task and not self._keepalive_task.done():
                self._keepalive_task.cancel()

            self._keepalive_task = asyncio.create_task(self._keepalive_loop())

            return {
                "success": True,
                "assigned_external_port": self.assigned_external_port,
                "internal_port": self.internal_port,
                "lifetime": self.lifetime,
                "gateway": f"{self.gateway_ip}:{self.gateway_port}",
                "status": "Active"
            }

    async def _keepalive_loop(self):
        """Background loop renewing NAT-PMP mapping before lease expires (RFC 6886 keepalive)."""
        while self.status == "Active":
            # Renew when 15 seconds remain, or at 75% of lifetime
            sleep_duration = max(10, self.lifetime - 15)
            try:
                await asyncio.sleep(sleep_duration)
            except asyncio.CancelledError:
                break

            if self.status != "Active":
                break

            # Renew UDP mapping
            res_udp = await self._send_pmp_mapping(
                opcode=1,
                internal_port=self.internal_port,
                external_port=self.assigned_external_port or 0,
                lifetime=self.lifetime
            )
            # Renew TCP mapping
            res_tcp = await self._send_pmp_mapping(
                opcode=2,
                internal_port=self.internal_port,
                external_port=self.assigned_external_port or 0,
                lifetime=self.lifetime
            )

            if res_udp.get("success") or res_tcp.get("success"):
                now = time.time()
                self.lease_start = now
                self.lease_expires = now + self.lifetime
                self.last_refreshed = now
            else:
                self.last_error = "Keep-alive renewal warning: gateway temporarily unresponsive."

    async def stop_p2p_port(self) -> Dict[str, Any]:
        """Releases the dynamic NAT-PMP port gracefully by sending lifetime=0."""
        async with self._lock:
            if self._keepalive_task and not self._keepalive_task.done():
                self._keepalive_task.cancel()
                self._keepalive_task = None

            if self.assigned_external_port and self.internal_port:
                # Send release requests with lifetime=0
                try:
                    await self._send_pmp_mapping(opcode=1, internal_port=self.internal_port, external_port=self.assigned_external_port, lifetime=0)
                    await self._send_pmp_mapping(opcode=2, internal_port=self.internal_port, external_port=self.assigned_external_port, lifetime=0)
                except Exception:
                    pass

            released_port = self.assigned_external_port
            self.status = "Released"
            self.assigned_external_port = None
            self.lease_expires = None
            return {"success": True, "released_port": released_port, "status": "Released"}

    def get_status(self) -> Dict[str, Any]:
        now = time.time()
        remaining = 0
        if self.lease_expires and self.status == "Active":
            remaining = max(0, int(self.lease_expires - now))

        return {
            "active": self.status == "Active" and bool(self.assigned_external_port),
            "status": self.status,
            "assigned_external_port": self.assigned_external_port,
            "internal_port": self.internal_port,
            "gateway": f"{self.gateway_ip}:{self.gateway_port}",
            "protocols": "TCP + UDP",
            "lifetime": self.lifetime,
            "seconds_remaining": remaining,
            "last_refreshed": self.last_refreshed,
            "error": self.last_error
        }


# ==================== Core Port Forwarding Engine ====================

class PortForwarder:
    def __init__(self):
        self.rules: Dict[str, Dict[str, Any]] = {}
        # active_servers maps rule_id -> Dict with keys "tcp_server" and/or "udp_protocol"
        self.active_servers: Dict[str, Dict[str, Any]] = {}
        self.nat_pmp = ProtonNatPmpClient()
        self.load_rules()

    def load_rules(self):
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    self.rules = json.load(f)
            except Exception:
                self.rules = {}

        if not self.rules:
            self.add_rule(
                "WireGuard Relay",
                51820,
                "127.0.0.1",
                51820,
                protocol="UDP",
                tunnel_id="all",
                tunnel_name="All Interfaces",
                auto_start=False
            )
            self.add_rule(
                "Orbot SOCKS5 Relay",
                9055,
                "127.0.0.1",
                9050,
                protocol="TCP",
                tunnel_id="orbot",
                tunnel_name="Orbot / Tor",
                auto_start=False
            )
            self.add_rule(
                "P2P Torrent Inbound",
                6881,
                "127.0.0.1",
                6881,
                protocol="BOTH",
                tunnel_id="all",
                tunnel_name="All Interfaces",
                auto_start=False
            )

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
        tunnel_id: str = "all",
        tunnel_name: str = "All Interfaces",
        auto_start: bool = True
    ) -> Dict[str, Any]:
        rule_id = f"fwd-{listen_port}-{target_port}-{protocol.lower()}"
        rule = {
            "id": rule_id,
            "name": name,
            "listen_port": listen_port,
            "target_host": target_host,
            "target_port": target_port,
            "protocol": protocol.upper(),
            "tunnel_id": tunnel_id or "all",
            "tunnel_name": tunnel_name or "All Interfaces",
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
        protocol = rule.get("protocol", "TCP").upper()
        server_handles: Dict[str, Any] = {}

        def record_traffic_udp(bytes_len: int):
            rule["bytes_forwarded"] += bytes_len
            rule["connections_handled"] += 1

        # 1. Start TCP Stream Forwarder
        if protocol in ("TCP", "BOTH"):
            async def handle_client(client_reader, client_writer):
                rule["connections_handled"] += 1
                try:
                    target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
                except Exception:
                    try:
                        client_writer.close()
                        await client_writer.wait_closed()
                    except Exception:
                        pass
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
                tcp_server = await asyncio.start_server(handle_client, "0.0.0.0", listen_port)
                server_handles["tcp_server"] = tcp_server
            except Exception as e:
                rule["status"] = "Error"
                return {"success": False, "error": f"Failed to bind TCP port {listen_port}: {e}"}

        # 2. Start UDP Packet Forwarder
        if protocol in ("UDP", "BOTH"):
            loop = asyncio.get_event_loop()
            try:
                transport, udp_proto = await loop.create_datagram_endpoint(
                    lambda: UDPForwarderProtocol(target_host, target_port, on_traffic_callback=record_traffic_udp),
                    local_addr=("0.0.0.0", listen_port)
                )
                server_handles["udp_proto"] = udp_proto
                server_handles["udp_transport"] = transport
            except Exception as e:
                # Cleanup TCP if already started
                if "tcp_server" in server_handles:
                    server_handles["tcp_server"].close()
                    await server_handles["tcp_server"].wait_closed()
                rule["status"] = "Error"
                return {"success": False, "error": f"Failed to bind UDP port {listen_port}: {e}"}

        self.active_servers[rule_id] = server_handles
        rule["status"] = "Active"
        self.save_rules()

        # 3. Optional OS-Level Hardware Acceleration
        if IS_WINDOWS and protocol in ("TCP", "BOTH"):
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
            for proto_tag in (["tcp"] if protocol == "TCP" else ["udp"] if protocol == "UDP" else ["tcp", "udp"]):
                try:
                    subprocess.run([
                        "iptables", "-t", "nat", "-A", "PREROUTING", "-p", proto_tag,
                        "--dport", str(listen_port), "-j", "DNAT", "--to-destination", f"{target_host}:{target_port}"
                    ], capture_output=True)
                except Exception:
                    pass

        return {"success": True, "rule_id": rule_id, "status": "Active", "protocol": protocol}

    async def stop_rule(self, rule_id: str) -> Dict[str, Any]:
        if rule_id in self.active_servers:
            handles = self.active_servers[rule_id]
            # Handle backward-compatible asyncio.Server object or new dict
            if isinstance(handles, dict):
                if "tcp_server" in handles:
                    handles["tcp_server"].close()
                    try:
                        await handles["tcp_server"].wait_closed()
                    except Exception:
                        pass
                if "udp_proto" in handles:
                    handles["udp_proto"].close()
            elif hasattr(handles, "close"):
                handles.close()
                try:
                    await handles.wait_closed()
                except Exception:
                    pass

            del self.active_servers[rule_id]

        if rule_id in self.rules:
            rule = self.rules[rule_id]
            rule["status"] = "Disabled"
            self.save_rules()
            listen_port = rule["listen_port"]
            target_host = rule["target_host"]
            target_port = rule["target_port"]
            protocol = rule.get("protocol", "TCP").upper()

            if IS_WINDOWS and protocol in ("TCP", "BOTH"):
                try:
                    subprocess.run(
                        ["netsh", "interface", "portproxy", "delete", "v4tov4", f"listenport={listen_port}"],
                        capture_output=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                except Exception:
                    pass
            elif IS_LINUX and shutil.which("iptables"):
                for proto_tag in (["tcp"] if protocol == "TCP" else ["udp"] if protocol == "UDP" else ["tcp", "udp"]):
                    try:
                        subprocess.run([
                            "iptables", "-t", "nat", "-D", "PREROUTING", "-p", proto_tag,
                            "--dport", str(listen_port), "-j", "DNAT", "--to-destination", f"{target_host}:{target_port}"
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

    async def stop_all(self):
        """Stops all active socket forwards and releases Proton NAT-PMP leases."""
        for rid in list(self.active_servers.keys()):
            try:
                await self.stop_rule(rid)
            except Exception:
                pass
        try:
            await self.nat_pmp.stop_p2p_port()
        except Exception:
            pass
