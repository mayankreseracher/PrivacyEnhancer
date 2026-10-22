"""
Lightweight Universal Async SOCKS5 Proxy Gateway for Multi-VPN Split-Tunneling.
Binds outbound traffic to specific WireGuard tunnel virtual interface IPs (e.g. 10.2.0.2, 10.2.1.2)
allowing individual applications (Brave, Games, Browsers, Torrents) to route through
distinct national VPN endpoints (US, India, Netherlands, etc.) concurrently.
"""

import asyncio
import socket
import struct
import time
from typing import Optional, Tuple, Dict, Any


class Socks5RelayServer:
    def __init__(self, port: int, bind_interface_ip: Optional[str] = None, name: str = "VPN Gateway"):
        self.port = port
        self.bind_interface_ip = bind_interface_ip
        self.name = name
        self.server: Optional[asyncio.AbstractServer] = None
        self.is_running = False
        self.bytes_relayed = 0
        self.active_connections = 0

    async def start(self):
        if self.is_running:
            return
        try:
            self.server = await asyncio.start_server(
                self.handle_client,
                host="127.0.0.1",
                port=self.port
            )
            self.is_running = True
            print(f"[Socks5Gateway] '{self.name}' listening on 127.0.0.1:{self.port} (Outbound: {self.bind_interface_ip or 'Default'})")
        except Exception as e:
            print(f"[Socks5Gateway] Error starting proxy on port {self.port}: {e}")

    async def stop(self):
        self.is_running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def handle_client(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
        self.active_connections += 1
        try:
            # 1. Negotiation Handshake
            header = await client_reader.read(2)
            if len(header) < 2:
                client_writer.close()
                return

            ver, nmethods = header[0], header[1]
            if ver != 5:
                client_writer.close()
                return

            methods = await client_reader.read(nmethods)
            # Response: SOCKS5, No Authentication Required (0x00)
            client_writer.write(b"\x05\x00")
            await client_writer.drain()

            # 2. Connection Request
            req_header = await client_reader.read(4)
            if len(req_header) < 4:
                client_writer.close()
                return

            ver, cmd, rsv, atyp = req_header
            if ver != 5 or cmd != 1:  # Only CONNECT (0x01) supported
                # Command not supported
                client_writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await client_writer.drain()
                client_writer.close()
                return

            # Parse Destination Address
            dest_host = None
            if atyp == 1:  # IPv4
                dest_raw = await client_reader.read(4)
                dest_host = socket.inet_ntoa(dest_raw)
            elif atyp == 3:  # Domain name
                domain_len = (await client_reader.read(1))[0]
                dest_raw = await client_reader.read(domain_len)
                dest_host = dest_raw.decode("utf-8", errors="ignore")
            elif atyp == 4:  # IPv6
                dest_raw = await client_reader.read(16)
                dest_host = socket.inet_ntop(socket.AF_INET6, dest_raw)
            else:
                client_writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await client_writer.drain()
                client_writer.close()
                return

            port_raw = await client_reader.read(2)
            dest_port = struct.unpack("!H", port_raw)[0]

            # 3. Connect to Destination, binding to specific VPN interface if configured
            loop = asyncio.get_event_loop()
            remote_reader = None
            remote_writer = None

            try:
                if self.bind_interface_ip:
                    # Create socket bound to virtual VPN IP (anti-leak protection: never fallback to clearnet)
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.setblocking(False)
                    clean_ip = self.bind_interface_ip.split("/")[0].strip()
                    try:
                        sock.bind((clean_ip, 0))
                    except Exception as bind_err:
                        # Fallback to any active VPN interface on host (e.g. ProtonVPN 10.2.0.2)
                        active_vpn_ip = None
                        try:
                            import psutil
                            for if_name, if_addrs in psutil.net_if_addrs().items():
                                if any(k in if_name.lower() for k in ["proton", "wireguard", "wg", "tun"]):
                                    for a in if_addrs:
                                        if getattr(a, "family", None) and getattr(a.family, "name", "") == "AF_INET":
                                            if a.address and a.address != clean_ip:
                                                active_vpn_ip = a.address
                                                break
                                if active_vpn_ip:
                                    break
                        except Exception:
                            pass

                        if active_vpn_ip:
                            try:
                                sock.bind((active_vpn_ip, 0))
                            except Exception as fallback_err:
                                print(f"[Socks5Gateway] Anti-Leak Protection: Cannot bind to {clean_ip} or fallback {active_vpn_ip} ({fallback_err}).")
                                client_writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                                await client_writer.drain()
                                client_writer.close()
                                return
                        else:
                            # Anti-leak sentry: If binding to the specified VPN interface fails,
                            # REJECT connection to prevent silent clearnet data leakage
                            print(f"[Socks5Gateway] Anti-Leak Protection: Cannot bind to VPN interface {clean_ip} ({bind_err}). Rejecting clearnet leak.")
                            client_writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                            await client_writer.drain()
                            client_writer.close()
                            return
                    
                    await asyncio.wait_for(
                        loop.sock_connect(sock, (dest_host, dest_port)),
                        timeout=10.0
                    )
                    remote_reader, remote_writer = await asyncio.open_connection(sock=sock)
                else:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(dest_host, dest_port),
                        timeout=10.0
                    )
            except Exception as e:
                # Host unreachable / Connection refused
                client_writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                await client_writer.drain()
                client_writer.close()
                return

            # Success response
            client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await client_writer.drain()

            # 4. Bidirectional Relay Loop
            async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
                try:
                    while True:
                        buf = await src.read(32768)
                        if not buf:
                            break
                        dst.write(buf)
                        await dst.drain()
                        self.bytes_relayed += len(buf)
                except Exception:
                    pass
                finally:
                    try:
                        dst.close()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(client_reader, remote_writer),
                forward(remote_reader, client_writer)
            )

        except Exception:
            pass
        finally:
            self.active_connections = max(0, self.active_connections - 1)
            try:
                client_writer.close()
            except Exception:
                pass


class MultiVpnProxyManager:
    """Manages active SOCKS5 relay servers for each configured WireGuard VPN tunnel."""
    def __init__(self):
        self.relays: Dict[str, Socks5RelayServer] = {} # tunnel_id -> Socks5RelayServer
        self.base_port = 1081

    async def sync_tunnels(self, tunnels: Dict[str, Dict[str, Any]]):
        """Ensures each active tunnel has a designated local proxy port for split routing."""
        active_ids = set()
        for idx, (tid, tunnel) in enumerate(tunnels.items()):
            assigned_port = self.base_port + idx
            tunnel["proxy_port"] = assigned_port
            tunnel["proxy_url"] = f"socks5://127.0.0.1:{assigned_port}"

            if tunnel.get("status") == "Connected":
                active_ids.add(tid)
                if tid not in self.relays:
                    bind_ip = tunnel.get("address", "10.2.0.2")
                    name = tunnel.get("name", f"Tunnel {tid}")
                    relay = Socks5RelayServer(port=assigned_port, bind_interface_ip=bind_ip, name=name)
                    self.relays[tid] = relay
                    await relay.start()

        # Stop relays for inactive/deleted tunnels
        for tid in list(self.relays.keys()):
            if tid not in active_ids:
                await self.relays[tid].stop()
                del self.relays[tid]

    async def get_or_create_server(self, port: int, tunnel_ip: Optional[str] = None, name: str = "Relay") -> Socks5RelayServer:
        """Retrieves or creates a dedicated SOCKS5 relay server on the specified port."""
        for relay in self.relays.values():
            if relay.port == port:
                return relay
        relay = Socks5RelayServer(port=port, bind_interface_ip=tunnel_ip, name=name)
        await relay.start()
        self.relays[f"port_{port}"] = relay
        return relay

    async def stop_all(self):
        for relay in self.relays.values():
            await relay.stop()
        self.relays.clear()

