"""
Core Engine Coordinator for TrackerControl PC.
Integrates the DNS Proxy, Process Monitor, Threat Intelligence,
Cross-Platform Firewall Enforcer, Database, and WebSocket Event Bus.
"""

import asyncio
import json
import time
from typing import Dict, Any, List, Set, Optional
from fastapi import WebSocket

from .database import Database
from .tracker_intelligence import TrackerIntelligence
from .dns_proxy import DNSProxy, DNSProtocol
from .process_monitor import ProcessMonitor
from .firewall_enforcer import FirewallEnforcer
from .app_discovery import AppDiscovery
from .wireguard_manager import WireGuardManager
from .proton_service import ProtonService
from .orbot_service import OrbotService
from .port_forwarder import PortForwarder
from .platform_helper import PlatformHelper

class TrackerEngine:
    def __init__(self):
        self.database = Database()
        self.intelligence = TrackerIntelligence()
        self.firewall = FirewallEnforcer()
        self.app_discovery = AppDiscovery(self.database)
        self.wireguard = WireGuardManager(self.database)
        self.proton = ProtonService()
        self.orbot = OrbotService()
        self.port_forwarder = PortForwarder()
        
        # State
        self.protection_mode = "MAX_PRIVACY" # MAX_PRIVACY, BALANCED, AUDIT_ONLY, LOCKDOWN
        self.shield_active = True
        self.active_websockets: Set[WebSocket] = set()
        self.recent_events_cache: List[Dict[str, Any]] = []
        self.max_cache_size = 100

        # Subsystems
        self.dns_proxy = DNSProxy(
            intelligence=self.intelligence,
            database=self.database,
            event_callback=self.on_event
        )
        self.process_monitor = ProcessMonitor(
            intelligence=self.intelligence,
            database=self.database,
            dns_proxy=self.dns_proxy,
            event_callback=self.on_event,
            poll_interval=0.5
        )

        self._dns_task = None
        self._monitor_task = None

    def on_event(self, event: Dict[str, Any]):
        """Called whenever DNS Proxy or Process Monitor records a network connection."""
        self.recent_events_cache.insert(0, event)
        if len(self.recent_events_cache) > self.max_cache_size:
            self.recent_events_cache.pop()

        if self.active_websockets:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.broadcast_event(event))
            except Exception:
                pass

    async def broadcast_event(self, event: Dict[str, Any]):
        dead_sockets = set()
        message = json.dumps({"type": "NEW_CONNECTION", "data": event})
        for ws in self.active_websockets:
            try:
                await ws.send_text(message)
            except Exception:
                dead_sockets.add(ws)
        
        for ws in dead_sockets:
            self.active_websockets.discard(ws)

    async def register_websocket(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)
        stats = self.get_stats()
        await websocket.send_text(json.dumps({
            "type": "INIT_STATE",
            "data": {
                "stats": stats,
                "shield_active": self.shield_active,
                "protection_mode": self.protection_mode,
                "system_summary": PlatformHelper.get_system_summary(),
                "recent_connections": self.recent_events_cache[:30]
            }
        }))

    def unregister_websocket(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    def set_protection_mode(self, mode: str):
        valid_modes = ["MAX_PRIVACY", "BALANCED", "AUDIT_ONLY", "LOCKDOWN"]
        if mode in valid_modes:
            self.protection_mode = mode

    def toggle_shield(self, active: bool):
        self.shield_active = active

    def get_stats(self) -> Dict[str, Any]:
        stats = self.database.get_stats()
        stats["shield_active"] = self.shield_active
        stats["protection_mode"] = self.protection_mode
        stats["os_privacy"] = self.firewall.get_os_privacy_status()
        stats["windows_privacy"] = self.firewall.get_windows_privacy_status()
        stats["system_summary"] = PlatformHelper.get_system_summary()
        return stats

    async def start(self):
        print(f"[Engine] Initializing TrackerControl PC Subsystems on {PlatformHelper.get_os_type()}...")
        loop = asyncio.get_event_loop()

        # Start DNS Proxy
        try:
            listen = loop.create_datagram_endpoint(
                lambda: DNSProtocol(self.dns_proxy),
                local_addr=(self.dns_proxy.listen_host, self.dns_proxy.listen_port)
            )
            transport, protocol = await listen
            self.dns_proxy.transport = transport
            self.dns_proxy.protocol = protocol
            print(f"[DNS] Listening on {self.dns_proxy.listen_host}:{self.dns_proxy.listen_port}")
        except (PermissionError, OSError) as e:
            print(f"[DNS] Notice: Port {self.dns_proxy.listen_port} not directly bindable ({e}). Falling back to port 5353.")
            try:
                self.dns_proxy.listen_port = 5353
                listen = loop.create_datagram_endpoint(
                    lambda: DNSProtocol(self.dns_proxy),
                    local_addr=(self.dns_proxy.listen_host, 5353)
                )
                transport, protocol = await listen
                self.dns_proxy.transport = transport
                self.dns_proxy.protocol = protocol
                print(f"[DNS] Listening on {self.dns_proxy.listen_host}:5353")
            except Exception as ex:
                print(f"[DNS] Could not bind fallback DNS: {ex}")
        except Exception as e:
            print(f"[DNS] DNS Server binding info: {e}")

        # Start Process Monitor
        self._monitor_task = asyncio.create_task(self.process_monitor.start())
        print(f"[ProcessMonitor] Real-time socket scanner active for {PlatformHelper.get_os_type()}.")

    async def stop(self):
        print("[Engine] Stopping TrackerControl PC...")
        if self.process_monitor:
            self.process_monitor.stop()
        if self._monitor_task:
            self._monitor_task.cancel()
        if self.dns_proxy.transport:
            self.dns_proxy.transport.close()
