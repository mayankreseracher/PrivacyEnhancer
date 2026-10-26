"""
Core Engine Coordinator for TrackerControl PC.
Integrates the DNS Proxy, Process Monitor, Threat Intelligence,
Cross-Platform Firewall Enforcer, Database, and WebSocket Event Bus.
"""

import asyncio
import json
import time
import psutil
from typing import Dict, Any, List, Set, Optional, Callable
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
from .updater import AutoUpdater

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
        self.updater = AutoUpdater(database=self.database, event_callback=self.on_updater_event)
        self._updater_task = None
        
        self.loop = None
        self.kill_switch_active = False
        self.tray = None
        self._last_desktop_notify = 0.0
        
        # State
        self.protection_mode = "MAX_PRIVACY" # MAX_PRIVACY, BALANCED, AUDIT_ONLY, LOCKDOWN
        self.shield_active = True
        self.active_websockets: Set[WebSocket] = set()
        self.event_listeners: List[Callable[[Dict[str, Any]], None]] = []
        self.recent_events_cache: List[Dict[str, Any]] = []
        self.max_cache_size = 100

        # GlassWire-style Live Bandwidth & Alerts Engine
        self.bandwidth_history: List[Dict[str, Any]] = []
        self.max_bandwidth_history = 120
        self.last_io_bytes = None
        self.last_io_time = None
        self._bandwidth_task = None

        self.alerts: List[Dict[str, Any]] = []
        self.max_alerts = 200
        self.known_apps: Set[str] = set()
        try:
            for app in self.database.get_all_apps():
                p_name = app.get("process_name")
                if p_name:
                    self.known_apps.add(p_name.lower())
        except Exception:
            pass

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
            firewall=self.firewall,
            event_callback=self.on_event,
            poll_interval=0.5,
            protection_mode=self.protection_mode
        )
        self.monitor = self.process_monitor
        self.dns_proxy.process_monitor = self.process_monitor

        self._dns_task = None
        self._monitor_task = None

    def _dispatch_coro(self, coro):
        """Thread-safe coroutine scheduler for WebSocket & in-process desktop broadcasts."""
        if not self.active_websockets and not getattr(self, "event_listeners", None):
            try:
                coro.close()
            except Exception:
                pass
            return
        if self.loop and self.loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(coro, self.loop)
                return
            except Exception:
                pass
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(coro)
                return
        except Exception:
            pass
        try:
            coro.close()
        except Exception:
            pass

    def on_event(self, event: Dict[str, Any]):
        """Called whenever DNS Proxy or Process Monitor records a network connection."""
        if not self.shield_active:
            event["status"] = "allowed"
            event["block_reason"] = "Shield Disabled"
        elif self.protection_mode in ("AUDIT", "AUDIT_ONLY"):
            event["status"] = "allowed"
            event["block_reason"] = "Audit Mode"

        self.recent_events_cache.insert(0, event)
        if len(self.recent_events_cache) > self.max_cache_size:
            self.recent_events_cache.pop()

        proc_name = event.get("process_name", "Unknown")
        proc_key = proc_name.lower().strip()
        now = event.get("timestamp", time.time())

        # 1. GlassWire-style New App First Connection Alert
        if proc_name not in ("Unknown", "DNS Client") and proc_key and proc_key not in self.known_apps:
            self.known_apps.add(proc_key)
            alert = {
                "id": f"alert-{int(now * 1000)}-app",
                "type": "NEW_APP",
                "severity": "info",
                "title": f"New Network Activity: {proc_name}",
                "message": f"'{proc_name}' accessed the network for the first time ({event.get('domain') or event.get('ip')}).",
                "process_name": proc_name,
                "timestamp": now,
                "domain": event.get("domain", ""),
                "ip": event.get("ip", "")
            }
            self._add_alert(alert)

        # 2. GlassWire-style Tracker Neutralized Alert
        if event.get("status") == "blocked":
            alert = {
                "id": f"alert-{int(now * 1000)}-blk",
                "type": "TRACKER_BLOCKED",
                "severity": "warning",
                "title": f"Tracker Blocked: {event.get('name') or event.get('company', 'Unknown')}",
                "message": f"Neutralized {event.get('category', 'Telemetry')} connection to {event.get('domain') or event.get('ip')} from {proc_name}.",
                "process_name": proc_name,
                "timestamp": now,
                "domain": event.get("domain", ""),
                "ip": event.get("ip", ""),
                "company": event.get("company", ""),
                "category": event.get("category", "")
            }
            self._add_alert(alert)

        self._dispatch_coro(self.broadcast_message({"type": "NEW_CONNECTION", "data": event}))

    def set_tray(self, tray):
        """Attaches the system tray sentry for background desktop alerts."""
        self.tray = tray
        if tray and hasattr(tray, "engine") and tray.engine is None:
            tray.engine = self

    def _add_alert(self, alert: Dict[str, Any]):
        self.alerts.insert(0, alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop()
        self._dispatch_coro(self.broadcast_message({"type": "SECURITY_ALERT", "data": alert}))

        # Background Threat Notification Sentry
        if hasattr(self, "tray") and self.tray:
            try:
                notify_enabled = self.database.get_setting("desktop_notifications", "true").lower() in ("true", "1")
                if notify_enabled and (alert.get("type") in ("TRACKER_BLOCKED", "NEW_APP", "UPDATE_AVAILABLE") or alert.get("severity") in ("warning", "error", "critical")):
                    now_t = alert.get("timestamp", time.time())
                    if now_t - getattr(self, "_last_desktop_notify", 0.0) >= 4.0:
                        self._last_desktop_notify = now_t
                        self.tray.notify(alert.get("title", "TrackerControl Alert"), alert.get("message", ""))
            except Exception:
                pass

    def on_updater_event(self, event: Dict[str, Any]):
        """Dispatches updater events (e.g. UPDATE_AVAILABLE, UPDATE_PROGRESS, UPDATE_READY, UPDATE_STATUS)."""
        if event.get("type") == "UPDATE_AVAILABLE":
            up_data = event.get("data", {})
            v = up_data.get("latest_version", "")
            now = time.time()
            alert = {
                "id": f"alert-{int(now * 1000)}-update",
                "type": "UPDATE_AVAILABLE",
                "severity": "info",
                "title": f"Update Available: TrackerControl PC v{v}",
                "message": f"A new version (v{v}) is available with the latest tracker definitions and security features.",
                "process_name": "TrackerControl",
                "timestamp": now,
                "domain": "github.com",
                "ip": "GitHub Releases"
            }
            self._add_alert(alert)

        self._dispatch_coro(self.broadcast_message(event))

    def add_event_listener(self, listener: Callable[[Dict[str, Any]], None]):
        """Registers an in-process listener for native desktop GUI telemetry."""
        if not hasattr(self, "event_listeners"):
            self.event_listeners = []
        if listener not in self.event_listeners:
            self.event_listeners.append(listener)

    def remove_event_listener(self, listener: Callable[[Dict[str, Any]], None]):
        if hasattr(self, "event_listeners") and listener in self.event_listeners:
            self.event_listeners.remove(listener)

    async def broadcast_message(self, message_dict: Dict[str, Any]):
        # 1. Native Desktop GUI event listeners (Zero-localhost in-memory IPC)
        if hasattr(self, "event_listeners"):
            for listener in list(self.event_listeners):
                try:
                    listener(message_dict)
                except Exception:
                    pass

        # 2. WebSocket clients (for headless/browser fallback mode)
        if self.active_websockets:
            dead_sockets = set()
            message = json.dumps(message_dict)
            for ws in list(self.active_websockets):
                try:
                    await ws.send_text(message)
                except Exception:
                    dead_sockets.add(ws)
            for ws in dead_sockets:
                self.active_websockets.discard(ws)

    async def broadcast_event(self, event: Dict[str, Any]):
        await self.broadcast_message({"type": "NEW_CONNECTION", "data": event})

    async def _bandwidth_loop(self):
        """1-second timer collecting live upload/download speed for GlassWire-style graph."""
        while True:
            try:
                await asyncio.sleep(1.0)
                now = time.time()
                io = psutil.net_io_counters()
                rx_bytes = io.bytes_recv
                tx_bytes = io.bytes_sent

                if self.last_io_bytes is not None and self.last_io_time is not None:
                    dt = max(0.1, now - self.last_io_time)
                    rx_speed_kbps = max(0.0, (rx_bytes - self.last_io_bytes[0]) / 1024.0 / dt)
                    tx_speed_kbps = max(0.0, (tx_bytes - self.last_io_bytes[1]) / 1024.0 / dt)
                else:
                    rx_speed_kbps = 0.0
                    tx_speed_kbps = 0.0

                self.last_io_bytes = (rx_bytes, tx_bytes)
                self.last_io_time = now

                recent_blocked = sum(1 for e in self.recent_events_cache if e.get("status") == "blocked" and now - e.get("timestamp", 0) < 5)
                active_sockets = 0
                if hasattr(self, "process_monitor") and self.process_monitor:
                    active_sockets = len(getattr(self.process_monitor, "seen_connections", set()))

                point = {
                    "timestamp": now,
                    "rx_kbps": round(rx_speed_kbps, 2),
                    "tx_kbps": round(tx_speed_kbps, 2),
                    "total_rx_mb": round(rx_bytes / 1024 / 1024, 2),
                    "total_tx_mb": round(tx_bytes / 1024 / 1024, 2),
                    "blocked_recent": recent_blocked,
                    "active_sockets": active_sockets
                }

                self.bandwidth_history.append(point)
                if len(self.bandwidth_history) > self.max_bandwidth_history:
                    self.bandwidth_history.pop(0)

                if self.active_websockets or getattr(self, "event_listeners", None):
                    await self.broadcast_message({"type": "BANDWIDTH_TICK", "data": point})
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(1.0)

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
                "recent_connections": self.recent_events_cache[:30],
                "bandwidth_history": self.bandwidth_history[-60:],
                "recent_alerts": self.alerts[:30],
                "updater": self.updater.get_status() if hasattr(self, "updater") else None
            }
        }))

    def unregister_websocket(self, websocket: WebSocket):
        self.active_websockets.discard(websocket)

    def set_protection_mode(self, mode: str):
        valid_modes = ["MAX_PRIVACY", "BALANCED", "AUDIT", "AUDIT_ONLY", "LOCKDOWN"]
        if mode in valid_modes:
            self.protection_mode = mode
            if hasattr(self, "monitor") and self.monitor:
                self.monitor.set_protection_mode(mode)
            elif hasattr(self, "process_monitor") and self.process_monitor:
                self.process_monitor.set_protection_mode(mode)
            if hasattr(self, "dns_proxy") and self.dns_proxy:
                self.dns_proxy.set_protection_mode(mode)

    def toggle_shield(self, active: bool):
        self.shield_active = active
        if hasattr(self, "monitor") and self.monitor:
            self.monitor.set_shield_active(active)
        elif hasattr(self, "process_monitor") and self.process_monitor:
            self.process_monitor.set_shield_active(active)
        if hasattr(self, "dns_proxy") and self.dns_proxy:
            self.dns_proxy.toggle_shield(active)

    def toggle_kill_switch(self, active: bool) -> Dict[str, Any]:
        self.kill_switch_active = active
        if hasattr(self.firewall, "toggle_kill_switch"):
            self.firewall.toggle_kill_switch(active)
        return {"success": True, "kill_switch_active": self.kill_switch_active}

    def get_stats(self) -> Dict[str, Any]:
        stats = self.database.get_stats()
        stats["shield_active"] = self.shield_active
        stats["kill_switch_active"] = self.kill_switch_active
        stats["protection_mode"] = self.protection_mode
        stats["os_privacy"] = self.firewall.get_os_privacy_status()
        stats["windows_privacy"] = self.firewall.get_windows_privacy_status()
        stats["system_summary"] = PlatformHelper.get_system_summary()
        return stats

    def restore_dns(self):
        """Restores original system DNS configuration."""
        if hasattr(self, "dns_proxy") and self.dns_proxy:
            self.dns_proxy.restore_system_dns()

    def restore_system_dns(self):
        """Restores original system DNS configuration."""
        self.restore_dns()

    async def start(self):
        print(f"[Engine] Initializing TrackerControl PC Subsystems on {PlatformHelper.get_os_type()}...")
        loop = asyncio.get_event_loop()
        self.loop = loop

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
            # Automatically redirect OS DNS to local sinkhole if bound to port 53
            if self.dns_proxy.listen_port == 53:
                self.dns_proxy.configure_system_dns()
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
                print("[DNS] Notice: Running on fallback port 5353. To intercept OS-wide DNS queries, run TrackerControl as Administrator / root so port 53 can bind.")
            except Exception as ex:
                print(f"[DNS] Could not bind fallback DNS: {ex}")
        except Exception as e:
            print(f"[DNS] DNS Server binding info: {e}")

        # Start Process Monitor
        self._monitor_task = asyncio.create_task(self.process_monitor.start())
        print(f"[ProcessMonitor] Real-time socket scanner active for {PlatformHelper.get_os_type()}.")

        # Start GlassWire-style Live Bandwidth Monitor
        self._bandwidth_task = asyncio.create_task(self._bandwidth_loop())
        print(f"[BandwidthEngine] Real-time traffic graph sampler active.")

        # Start Auto-Updater background checking loop if enabled
        if hasattr(self, "updater") and self.updater:
            self._updater_task = asyncio.create_task(self.updater.start_periodic_check(delay_initial_seconds=4))
            print("[AutoUpdater] Background update sentry initialized.")

        # Ensure Multi-VPN SOCKS5 split-tunneling proxies are running for active tunnels
        if hasattr(self, "wireguard") and self.wireguard and hasattr(self.wireguard, "proxy_manager"):
            try:
                self.wireguard._detect_system_vpn_interfaces()
                await self.wireguard.proxy_manager.sync_tunnels(self.wireguard.tunnels)
                print(f"[WireGuard] Initialized SOCKS5 split-tunneling proxies ({len(self.wireguard.tunnels)} active).")
            except Exception as e:
                print(f"[WireGuard] Proxy sync error on startup: {e}")

        # Auto-start Orbot / Tor daemon if available and enabled (default True)
        if hasattr(self, "orbot") and self.orbot:
            try:
                tor_bin = self.orbot.find_tor_binary()
                auto_tor = self.database.get_setting("orbot_auto_start", "true").lower() in ("true", "1")
                if auto_tor and tor_bin:
                    print(f"[Orbot] Auto-launching detected Tor daemon ({tor_bin}) in background...")
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(None, self.orbot.start_tor_service)
            except Exception as e:
                print(f"[Orbot] Notice during auto-start: {e}")

    async def stop(self):
        print("[Engine] Stopping TrackerControl PC...")
        if hasattr(self, "updater") and self.updater:
            self.updater.stop()
        if self._updater_task:
            self._updater_task.cancel()
        if self._bandwidth_task:
            self._bandwidth_task.cancel()
        if self.process_monitor:
            self.process_monitor.stop()
        if self._monitor_task:
            self._monitor_task.cancel()
        if self.dns_proxy:
            try:
                self.dns_proxy.restore_system_dns()
            except Exception as e:
                print(f"[Engine] Notice during DNS restore: {e}")
            if self.dns_proxy.transport:
                self.dns_proxy.transport.close()
        if self.port_forwarder:
            try:
                await self.port_forwarder.stop_all()
            except Exception as e:
                print(f"[Engine] Notice during port forwarder cleanup: {e}")
        if self.firewall:
            try:
                self.firewall.flush_all_tc_rules()
            except Exception as e:
                print(f"[Engine] Notice during firewall cleanup: {e}")
        if hasattr(self, "wireguard") and self.wireguard:
            try:
                for tid, t in list(self.wireguard.tunnels.items()):
                    if t.get("status") == "Connected":
                        self.wireguard.disconnect_tunnel(tid)
            except Exception:
                pass
            if hasattr(self.wireguard, "proxy_manager"):
                try:
                    await self.wireguard.proxy_manager.stop_all()
                except Exception:
                    pass
        if hasattr(self, "orbot") and self.orbot:
            try:
                self.orbot.stop_tor_service()
            except Exception:
                pass

        # Close all active WebSockets gracefully
        for ws in list(self.active_websockets):
            try:
                await ws.close()
            except Exception:
                pass
        self.active_websockets.clear()

    def get_bandwidth_history(self) -> List[Dict[str, Any]]:
        return self.bandwidth_history

    def get_alerts(self) -> List[Dict[str, Any]]:
        return self.alerts

    def clear_alerts(self):
        self.alerts.clear()

