"""
Cross-Platform Real-time Process Network Monitor & Socket Attribution Engine for TrackerControl PC.
Maps active Linux & Windows TCP/UDP sockets directly to Process IDs, Executables,
and Parent Process Trees, resolving domain names and classifying trackers.
"""

import asyncio
import concurrent.futures
import psutil
import socket
import time
from typing import Dict, Any, Set, Tuple, Optional, Callable

from .platform_helper import IS_WINDOWS, IS_LINUX

class ProcessMonitor:
    def __init__(
        self,
        intelligence,
        database,
        dns_proxy,
        firewall=None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        poll_interval: float = 0.5,
        protection_mode: str = "MAX_PRIVACY"
    ):
        self.intelligence = intelligence
        self.database = database
        self.dns_proxy = dns_proxy

        # Support both (firewall, event_callback) and legacy (event_callback) as 4th positional arg
        if callable(firewall) and event_callback is None:
            self.firewall = None
            self.event_callback = firewall
        else:
            self.firewall = firewall
            self.event_callback = event_callback

        self.poll_interval = poll_interval
        self.protection_mode = protection_mode
        self.shield_active = True
        self.blocked_ips: Set[str] = set()
        
        self.is_running = False
        self.seen_connections: Set[Tuple[int, str, int, str, int]] = set()
        self.process_cache: Dict[int, Dict[str, Any]] = {}
        self.rdns_cache: Dict[str, str] = {}
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=8)
        self._warned_permissions = False

    def set_shield_active(self, active: bool):
        self.shield_active = active

    def set_protection_mode(self, mode: str):
        self.protection_mode = mode

    def resolve_rdns(self, ip: str) -> Optional[str]:
        if ip in self.rdns_cache:
            return self.rdns_cache[ip]
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            self.rdns_cache[ip] = host
            return host
        except Exception:
            self.rdns_cache[ip] = ip
            return None

    def get_process_info(self, pid: Optional[int]) -> Dict[str, Any]:
        if not pid or pid == 0:
            if IS_WINDOWS:
                return {
                    "name": "System",
                    "exe": "C:\\Windows\\System32\\ntoskrnl.exe",
                    "parent": "None"
                }
            else:
                return {
                    "name": "Kernel / System",
                    "exe": "/boot/vmlinuz",
                    "parent": "systemd"
                }
        
        if pid in self.process_cache:
            return self.process_cache[pid]

        try:
            p = psutil.Process(pid)
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                exe = name
            try:
                parent = p.parent().name() if p.parent() else "None"
            except Exception:
                parent = "None"

            info = {"name": name, "exe": exe, "parent": parent}
            self.process_cache[pid] = info
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"name": f"PID-{pid}", "exe": "", "parent": "Unknown"}

    async def scan_once(self):
        loop = asyncio.get_event_loop()
        try:
            # Fetch network connections
            connections = await loop.run_in_executor(
                self.thread_pool,
                lambda: psutil.net_connections(kind="inet")
            )
        except psutil.AccessDenied:
            if not self._warned_permissions and IS_LINUX:
                print("[ProcessMonitor] Tip: Run with sudo on Linux for complete kernel socket visibility.")
                self._warned_permissions = True
            connections = []
        except Exception as e:
            print(f"[ProcessMonitor] Error fetching connections: {e}")
            connections = []

        current_active: Set[Tuple[int, str, int, str, int]] = set()

        for c in connections:
            if not c.raddr:
                continue
            
            # Filter local/loopback noise
            remote_ip = c.raddr.ip
            remote_port = c.raddr.port
            local_ip = c.laddr.ip if c.laddr else "0.0.0.0"
            local_port = c.laddr.port if c.laddr else 0
            pid = c.pid or 0

            # Ignore pure loopback unless requested
            if remote_ip == "127.0.0.1" or remote_ip == "::1":
                continue

            conn_key = (pid, remote_ip, remote_port, local_ip, local_port)
            current_active.add(conn_key)

            if conn_key in self.seen_connections:
                continue
            self.seen_connections.add(conn_key)

            # Attribution logic
            proc_info = self.get_process_info(pid)
            proc_name = proc_info["name"]
            exe_path = proc_info["exe"]

            # Try to resolve domain name:
            # 1. DNS Proxy Reverse Cache
            # 2. Reverse DNS
            domain = self.dns_proxy.get_domain_for_ip(remote_ip)
            if not domain:
                resolved = await loop.run_in_executor(None, self.resolve_rdns, remote_ip)
                domain = resolved or remote_ip

            # Classify threat
            domain_threat = self.intelligence.inspect_domain(domain)
            ip_threat = self.intelligence.inspect_ip(remote_ip)

            is_tracker = bool(domain_threat.get("is_tracker", False) or ip_threat.get("is_tracker", False))

            category = domain_threat.get("category")
            if not category or category in ("Functional", "Unknown"):
                category = ip_threat.get("category", category or "General")

            company = domain_threat.get("company")
            if not company or company == "Unknown":
                company = ip_threat.get("company", "Unknown")

            country = ip_threat.get("country")
            if not country or country in ("Global", "Unknown"):
                country = domain_threat.get("country", "US")

            flag = ip_threat.get("flag")
            if not flag or flag == "🌐":
                flag = domain_threat.get("flag", "🌐")

            threat = {
                "is_tracker": is_tracker,
                "category": category,
                "company": company,
                "risk": domain_threat.get("risk", "Low"),
                "name": domain_threat.get("name") or ip_threat.get("company", "Unknown Tracker"),
                "country": country,
                "flag": flag,
                "rule_matched": domain_threat.get("rule_matched", "")
            }

            # Check app privacy policy in database
            try:
                control_mode = self.database.get_app_mode(exe_path, proc_name)
            except TypeError:
                control_mode = self.database.get_app_mode(proc_name)

            if isinstance(control_mode, dict):
                control_mode = control_mode.get("control_mode", "block_trackers")
            if not control_mode:
                control_mode = "block_trackers"

            # Determine final status
            status = "allowed"
            block_reason = None

            if not self.shield_active:
                status = "allowed"
                block_reason = "Shield Disabled"
            elif self.protection_mode in ("AUDIT", "AUDIT_ONLY"):
                status = "allowed"
                block_reason = "Audit Mode"
            elif control_mode == "block_all":
                status = "blocked"
                block_reason = f"Application '{proc_name}' is set to Block All Outbound"
            elif control_mode == "allow_all":
                status = "allowed"
                block_reason = "Application Whitelisted"
            elif control_mode == "block_trackers":
                if is_tracker:
                    status = "blocked"
                    block_reason = f"Matched Tracker Signature: {threat.get('name', 'Unknown Tracker')}"
                else:
                    status = "allowed"
            elif control_mode == "audit":
                status = "allowed"
                block_reason = "Audit Mode"

            # Enforce firewall blocking if tracker / blocked and shield is active
            if status == "blocked" and self.shield_active:
                if self.protection_mode in ("MAX_PRIVACY", "LOCKDOWN"):
                    if self.firewall and remote_ip not in self.blocked_ips:
                        try:
                            self.firewall.block_ip(remote_ip)
                        except Exception as e:
                            print(f"[ProcessMonitor] Error blocking IP {remote_ip}: {e}")
                        self.blocked_ips.add(remote_ip)

            # Assemble event
            event = {
                "timestamp": time.time(),
                "pid": pid,
                "process_name": proc_name,
                "exe_path": exe_path,
                "domain": domain,
                "ip": remote_ip,
                "port": remote_port,
                "protocol": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                "category": threat.get("category", "General"),
                "company": threat.get("company", "Unknown"),
                "risk": threat.get("risk", "Low"),
                "status": status,
                "block_reason": block_reason,
                "country": threat.get("country", "US"),
                "flag": threat.get("flag", "🌐")
            }

            # Persist and dispatch
            self.database.log_connection(event)
            if self.event_callback:
                self.event_callback(event)

        # Cleanup closed sockets from seen cache
        if len(self.seen_connections) > 1000:
            self.seen_connections = self.seen_connections.intersection(current_active)

    async def start(self):
        self.is_running = True
        while self.is_running:
            try:
                if self.shield_active:
                    await self.scan_once()
            except Exception as e:
                print(f"[ProcessMonitor] Error: {e}")
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self.is_running = False
        self.thread_pool.shutdown(wait=False)
