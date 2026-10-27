"""
Cross-Platform Real-time Process Network Monitor & Socket Attribution Engine for TrackerControl PC.
Maps active Linux & Windows TCP/UDP sockets directly to Process IDs, Executables,
and Parent Process Trees, resolving domain names and classifying trackers.
"""

import asyncio
import concurrent.futures
import os
import shutil
import socket
import subprocess
import time
from typing import Dict, Any, Set, Tuple, Optional, Callable, List

import psutil

from .platform_helper import IS_WINDOWS, IS_LINUX, IS_MACOS

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
        self._recent_endpoint_cache: Dict[Tuple[str, int], Tuple[float, Dict[str, Any]]] = {}
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

    def _find_process_via_lsof(self, client_ip: str, client_port: int) -> Optional[Dict[str, Any]]:
        """
        macOS & Unix non-root fallback: resolves owning process using lsof for a given local socket port.
        """
        lsof_bin = shutil.which("lsof") or ("/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else None)
        if not lsof_bin:
            return None

        try:
            cmd = [lsof_bin, "-n", "-P", f"-i:{client_port}"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout:
                lines = res.stdout.strip().splitlines()
                # Skip header line
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        pid = int(parts[1])
                        endpoint_match = False
                        for p in parts[8:]:
                            if f":{client_port}" in p:
                                endpoint_match = True
                                break
                        if endpoint_match or len(lines) == 2:
                            info = self.get_process_info(pid)
                            cmd_name = parts[0]
                            return {
                                "pid": pid,
                                "process_name": info.get("name") or cmd_name,
                                "exe_path": info.get("exe") or ""
                            }
        except Exception:
            pass
        return None

    def _get_connections_via_lsof(self) -> List[Any]:
        """
        Parses active TCP and UDP internet connections via lsof on macOS / Unix
        when psutil.net_connections() cannot inspect kernel sockets without root.
        """
        lsof_bin = shutil.which("lsof") or ("/usr/sbin/lsof" if os.path.exists("/usr/sbin/lsof") else None)
        if not lsof_bin:
            return []

        conns = []
        try:
            cmd = [lsof_bin, "-iTCP", "-iUDP", "-n", "-P"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.strip().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) < 8 or not parts[1].isdigit():
                        continue

                    pid = int(parts[1])

                    # Look for connection part with -> (established or connected UDP/TCP)
                    conn_str = None
                    for p in parts[8:]:
                        if "->" in p:
                            conn_str = p
                            break

                    if not conn_str:
                        continue

                    conn_str = conn_str.split("(")[0].strip()
                    if "->" not in conn_str:
                        continue

                    local_part, remote_part = conn_str.split("->", 1)
                    if ":" not in local_part or ":" not in remote_part:
                        continue

                    local_ip, local_port_str = local_part.rsplit(":", 1)
                    remote_ip, remote_port_str = remote_part.rsplit(":", 1)

                    try:
                        local_port = int(local_port_str)
                        remote_port = int(remote_port_str)
                    except ValueError:
                        continue

                    is_tcp = "TCP" in line.upper()
                    sock_type = socket.SOCK_STREAM if is_tcp else socket.SOCK_DGRAM

                    conn_obj = type("Connection", (), {
                        "pid": pid,
                        "type": sock_type,
                        "laddr": type("Addr", (), {"ip": local_ip, "port": local_port})(),
                        "raddr": type("Addr", (), {"ip": remote_ip, "port": remote_port})(),
                        "status": "ESTABLISHED"
                    })()
                    conns.append(conn_obj)
        except Exception:
            pass
        return conns

    def find_process_for_endpoint(self, client_ip: str, client_port: int) -> Optional[Dict[str, Any]]:
        """
        Attempts to correlate a local socket (client_ip, client_port) to the owning process.
        Returns a dict: {"pid": int|None, "process_name": str, "exe_path": str} or None on failure.

        Note: Performs a cached or fresh scan and falls back to lsof on macOS/Unix when non-root.
        Callers should run it in a thread executor to avoid blocking the event loop.
        """
        cache_key = (client_ip, client_port)
        now = time.time()
        cached = self._recent_endpoint_cache.get(cache_key)
        if cached and (now - cached[0]) < 2.0:
            return cached[1]

        result = None
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                laddr = c.laddr
                if not laddr:
                    continue
                lip = getattr(laddr, "ip", None)
                lport = getattr(laddr, "port", None)
                if lip == client_ip and lport == client_port:
                    pid = c.pid or None
                    info = self.get_process_info(pid)
                    result = {"pid": pid, "process_name": info.get("name"), "exe_path": info.get("exe")}
                    break
        except (psutil.AccessDenied, PermissionError):
            result = self._find_process_via_lsof(client_ip, client_port)
        except Exception:
            result = None

        if result is None and (IS_MACOS or IS_LINUX):
            result = self._find_process_via_lsof(client_ip, client_port)

        if result:
            self._recent_endpoint_cache[cache_key] = (now, result)
            if len(self._recent_endpoint_cache) > 500:
                self._recent_endpoint_cache = {
                    k: v for k, v in self._recent_endpoint_cache.items() if (now - v[0]) < 4.0
                }

        return result

    def _is_private_or_local(self, ip_str: str) -> bool:
        if not ip_str or ip_str in ("0.0.0.0", "::", "127.0.0.1", "localhost"):
            return True
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip_str)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_link_local
        except Exception:
            return True

    async def scan_once(self):
        loop = asyncio.get_event_loop()
        try:
            # Fetch network connections
            connections = await loop.run_in_executor(
                self.thread_pool,
                lambda: psutil.net_connections(kind="inet")
            )
        except psutil.AccessDenied:
            if not self._warned_permissions:
                if IS_LINUX:
                    print("[ProcessMonitor] Tip: Run with sudo on Linux for complete kernel socket visibility.")
                elif IS_MACOS:
                    print("[ProcessMonitor] Tip: Run with sudo on macOS for complete socket inspection.")
                self._warned_permissions = True
            if IS_MACOS or IS_LINUX:
                connections = await loop.run_in_executor(
                    self.thread_pool,
                    self._get_connections_via_lsof
                )
            else:
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

            # Determine initial intent and enforce policy
            status = "allowed"
            block_reason = None

            if not self.shield_active:
                status = "allowed"
                block_reason = "Shield Disabled"
            elif self.protection_mode in ("AUDIT", "AUDIT_ONLY"):
                status = "allowed"
                block_reason = "Audit Mode (Monitoring Only)"
            elif control_mode == "allow_all":
                status = "allowed"
                block_reason = "Application Whitelisted"
            elif control_mode == "audit":
                status = "allowed"
                block_reason = "Audit Mode"
            elif control_mode == "block_all":
                # App-specific block: block entire application
                if self.firewall and self.shield_active:
                    fw_res = self.firewall.block_executable(exe_path, proc_name)
                    if fw_res.get("success"):
                        status = "blocked"
                        block_reason = f"Application '{proc_name}' blocked by firewall policy"
                    else:
                        status = "flagged"
                        err_detail = fw_res.get("error") or "Elevation required"
                        block_reason = f"App set to Block All; firewall enforcement failed: {err_detail}"
                else:
                    status = "flagged"
                    block_reason = f"App set to Block All (Firewall inactive)"
            elif control_mode == "block_trackers":
                if is_tracker:
                    if not self.shield_active:
                        status = "allowed"
                        block_reason = "Shield Disabled"
                    elif self._is_private_or_local(remote_ip):
                        status = "allowed"
                        block_reason = "Local / Private Network IP"
                    elif not self.firewall:
                        status = "flagged"
                        block_reason = f"Matched Tracker: {threat.get('name', 'Unknown Tracker')} (Firewall inactive)"
                    else:
                        rule_key = f"{proc_name}_{remote_ip}"
                        is_shared = getattr(self.firewall, "is_shared_infrastructure", lambda ip: False)(remote_ip)

                        if rule_key in self.blocked_ips or (not is_shared and remote_ip in self.blocked_ips):
                            status = "blocked"
                            block_reason = f"Matched Tracker Signature: {threat.get('name', 'Unknown Tracker')}"
                        elif is_shared:
                            # CRITICAL: Prevent collateral damage on shared CDNs / multi-tenant infrastructure
                            # Use application-isolated rule target, never drop global IP
                            if hasattr(self.firewall, "block_app_target"):
                                fw_res = self.firewall.block_app_target(exe_path, proc_name, remote_ip)
                                if fw_res.get("success"):
                                    status = "blocked"
                                    block_reason = f"Blocked Tracker (App-Isolated on CDN): {threat.get('name', 'Unknown')}"
                                    if len(self.blocked_ips) > 2000:
                                        self.blocked_ips.clear()
                                    self.blocked_ips.add(rule_key)
                                else:
                                    status = "flagged"
                                    err_detail = fw_res.get("error") or "Elevation required"
                                    block_reason = f"Tracker on shared CDN; app-isolated rule failed: {err_detail}"
                            else:
                                status = "flagged"
                                block_reason = "Tracker on shared CDN; domain sinkholed at DNS layer"
                        else:
                            # Dedicated tracker IP: attempt app-isolated rule first if exe is known, else block_ip
                            if exe_path and hasattr(self.firewall, "block_app_target"):
                                fw_res = self.firewall.block_app_target(exe_path, proc_name, remote_ip)
                            else:
                                fw_res = self.firewall.block_ip(remote_ip)

                            if fw_res.get("success"):
                                status = "blocked"
                                block_reason = f"Matched Tracker Signature: {threat.get('name', 'Unknown Tracker')}"
                                if len(self.blocked_ips) > 2000:
                                    self.blocked_ips.clear()
                                self.blocked_ips.add(remote_ip)
                            else:
                                status = "flagged"
                                err_detail = fw_res.get("error") or "Firewall rule failed or unprivileged"
                                block_reason = f"Tracker detected; firewall enforcement unavailable: {err_detail}"
                else:
                    status = "allowed"
                    block_reason = "Clean Connection"

            # Assemble event
            event = {
                "timestamp": time.time(),
                "pid": pid,
                "process_name": proc_name,
                "exe_path": exe_path,
                "domain": domain,
                "ip": remote_ip,
                "port": remote_port,
                "protocol": "TCP" if getattr(c, "type", socket.SOCK_STREAM) == socket.SOCK_STREAM else "UDP",
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
