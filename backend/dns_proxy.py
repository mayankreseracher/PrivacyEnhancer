"""
High-Performance Local DNS Interception & Sinkhole Engine for TrackerControl PC.
Intercepts DNS requests, matches against tracker intelligence, and instantly sinkholes
blocked domains to 0.0.0.0 while forwarding valid requests to upstream secure resolvers.
Also maintains an IP -> Domain cache for process socket attribution.
"""

import asyncio
import atexit
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from typing import Dict, Any, List, Optional, Callable
from dnslib import DNSRecord, DNSHeader, RR, A, AAAA, QTYPE, RCODE
from .platform_helper import PlatformHelper

DATA_DIR = PlatformHelper.get_data_dir()
DNS_BACKUP_FILE = os.path.join(DATA_DIR, "original_dns_backup.json")

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")
IS_MACOS = sys.platform == "darwin"

class DNSProxy:
    def __init__(
        self,
        intelligence,
        database,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 53,
        upstream_dns: str = "1.1.1.1",
        upstream_port: int = 53
    ):
        self.intelligence = intelligence
        self.database = database
        self.event_callback = event_callback
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.upstream_port = upstream_port
        
        self.is_running = False
        self.transport = None
        self.protocol = None
        self.ip_to_domain_cache: Dict[str, str] = {} # IP -> Domain mapping
        self.domain_to_ip_cache: Dict[str, str] = {}
        self.original_dns_settings: Dict[str, Any] = {}
        self.dns_configured: bool = False
        self.protection_mode: str = "MAX_PRIVACY"
        self.shield_active: bool = True

        # Optional ProcessMonitor reference for DNS client attribution (set by engine)
        self.process_monitor = None

    def set_protection_mode(self, mode: str):
        self.protection_mode = mode

    def toggle_shield(self, active: bool):
        self.shield_active = active

    def get_domain_for_ip(self, ip: str) -> Optional[str]:
        return self.ip_to_domain_cache.get(ip)

    async def handle_dns_query(self, data: bytes, client_addr) -> bytes:
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".")
            qtype_code = request.q.qtype
            try:
                qtype = QTYPE.get(qtype_code, str(qtype_code))
            except Exception:
                qtype = str(qtype_code)
            
            # Inspect domain
            threat = self.intelligence.inspect_domain(qname)
            is_tracker = threat.get("is_tracker", False)

            # Check custom rules in database
            custom_rules = self.database.get_custom_rules()
            custom_block = False
            custom_allow = False
            for r in custom_rules:
                if r["target_type"] == "domain":
                    target = r["target_value"].lower().strip()
                    if target == qname.lower() or qname.lower().endswith("." + target):
                        if r["action"] == "block":
                            custom_block = True
                        elif r["action"] == "allow":
                            custom_allow = True

            # Attempt to attribute DNS request to originating process via ProcessMonitor
            pid = None
            process_name = "DNS Client"
            exe_path = ""
            try:
                client_ip = client_addr[0] if isinstance(client_addr, (tuple, list)) and len(client_addr) > 0 else None
                client_port = client_addr[1] if isinstance(client_addr, (tuple, list)) and len(client_addr) > 1 else None
                if client_ip and client_port and hasattr(self, "process_monitor") and self.process_monitor:
                    loop = asyncio.get_running_loop()
                    finder = lambda: self.process_monitor.find_process_for_endpoint(client_ip, client_port)
                    proc = await loop.run_in_executor(None, finder)
                    if proc:
                        pid = proc.get("pid")
                        process_name = proc.get("process_name") or process_name
                        exe_path = proc.get("exe_path") or exe_path
            except Exception:
                # Attribution best-effort only; fall back to DNS Client placeholders
                pid = None
                process_name = "DNS Client"
                exe_path = ""

            # Guest / Audit Mode & Shield Active check
            is_audit_mode = (self.protection_mode in ("AUDIT", "AUDIT_ONLY") or not self.shield_active)

            # Check per-application policy if process is attributed
            app_policy = None
            if process_name and process_name != "DNS Client":
                try:
                    app_policy = self.database.get_app_mode(exe_path, process_name)
                    if isinstance(app_policy, dict):
                        app_policy = app_policy.get("control_mode")
                except Exception:
                    pass

            if app_policy == "allow_all":
                should_block = False
            elif app_policy == "block_all":
                should_block = not is_audit_mode
            elif app_policy == "audit":
                should_block = False
            else:
                should_block = (is_tracker or custom_block) and not custom_allow and not is_audit_mode

            # If blocked: generate sinkhole response (0.0.0.0 / ::) or NXDOMAIN
            if should_block:
                if qtype == "A" or qtype_code == 1:
                    reply = DNSRecord(
                        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                        q=request.q
                    )
                    reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
                elif qtype == "AAAA" or qtype_code == 28:
                    reply = DNSRecord(
                        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                        q=request.q
                    )
                    reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=300))
                else:
                    # Bug 2 fix: For HTTPS (type 65), SVCB (type 64), and other record types
                    # on blocked domains, return NXDOMAIN (rcode=3) to prevent connection leaks
                    nxdomain_rcode = getattr(RCODE, "NXDOMAIN", 3)
                    reply = DNSRecord(
                        DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, rcode=nxdomain_rcode),
                        q=request.q
                    )

                event = {
                    "timestamp": time.time(),
                    "pid": pid,
                    "process_name": process_name,
                    "exe_path": exe_path,
                    "domain": qname,
                    "ip": "0.0.0.0",
                    "port": 53,
                    "protocol": "DNS",
                    "category": threat.get("category", "Advertising"),
                    "company": threat.get("company", "Unknown"),
                    "risk": threat.get("risk", "High"),
                    "status": "blocked",
                    "block_reason": f"Blocked Tracker: {threat.get('name', qname)}",
                    "country": threat.get("country", "US"),
                    "flag": threat.get("flag", "🛑")
                }
                
                self.database.log_connection(event)
                if self.event_callback:
                    self.event_callback(event)

                return reply.pack()

            # If threat detected in Audit / Guest mode, log audit event without blocking
            if not should_block and (is_tracker or custom_block):
                audit_event = {
                    "timestamp": time.time(),
                    "pid": pid,
                    "process_name": process_name,
                    "exe_path": exe_path,
                    "domain": qname,
                    "ip": "Audit",
                    "port": 53,
                    "protocol": "DNS",
                    "category": threat.get("category", "Advertising"),
                    "company": threat.get("company", "Unknown"),
                    "risk": threat.get("risk", "Medium"),
                    "status": "audit",
                    "block_reason": "Audit Mode (Monitoring Only)",
                    "country": threat.get("country", "US"),
                    "flag": threat.get("flag", "👁️")
                }
                self.database.log_connection(audit_event)
                if self.event_callback:
                    self.event_callback(audit_event)

            # Otherwise, forward upstream asynchronously (Bug 1 fix)
            upstream_response = await self._forward_upstream(data)
            if upstream_response:
                # Cache resolved IPs
                try:
                    resp_record = DNSRecord.parse(upstream_response)
                    for rr in resp_record.rr:
                        if rr.rtype == QTYPE.A:
                            resolved_ip = str(rr.rdata)
                            self.ip_to_domain_cache[resolved_ip] = qname
                            self.domain_to_ip_cache[qname] = resolved_ip
                except Exception:
                    pass

                event = {
                    "timestamp": time.time(),
                    "pid": pid,
                    "process_name": process_name,
                    "exe_path": exe_path,
                    "domain": qname,
                    "ip": self.domain_to_ip_cache.get(qname, "Resolved"),
                    "port": 53,
                    "protocol": "DNS",
                    "category": threat.get("category", "Functional"),
                    "company": threat.get("company", "Functional"),
                    "risk": "Clean",
                    "status": "allowed",
                    "block_reason": "Clean Domain",
                    "country": threat.get("country", "Global"),
                    "flag": threat.get("flag", "🌐")
                }
                self.database.log_connection(event)
                if self.event_callback:
                    self.event_callback(event)

                return upstream_response

        except Exception as e:
            # Fallback pass-through on parse error
            pass

        return (await self._forward_upstream(data)) or b""

    def _forward_upstream_sync(self, data: bytes) -> Optional[bytes]:
        """
        Synchronous UDP query to upstream DNS resolver with resilient fail-open
        fallback across primary and secondary upstream resolvers (1.1.1.1, 9.9.9.9, 8.8.8.8).
        """
        candidate_resolvers = [self.upstream_dns]
        for fallback in ("1.1.1.1", "9.9.9.9", "8.8.8.8"):
            if fallback != self.upstream_dns and fallback not in candidate_resolvers:
                candidate_resolvers.append(fallback)

        for resolver in candidate_resolvers:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1.5)
                sock.sendto(data, (resolver, self.upstream_port))
                resp, _ = sock.recvfrom(4096)
                if resp and len(resp) >= 12:
                    return resp
            except Exception:
                continue
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
        return None

    async def _forward_upstream(self, data: bytes) -> Optional[bytes]:
        """
        Asynchronously forwards standard DNS query over UDP to upstream resolver
        using a thread pool executor, preventing blocking of the asyncio event loop (Bug 1 fix).
        """
        try:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, self._forward_upstream_sync, data)
        except RuntimeError:
            return self._forward_upstream_sync(data)

    # ==================== System DNS Reconfiguration (Bug 3) ====================
    # NOTE: configure_system_dns() and restore_system_dns() should be called from
    # engine.py's start() and stop() methods to route system DNS traffic through this proxy.

    def _save_dns_backup_to_disk(self):
        """Persists original DNS configurations to disk so an unexpected reboot or crash can recover."""
        try:
            if self.original_dns_settings:
                with open(DNS_BACKUP_FILE, "w", encoding="utf-8") as f:
                    json.dump(self.original_dns_settings, f, indent=2)
                print(f"[DNS] Persistent original DNS backup saved to {DNS_BACKUP_FILE}")
        except Exception as e:
            print(f"[DNS] Warning saving DNS backup to disk: {e}")

    def _load_dns_backup_from_disk(self):
        """Loads persistent original DNS backup from disk if available."""
        if os.path.exists(DNS_BACKUP_FILE):
            try:
                with open(DNS_BACKUP_FILE, "r", encoding="utf-8") as f:
                    self.original_dns_settings = json.load(f)
                print(f"[DNS] Loaded original DNS backup from {DNS_BACKUP_FILE}")
            except Exception as e:
                print(f"[DNS] Error loading DNS backup from disk: {e}")

    def _remove_dns_backup_from_disk(self):
        """Removes persistent original DNS backup after clean restoration."""
        if os.path.exists(DNS_BACKUP_FILE):
            try:
                os.remove(DNS_BACKUP_FILE)
                print("[DNS] Cleaned up original DNS backup from disk.")
            except Exception:
                pass

    def _flush_system_dns_cache(self):
        """Flushes host operating system DNS cache."""
        try:
            if IS_WINDOWS:
                subprocess.run(
                    ["ipconfig", "/flushdns"],
                    capture_output=True,
                    timeout=4,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                )
            elif IS_LINUX:
                if shutil.which("resolvectl"):
                    subprocess.run(["resolvectl", "flush-caches"], capture_output=True, timeout=3)
                elif shutil.which("systemd-resolve"):
                    subprocess.run(["systemd-resolve", "--flush-caches"], capture_output=True, timeout=3)
            elif IS_MACOS:
                subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, timeout=3)
                subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, timeout=3)
        except Exception:
            pass
    def configure_system_dns(self) -> bool:
        """
        Configures the host operating system to route DNS queries to this proxy (127.0.0.1).
        Stores original DNS settings in RAM and persists to disk for emergency crash recovery.
        """
        if self.dns_configured:
            return True

        if self.listen_port != 53:
            print(f"[DNS] Warning: DNS Proxy is listening on port {self.listen_port}, but OS resolvers query port 53.")

        print(f"[DNS] Reconfiguring system DNS to {self.listen_host}...")
        try:
            if IS_WINDOWS:
                self.original_dns_settings["interfaces"] = {}
                self._configure_windows_dns()
            elif IS_LINUX:
                self._configure_linux_dns()
            elif IS_MACOS:
                self.original_dns_settings["macos"] = {}
                self._configure_macos_dns()
            else:
                print(f"[DNS] System DNS automatic reconfiguration not implemented for {sys.platform}.")

            # Save on-disk backup immediately for crash resilience
            self._save_dns_backup_to_disk()

            self.dns_configured = True
            atexit.register(self.restore_system_dns)
            return True
        except Exception as e:
            print(f"[DNS] Failed to configure system DNS: {e}")
            return False

    def restore_system_dns(self, force_clean_all: bool = False) -> bool:
        """
        Restores host operating system DNS configuration to original pre-proxy settings.
        Capable of loading state from disk backup or performing an emergency DHCP reset.
        """
        if not self.dns_configured and not self.original_dns_settings and not force_clean_all:
            if not os.path.exists(DNS_BACKUP_FILE):
                return True

        print("[DNS] Restoring original system DNS configuration...")
        if not self.original_dns_settings:
            self._load_dns_backup_from_disk()

        try:
            if IS_WINDOWS:
                self._restore_windows_dns(force_clean_all=force_clean_all)
            elif IS_LINUX:
                self._restore_linux_dns()
            elif IS_MACOS:
                self._restore_macos_dns()

            self.dns_configured = False
            self.original_dns_settings.clear()
            self._remove_dns_backup_from_disk()
            self._flush_system_dns_cache()
            return True
        except Exception as e:
            print(f"[DNS] Failed to restore system DNS: {e}")
            return False

    def restore_dns(self, force_clean_all: bool = False) -> bool:
        """Alias for restore_system_dns."""
        return self.restore_system_dns(force_clean_all=force_clean_all)

    def _get_active_windows_interfaces(self) -> List[str]:
        """Finds all active, connected network interfaces on Windows."""
        interfaces = []
        try:
            res = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            for line in res.stdout.splitlines():
                parts = line.strip().split(None, 3)
                if len(parts) >= 4 and "connected" in parts[1].lower():
                    interfaces.append(parts[3])
        except Exception:
            pass

        # Supplement or fallback with psutil active non-loopback interfaces
        if not interfaces:
            try:
                import psutil
                for iface, stats in psutil.net_if_stats().items():
                    if stats.isup and "loopback" not in iface.lower():
                        interfaces.append(iface)
            except Exception:
                pass

        return list(dict.fromkeys(interfaces))

    def _get_windows_dns_config(self, iface: str) -> Dict[str, Any]:
        """Queries and parses the current DNS configuration for a Windows network interface."""
        config: Dict[str, Any] = {"is_dhcp": True, "servers": []}
        try:
            res = subprocess.run(
                ["netsh", "interface", "ip", "show", "config", f"name={iface}"],
                capture_output=True,
                text=True,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            if res.returncode == 0:
                parsing_static = False
                for line in res.stdout.splitlines():
                    line_str = line.strip()
                    if not line_str:
                        continue
                    lower = line_str.lower()
                    if "statically configured dns servers" in lower:
                        config["is_dhcp"] = False
                        parsing_static = True
                        parts = line_str.split(":", 1)
                        if len(parts) > 1 and parts[1].strip():
                            val = parts[1].strip()
                            if any(c.isdigit() for c in val):
                                config["servers"].append(val)
                    elif "dns servers configured through dhcp" in lower:
                        config["is_dhcp"] = True
                        parsing_static = False
                        parts = line_str.split(":", 1)
                        if len(parts) > 1 and parts[1].strip():
                            val = parts[1].strip()
                            if any(c.isdigit() for c in val):
                                config["servers"].append(val)
                    elif parsing_static:
                        if ":" in line_str:
                            parsing_static = False
                        else:
                            val = line_str.strip()
                            if any(c.isdigit() for c in val):
                                config["servers"].append(val)
        except Exception as e:
            print(f"[DNS] Could not query DNS config for {iface}: {e}")
        return config

    def _configure_windows_dns(self):
        """Configures DNS on Windows network interfaces to point to 127.0.0.1."""
        interfaces = self._get_active_windows_interfaces()
        if not interfaces:
            print("[DNS] Notice: No active connected network interfaces detected on Windows.")
            return

        for iface in interfaces:
            orig_config = self._get_windows_dns_config(iface)
            self.original_dns_settings.setdefault("interfaces", {})[iface] = orig_config

            cmd = ["netsh", "interface", "ip", "set", "dns", iface, "static", self.listen_host]
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=5,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                )
                if res.returncode == 0:
                    print(f"[DNS] Configured Windows DNS on '{iface}' -> {self.listen_host}")
                else:
                    err_msg = (res.stderr or res.stdout).strip()
                    print(f"[DNS] Notice: netsh set dns on '{iface}' returned: {err_msg}")
            except PermissionError:
                print(f"[DNS] Warning: Administrator elevation required to set DNS on '{iface}'.")
            except Exception as e:
                print(f"[DNS] Error setting DNS on '{iface}': {e}")

    def _restore_windows_dns(self, force_clean_all: bool = False):
        """Restores Windows network interfaces to their pre-proxy DNS configuration."""
        interfaces_data = self.original_dns_settings.get("interfaces", {})

        # If forced or no backup data, scan all active interfaces to clear any residual 127.0.0.1
        if not interfaces_data or force_clean_all:
            for iface in self._get_active_windows_interfaces():
                try:
                    conf = self._get_windows_dns_config(iface)
                    servers = conf.get("servers", [])
                    if any("127.0.0.1" in s or "::1" in s for s in servers) or force_clean_all:
                        subprocess.run(
                            ["netsh", "interface", "ip", "set", "dns", iface, "dhcp"],
                            capture_output=True,
                            timeout=5,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                        )
                        print(f"[DNS] Emergency reset of interface '{iface}' -> DHCP")
                except Exception as e:
                    print(f"[DNS] Error resetting interface '{iface}': {e}")
            if not interfaces_data:
                return

        for iface, original in interfaces_data.items():
            try:
                is_dhcp = original.get("is_dhcp", True)
                servers = original.get("servers", [])
                if is_dhcp:
                    res = subprocess.run(
                        ["netsh", "interface", "ip", "set", "dns", iface, "dhcp"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                    )
                    if res.returncode == 0:
                        print(f"[DNS] Restored Windows DNS on '{iface}' -> DHCP")
                    else:
                        print(f"[DNS] Warning restoring DHCP on '{iface}': {res.stderr.strip()}")
                else:
                    if servers:
                        subprocess.run(
                            ["netsh", "interface", "ip", "set", "dns", iface, "static", servers[0]],
                            capture_output=True,
                            text=True,
                            timeout=5,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                        )
                        for s in servers[1:]:
                            subprocess.run(
                                ["netsh", "interface", "ip", "add", "dns", iface, s],
                                capture_output=True,
                                text=True,
                                timeout=5,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                            )
                        print(f"[DNS] Restored Windows static DNS on '{iface}' -> {servers}")
                    else:
                        subprocess.run(
                            ["netsh", "interface", "ip", "set", "dns", iface, "dhcp"],
                            capture_output=True,
                            text=True,
                            timeout=5,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
                        )
                        print(f"[DNS] Restored Windows DNS on '{iface}' -> DHCP (fallback)")
            except Exception as e:
                print(f"[DNS] Error restoring DNS on '{iface}': {e}")

    def _configure_linux_dns(self):
        """Configures DNS on Linux by updating /etc/resolv.conf and/or using resolvectl."""
        linux_backup: Dict[str, Any] = {
            "resolv_conf": None,
            "is_symlink": False,
            "symlink_target": None,
            "resolvectl_interfaces": []
        }

        # 1. Backup /etc/resolv.conf
        resolv_path = "/etc/resolv.conf"
        if os.path.exists(resolv_path) or os.path.islink(resolv_path):
            try:
                is_link = os.path.islink(resolv_path)
                linux_backup["is_symlink"] = is_link
                if is_link:
                    linux_backup["symlink_target"] = os.readlink(resolv_path)

                if os.path.exists(resolv_path):
                    with open(resolv_path, "r", encoding="utf-8", errors="ignore") as f:
                        linux_backup["resolv_conf"] = f.read()

                try:
                    if linux_backup["resolv_conf"]:
                        with open("/etc/resolv.conf.trackercontrol.bak", "w", encoding="utf-8") as f:
                            f.write(linux_backup["resolv_conf"])
                except Exception:
                    pass

                if is_link:
                    try:
                        os.unlink(resolv_path)
                    except Exception:
                        pass

                new_resolv = (
                    "# Generated by TrackerControl PC DNS Proxy\n"
                    f"nameserver {self.listen_host}\n"
                    "options timeout:2 attempts:3\n"
                )
                with open(resolv_path, "w", encoding="utf-8") as f:
                    f.write(new_resolv)
                print(f"[DNS] Configured /etc/resolv.conf -> {self.listen_host}")
            except PermissionError:
                print("[DNS] Warning: Permission denied writing /etc/resolv.conf (run as root/sudo).")
            except Exception as e:
                print(f"[DNS] Failed to configure /etc/resolv.conf: {e}")

        # 2. Use resolvectl if present (systemd-resolved)
        resolvectl_bin = shutil.which("resolvectl")
        if resolvectl_bin:
            try:
                res = subprocess.run(
                    ["ip", "-o", "link", "show", "up"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.split(":", 2)
                        if len(parts) >= 2:
                            iface = parts[1].strip()
                            if iface and iface != "lo" and not iface.startswith(("docker", "veth", "br-")):
                                set_res = subprocess.run(
                                    [resolvectl_bin, "dns", iface, self.listen_host],
                                    capture_output=True,
                                    text=True,
                                    timeout=5
                                )
                                if set_res.returncode == 0:
                                    linux_backup["resolvectl_interfaces"].append(iface)
                                    print(f"[DNS] Configured resolvectl dns on '{iface}' -> {self.listen_host}")
            except Exception as e:
                print(f"[DNS] Notice: resolvectl configuration error: {e}")

        self.original_dns_settings["linux"] = linux_backup

    def _restore_linux_dns(self):
        """Restores Linux DNS configuration from saved backup."""
        linux_backup = self.original_dns_settings.get("linux", {})

        # 1. Revert resolvectl
        resolvectl_bin = shutil.which("resolvectl")
        if resolvectl_bin:
            for iface in linux_backup.get("resolvectl_interfaces", []):
                try:
                    subprocess.run(
                        [resolvectl_bin, "revert", iface],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    print(f"[DNS] Reverted resolvectl dns on '{iface}'")
                except Exception:
                    pass

        # 2. Restore /etc/resolv.conf
        resolv_path = "/etc/resolv.conf"
        try:
            if linux_backup.get("is_symlink") and linux_backup.get("symlink_target"):
                if os.path.exists(resolv_path) or os.path.islink(resolv_path):
                    os.unlink(resolv_path)
                os.symlink(linux_backup["symlink_target"], resolv_path)
                print(f"[DNS] Restored /etc/resolv.conf symlink -> {linux_backup['symlink_target']}")
            elif linux_backup.get("resolv_conf") is not None:
                with open(resolv_path, "w", encoding="utf-8") as f:
                    f.write(linux_backup["resolv_conf"])
                print("[DNS] Restored original /etc/resolv.conf")
            else:
                backup_path = "/etc/resolv.conf.trackercontrol.bak"
                if os.path.exists(backup_path):
                    shutil.copy2(backup_path, resolv_path)
                    print("[DNS] Restored /etc/resolv.conf from disk backup")
        except PermissionError:
            print("[DNS] Warning: Permission denied restoring /etc/resolv.conf (requires root/sudo).")
        except Exception as e:
            print(f"[DNS] Failed to restore /etc/resolv.conf: {e}")

        # Clean up backup file
        backup_path = "/etc/resolv.conf.trackercontrol.bak"
        if os.path.exists(backup_path):
            try:
                os.unlink(backup_path)
            except Exception:
                pass

    def _get_active_macos_services(self) -> List[str]:
        """Finds all active network services on macOS via networksetup."""
        services = []
        try:
            res = subprocess.run(
                ["networksetup", "-listallnetworkservices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    line_s = line.strip()
                    if not line_s or line_s.startswith("*") or "asterisk" in line_s.lower():
                        continue
                    services.append(line_s)
        except Exception as e:
            print(f"[DNS] Could not list macOS network services: {e}")
        return services

    def _configure_macos_dns(self):
        """Points active macOS network services DNS to 127.0.0.1 via networksetup."""
        services = self._get_active_macos_services()
        if not services:
            print("[DNS] Notice: No active macOS network services detected via networksetup.")
            return

        for s in services:
            try:
                res = subprocess.run(
                    ["networksetup", "-getdnsservers", s],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                orig = {"is_dhcp": True, "servers": []}
                out = res.stdout.strip()
                if "aren't any DNS Servers set" not in out and out:
                    srv_list = [l.strip() for l in out.splitlines() if l.strip() and any(c.isdigit() for c in l)]
                    if srv_list:
                        orig = {"is_dhcp": False, "servers": srv_list}
                self.original_dns_settings.setdefault("macos", {})[s] = orig

                set_res = subprocess.run(
                    ["networksetup", "-setdnsservers", s, self.listen_host],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if set_res.returncode == 0:
                    print(f"[DNS] Configured macOS DNS on '{s}' -> {self.listen_host}")
                else:
                    err_msg = (set_res.stderr or set_res.stdout).strip()
                    print(f"[DNS] Notice: networksetup setdnsservers on '{s}' returned: {err_msg} (Administrator privileges may be required)")
            except Exception as e:
                print(f"[DNS] Error configuring macOS DNS on '{s}': {e}")

        # Flush macOS DNS cache
        try:
            subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, timeout=3)
            subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, timeout=3)
        except Exception:
            pass

    def _restore_macos_dns(self):
        """Restores original macOS network services DNS configuration."""
        macos_backup = self.original_dns_settings.get("macos", {})
        for s, orig in macos_backup.items():
            try:
                if orig.get("is_dhcp"):
                    subprocess.run(
                        ["networksetup", "-setdnsservers", s, "Empty"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    print(f"[DNS] Restored macOS DNS on '{s}' -> DHCP (automatic)")
                else:
                    srvs = orig.get("servers", [])
                    if srvs:
                        subprocess.run(
                            ["networksetup", "-setdnsservers", s] + srvs,
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        print(f"[DNS] Restored macOS static DNS on '{s}' -> {srvs}")
                    else:
                        subprocess.run(
                            ["networksetup", "-setdnsservers", s, "Empty"],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
            except Exception as e:
                print(f"[DNS] Error restoring macOS DNS on '{s}': {e}")

        # Flush macOS DNS cache
        try:
            subprocess.run(["dscacheutil", "-flushcache"], capture_output=True, timeout=3)
            subprocess.run(["killall", "-HUP", "mDNSResponder"], capture_output=True, timeout=3)
        except Exception:
            pass

class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy: DNSProxy):
        self.proxy = proxy
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        # Schedule asynchronous processing of incoming datagram so event loop is never blocked (Bug 1 fix)
        asyncio.create_task(self._process_datagram(data, addr))

    async def _process_datagram(self, data: bytes, addr):
        try:
            response = await self.proxy.handle_dns_query(data, addr)
            if response and self.transport and not self.transport.is_closing():
                self.transport.sendto(response, addr)
        except Exception:
            pass
