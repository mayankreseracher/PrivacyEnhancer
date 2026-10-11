"""
High-Performance Local DNS Interception & Sinkhole Engine for TrackerControl PC.
Intercepts DNS requests, matches against tracker intelligence, and instantly sinkholes
blocked domains to 0.0.0.0 while forwarding valid requests to upstream secure resolvers.
Also maintains an IP -> Domain cache for process socket attribution.
"""

import asyncio
import socket
import time
from typing import Dict, Any, Optional, Callable
from dnslib import DNSRecord, DNSHeader, RR, A, AAAA, QTYPE

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

    def get_domain_for_ip(self, ip: str) -> Optional[str]:
        return self.ip_to_domain_cache.get(ip)

    def handle_dns_query(self, data: bytes, client_addr) -> bytes:
        try:
            request = DNSRecord.parse(data)
            qname = str(request.q.qname).rstrip(".")
            qtype = QTYPE[request.q.qtype]
            
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

            should_block = (is_tracker or custom_block) and not custom_allow

            # If blocked: generate sinkhole response (0.0.0.0 / ::)
            if should_block:
                reply = DNSRecord(
                    DNSHeader(id=request.header.id, qr=1, aa=1, ra=1),
                    q=request.q
                )
                if qtype == "A":
                    reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=300))
                elif qtype == "AAAA":
                    reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=300))

                event = {
                    "timestamp": time.time(),
                    "pid": None,
                    "process_name": "DNS Client",
                    "exe_path": "",
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

            # Otherwise, forward upstream
            upstream_response = self._forward_upstream(data)
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

                # Log allowed query
                event = {
                    "timestamp": time.time(),
                    "pid": None,
                    "process_name": "DNS Client",
                    "exe_path": "",
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

        return self._forward_upstream(data) or b""

    def _forward_upstream(self, data: bytes) -> Optional[bytes]:
        """Forwards standard DNS query over UDP to upstream resolver."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(data, (self.upstream_dns, self.upstream_port))
            resp, _ = sock.recvfrom(4096)
            sock.close()
            return resp
        except Exception:
            return None

class DNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, proxy: DNSProxy):
        self.proxy = proxy

    def datagram_received(self, data: bytes, addr):
        response = self.proxy.handle_dns_query(data, addr)
        if response and self.transport:
            self.transport.sendto(response, addr)

    def connection_made(self, transport):
        self.transport = transport
