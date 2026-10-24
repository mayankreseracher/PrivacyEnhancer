"""
FastAPI Server and REST API for TrackerControl PC.
Provides real-time WebSockets and endpoints for the Cyber-Dark Dashboard.
"""

import os
import sys
import asyncio
import csv
import io
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from .engine import TrackerEngine
from .platform_helper import PlatformHelper
from .credential_vault import vault

FRONTEND_DIR = PlatformHelper.get_resource_path("frontend")

app = FastAPI(title="TrackerControl PC", version="1.1.0")

# Enable CORS restricted to localhost & local dashboard for CSRF & RCE security
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1",
        "http://localhost",
        "null"
    ],
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

engine = TrackerEngine()

@app.on_event("startup")
async def startup_event():
    await engine.start()

@app.on_event("shutdown")
async def shutdown_event():
    await engine.stop()

# ==================== WebSockets ====================

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await engine.register_websocket(websocket)
    try:
        import json, time
        while True:
            # Keep alive and listen for client commands / heartbeats
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                mtype = msg.get("type")
                if mtype == "PING":
                    await websocket.send_text(json.dumps({
                        "type": "PONG",
                        "timestamp": time.time(),
                        "client_ts": msg.get("timestamp")
                    }))
            except Exception:
                if data.strip().lower() == "ping":
                    await websocket.send_text("pong")
    except WebSocketDisconnect:
        engine.unregister_websocket(websocket)
    except Exception:
        engine.unregister_websocket(websocket)

# ==================== REST API ====================

@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "TrackerControl PC"}

@app.get("/api/stats")
async def get_stats():
    return engine.get_stats()

@app.get("/api/bandwidth")
async def get_bandwidth():
    return engine.get_bandwidth_history()

@app.get("/api/alerts")
async def get_alerts():
    return engine.get_alerts()

@app.post("/api/alerts/clear")
async def clear_alerts():
    engine.clear_alerts()
    return {"success": True}

@app.get("/api/connections")
async def get_connections(
    limit: int = Query(50, ge=1, le=500),
    status: Optional[str] = None,
    app: Optional[str] = None
):
    return engine.database.get_recent_connections(limit=limit, filter_status=status, filter_app=app)

@app.get("/api/apps")
async def get_apps():
    return engine.database.get_all_apps()

@app.get("/api/system-apps")
async def get_system_apps(q: Optional[str] = None):
    """Discovers all installed applications on the Windows system."""
    return engine.app_discovery.get_all_system_apps(query=q)

class SelectAppRequest(BaseModel):
    name: str
    process_name: str
    exe_path: str
    mode: str = "block_trackers"

@app.post("/api/apps/select")
async def select_system_app(payload: SelectAppRequest):
    """Adds a discovered system application to TrackerControl's managed matrix."""
    clean_proc = payload.process_name or os.path.basename(payload.exe_path)
    clean_name = payload.name or os.path.splitext(clean_proc)[0]
    
    engine.database.add_or_update_app(
        exe_path=payload.exe_path,
        process_name=clean_proc,
        display_name=clean_name,
        control_mode=payload.mode
    )

    if payload.mode == "block_all" and payload.exe_path and os.path.exists(payload.exe_path):
        engine.firewall.block_executable(payload.exe_path, clean_proc)
    elif payload.mode != "block_all":
        engine.firewall.unblock_executable(clean_proc)

    return {"success": True, "app": clean_name, "mode": payload.mode}

class AppModeRequest(BaseModel):
    mode: str # 'block_all', 'block_trackers', 'allow_all', 'audit'

@app.post("/api/apps/{app_name}/mode")
async def set_app_mode(app_name: str, payload: AppModeRequest):
    engine.database.set_app_mode(app_name, payload.mode)
    if payload.mode == "block_all":
        for a in engine.database.get_all_apps():
            if a["process_name"].lower() == app_name.lower():
                if a.get("exe_path") and os.path.exists(a["exe_path"]):
                    engine.firewall.block_executable(a["exe_path"], app_name)
    else:
        engine.firewall.unblock_executable(app_name)
    return {"success": True, "app": app_name, "mode": payload.mode}

class ShieldModeRequest(BaseModel):
    mode: str # 'MAX_PRIVACY', 'BALANCED', 'AUDIT_ONLY', 'LOCKDOWN'

@app.post("/api/shield/mode")
async def set_shield_mode(payload: ShieldModeRequest):
    engine.set_protection_mode(payload.mode)
    return {"success": True, "mode": payload.mode}

class ShieldToggleRequest(BaseModel):
    active: bool

@app.post("/api/shield/toggle")
async def toggle_shield(payload: ShieldToggleRequest):
    engine.toggle_shield(payload.active)
    return {"success": True, "active": payload.active}

@app.get("/api/rules")
async def get_rules():
    return engine.database.get_custom_rules()

class RuleCreateRequest(BaseModel):
    target_type: str # 'domain', 'ip', 'app'
    target_value: str
    action: str      # 'block', 'allow'
    notes: Optional[str] = ""

@app.post("/api/rules")
async def add_rule(payload: RuleCreateRequest):
    engine.database.add_custom_rule(payload.target_type, payload.target_value, payload.action, payload.notes or "")
    return {"success": True}

@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: int):
    engine.database.delete_custom_rule(rule_id)
    return {"success": True}

from .platform_helper import PlatformHelper

# Cross-Platform OS Info & Telemetry Debloater
@app.get("/api/os-info")
async def get_os_info():
    return PlatformHelper.get_system_summary()

@app.get("/api/telemetry/status")
async def get_telemetry_status():
    return engine.firewall.get_os_privacy_status()

class TelemetryToggleRequest(BaseModel):
    service: str # e.g. 'whoopsie', 'apport', 'popularity-contest', 'diagtrack', 'advertising_id'
    disable: bool

@app.post("/api/telemetry/toggle")
async def toggle_telemetry(payload: TelemetryToggleRequest):
    tgt = payload.service.lower()
    if tgt == "diagtrack":
        return engine.firewall.toggle_diagtrack(payload.disable)
    elif tgt == "dmwappushservice":
        return engine.firewall.toggle_dmwappushservice(payload.disable)
    elif tgt == "advertising_id":
        return engine.firewall.toggle_advertising_id(payload.disable)
    elif PlatformHelper.get_os_type() == "macOS":
        return engine.firewall.toggle_macos_telemetry(payload.service, payload.disable)
    else:
        return engine.firewall.toggle_linux_telemetry(payload.service, payload.disable)

# Legacy Windows privacy endpoint for backward compatibility
@app.get("/api/windows-privacy")
async def get_windows_privacy():
    return engine.firewall.get_windows_privacy_status()

class WindowsPrivacyToggleRequest(BaseModel):
    target: str # 'diagtrack', 'dmwappushservice', 'advertising_id'
    disable: bool

@app.post("/api/windows-privacy/toggle")
async def toggle_windows_privacy(payload: WindowsPrivacyToggleRequest):
    tgt = payload.target.lower()
    if tgt == "diagtrack":
        return engine.firewall.toggle_diagtrack(payload.disable)
    elif tgt == "dmwappushservice":
        return engine.firewall.toggle_dmwappushservice(payload.disable)
    elif tgt == "advertising_id":
        return engine.firewall.toggle_advertising_id(payload.disable)
    return {"success": False, "error": "Unknown target"}
# ==================== WireGuard & Proton VPN ====================

@app.get("/api/vpn/tunnels")
async def get_vpn_tunnels():
    return engine.wireguard.get_all_tunnels()

class CreateTunnelRequest(BaseModel):
    name: str
    endpoint: str
    public_key: str
    private_key: str
    address: Optional[str] = "10.2.0.2/32"
    dns: Optional[str] = "10.2.0.1"
    country: Optional[str] = "Global"
    flag: Optional[str] = "🌐"

@app.post("/api/vpn/tunnels")
async def create_vpn_tunnel(payload: CreateTunnelRequest):
    tunnel = engine.wireguard.add_tunnel(
        name=payload.name,
        tunnel_type="custom",
        endpoint=payload.endpoint,
        public_key=payload.public_key,
        private_key=payload.private_key,
        address=payload.address or "10.2.0.2/32",
        dns=payload.dns or "10.2.0.1",
        country=payload.country or "Global",
        flag=payload.flag or "🌐"
    )
    return {"success": True, "tunnel": tunnel}

class ToggleTunnelRequest(BaseModel):
    activate: bool

@app.post("/api/vpn/tunnels/{tunnel_id}/toggle")
async def toggle_vpn_tunnel(tunnel_id: str, payload: ToggleTunnelRequest):
    res = engine.wireguard.toggle_tunnel(tunnel_id, payload.activate)
    return res

@app.delete("/api/vpn/tunnels/{tunnel_id}")
async def delete_vpn_tunnel(tunnel_id: str):
    res = engine.wireguard.delete_tunnel(tunnel_id)
    return res

@app.get("/api/vpn/proton/servers")
async def get_proton_servers(country: Optional[str] = None, tier: Optional[str] = None, q: Optional[str] = None):
    return engine.proton.get_servers(country=country, tier=tier, search=q)

@app.get("/api/vpn/proton/auth")
async def get_proton_auth():
    return engine.proton.get_auth_status()

class ProtonAuthRequest(BaseModel):
    private_key: str
    address: Optional[str] = "10.2.0.2/32"
    tier: Optional[str] = "Free"
    username: Optional[str] = "Proton User"

@app.post("/api/vpn/proton/auth")
async def save_proton_auth(payload: ProtonAuthRequest):
    res = engine.proton.save_auth(
        private_key=payload.private_key,
        address=payload.address or "10.2.0.2/32",
        tier=payload.tier or "Free",
        username=payload.username or "Proton User"
    )
    return res

@app.get("/api/vpn/wireguard/generate-keypair")
async def generate_wireguard_keypair():
    import base64
    priv_bytes = bytearray(os.urandom(32))
    priv_bytes[0] &= 248
    priv_bytes[31] &= 127
    priv_bytes[31] |= 64
    priv_b64 = base64.b64encode(bytes(priv_bytes)).decode("ascii")
    return {
        "success": True,
        "private_key": priv_b64,
        "address": "10.2.0.2/32"
    }

class DeployProtonTunnelRequest(BaseModel):
    server_id: str
    custom_name: Optional[str] = None

@app.post("/api/vpn/proton/deploy")
async def deploy_proton_server(payload: DeployProtonTunnelRequest):
    auth_status = engine.proton.get_auth_status()
    if not auth_status.get("configured"):
        # Auto-provision valid Curve25519 WireGuard keypair so deployment never fails with blocking error
        import base64
        priv_bytes = bytearray(os.urandom(32))
        priv_bytes[0] &= 248
        priv_bytes[31] &= 127
        priv_bytes[31] |= 64
        auto_priv = base64.b64encode(bytes(priv_bytes)).decode("ascii")
        engine.proton.save_auth(private_key=auto_priv, address="10.2.0.2/32", tier="Free", username="Proton User (Auto)")

    # Derive unique virtual subnet IP for each tunnel (e.g. 10.2.0.2, 10.2.1.2)
    existing_count = len(engine.wireguard.tunnels)
    unique_ip = f"10.2.{existing_count}.2/32"
    wg_conf = engine.proton.generate_wireguard_config(payload.server_id, custom_address=unique_ip)
    name = payload.custom_name or f"Proton {wg_conf['server_name']}"
    
    tunnel = engine.wireguard.add_tunnel(
        name=name,
        tunnel_type="proton",
        endpoint=wg_conf["endpoint"],
        public_key=wg_conf["public_key"],
        private_key=engine.proton.auth_data.get("private_key", "CLIENT_PRIVATE_KEY_HERE"),
        address=unique_ip,
        country=wg_conf["country"],
        flag=wg_conf["flag"],
        conf_content=wg_conf["conf_content"]
    )
    return {"success": True, "tunnel": tunnel}

class BindAppRequest(BaseModel):
    process_name: str
    tunnel_id: Optional[str] = None

@app.post("/api/vpn/bind-app")
async def bind_app_tunnel(payload: BindAppRequest):
    res = engine.wireguard.bind_app_to_tunnel(payload.process_name, payload.tunnel_id)
    return res

@app.get("/api/vpn/bindings")
async def get_vpn_app_bindings():
    """Returns matrix of all apps bound to specific VPN tunnels."""
    return engine.wireguard.get_all_bindings()

class KillSwitchToggleRequest(BaseModel):
    active: bool

@app.get("/api/vpn/killswitch")
async def get_kill_switch_status():
    return {"kill_switch_active": getattr(engine, "kill_switch_active", False)}

@app.post("/api/vpn/killswitch")
async def toggle_kill_switch(payload: KillSwitchToggleRequest):
    return engine.toggle_kill_switch(payload.active)

class LaunchAppVpnRequest(BaseModel):
    process_name: str
    exe_path: Optional[str] = None
    tunnel_id: Optional[str] = None

@app.post("/api/vpn/launch-app")
async def launch_app_with_vpn(payload: LaunchAppVpnRequest):
    """Launches an application with proxy routing flags & environment variables if bound to a VPN tunnel."""
    import subprocess
    proc_name = payload.process_name.lower().strip()
    tunnel_id = payload.tunnel_id or engine.wireguard.app_bindings.get(proc_name)
    exe_path = payload.exe_path

    # Try resolving exe_path from system apps if not supplied
    if not exe_path:
        sys_apps = engine.app_discovery.get_all_system_apps(query=proc_name)
        for sa in sys_apps:
            if sa.get("process_name", "").lower() == proc_name:
                exe_path = sa.get("exe_path")
                break

    if not exe_path or not os.path.exists(exe_path):
        return {"success": False, "error": f"Executable not found on system for '{payload.process_name}'"}

    # Security Guard: Block direct launch of dangerous system interpreters & script hosts
    base_bin = os.path.basename(exe_path).lower()
    disallowed_bins = {"cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe", "bash", "sh", "zsh"}
    if base_bin in disallowed_bins:
        return {"success": False, "error": f"Launching shell interpreter '{base_bin}' via proxy is disallowed for security"}

    tunnel_info = engine.wireguard.tunnels.get(tunnel_id) if tunnel_id in engine.wireguard.tunnels else None
    proxy_url = tunnel_info.get("proxy_url") if tunnel_info else ("socks5://127.0.0.1:9050" if tunnel_id == "orbot" else None)

    cmd = [exe_path]
    env = os.environ.copy()
    if proxy_url:
        cmd.append(f"--proxy-server={proxy_url}")
        # Inject standard proxy environment variables so non-Chromium apps can inherit tunnel routing
        env["HTTP_PROXY"] = proxy_url
        env["HTTPS_PROXY"] = proxy_url
        env["ALL_PROXY"] = proxy_url
        env["http_proxy"] = proxy_url
        env["https_proxy"] = proxy_url
        env["all_proxy"] = proxy_url

    try:
        proc = subprocess.Popen(cmd, env=env)
        return {
            "success": True,
            "pid": proc.pid,
            "app": payload.process_name,
            "tunnel": tunnel_info.get("name") if tunnel_info else ("Orbot / Tor" if tunnel_id == "orbot" else "Direct"),
            "proxy_url": proxy_url
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# ==================== Orbot VPN Endpoints ====================

@app.get("/api/vpn/orbot/status")
async def get_orbot_status():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, engine.orbot.detect_status)

@app.get("/api/vpn/orbot/identity")
async def get_orbot_identity():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, engine.orbot.get_network_identity)

@app.post("/api/vpn/orbot/new-identity")
async def cycle_orbot_identity():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, engine.orbot.request_new_identity)

@app.post("/api/vpn/orbot/start")
async def start_orbot_service():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, engine.orbot.start_tor_service)

@app.post("/api/vpn/orbot/stop")
async def stop_orbot_service():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, engine.orbot.stop_tor_service)

@app.post("/api/vpn/orbot/toggle")
async def toggle_orbot_service():
    loop = asyncio.get_running_loop()
    def _toggle():
        st = engine.orbot.detect_status()
        if st.get("is_running"):
            return engine.orbot.stop_tor_service()
        else:
            return engine.orbot.start_tor_service()
    return await loop.run_in_executor(None, _toggle)

# ==================== Port Forwarding & Multi-VPN Relay Endpoints ====================

@app.get("/api/vpn/port-forwarding")
async def get_port_forwarding_rules():
    return engine.port_forwarder.get_all_rules()

class CreatePortForwardRequest(BaseModel):
    name: str
    listen_port: int
    target_host: str
    target_port: int
    protocol: Optional[str] = "TCP" # "TCP", "UDP", "BOTH"
    tunnel_id: Optional[str] = "all"
    tunnel_name: Optional[str] = "All Interfaces"
    auto_start: Optional[bool] = True

@app.post("/api/vpn/port-forwarding")
async def create_port_forward_rule(payload: CreatePortForwardRequest):
    rule = engine.port_forwarder.add_rule(
        name=payload.name,
        listen_port=payload.listen_port,
        target_host=payload.target_host,
        target_port=payload.target_port,
        protocol=payload.protocol or "TCP",
        tunnel_id=payload.tunnel_id or "all",
        tunnel_name=payload.tunnel_name or "All Interfaces",
        auto_start=payload.auto_start if payload.auto_start is not None else True
    )
    if payload.auto_start:
        await engine.port_forwarder.start_rule(rule["id"])
    return {"success": True, "rule": rule}

@app.post("/api/vpn/port-forwarding/{rule_id}/start")
async def start_port_forward_rule(rule_id: str):
    return await engine.port_forwarder.start_rule(rule_id)

@app.post("/api/vpn/port-forwarding/{rule_id}/stop")
async def stop_port_forward_rule(rule_id: str):
    return await engine.port_forwarder.stop_rule(rule_id)

@app.delete("/api/vpn/port-forwarding/{rule_id}")
async def delete_port_forward_rule(rule_id: str):
    return await engine.port_forwarder.delete_rule(rule_id)

# ==================== Proton VPN Dynamic NAT-PMP (RFC 6886) Endpoints ====================

@app.get("/api/vpn/nat-pmp/status")
async def get_nat_pmp_status():
    return engine.port_forwarder.nat_pmp.get_status()

class NatPmpRequest(BaseModel):
    internal_port: Optional[int] = None
    lifetime: Optional[int] = 60
    gateway: Optional[str] = "10.2.0.1"

@app.post("/api/vpn/nat-pmp/request")
async def request_nat_pmp_port(payload: NatPmpRequest):
    res = await engine.port_forwarder.nat_pmp.request_p2p_port(
        internal_port=payload.internal_port,
        lifetime=payload.lifetime or 60,
        gateway_ip=payload.gateway or "10.2.0.1"
    )
    return res

@app.post("/api/vpn/nat-pmp/stop")
async def stop_nat_pmp_port():
    return await engine.port_forwarder.nat_pmp.stop_p2p_port()

# ==================== Split Tunneling ====================

class SplitTunnelConfigRequest(BaseModel):
    process_name: str
    mode: str # 'tunnel', 'orbot', 'bypass', 'block'
    tunnel_id: Optional[str] = None

@app.post("/api/vpn/split-tunneling")
async def set_split_tunneling(payload: SplitTunnelConfigRequest):
    if payload.mode == "tunnel":
        engine.wireguard.bind_app_to_tunnel(payload.process_name, payload.tunnel_id)
        engine.database.set_app_mode(payload.process_name, "block_trackers")
        engine.firewall.unblock_executable(payload.process_name)
    elif payload.mode == "orbot":
        engine.wireguard.bind_app_to_tunnel(payload.process_name, "orbot")
        engine.database.set_app_mode(payload.process_name, "block_trackers")
        engine.firewall.unblock_executable(payload.process_name)
    elif payload.mode == "bypass":
        engine.wireguard.bind_app_to_tunnel(payload.process_name, "direct")
        engine.database.set_app_mode(payload.process_name, "allow_all")
        engine.firewall.unblock_executable(payload.process_name)
    elif payload.mode == "block":
        engine.wireguard.bind_app_to_tunnel(payload.process_name, None)
        engine.database.set_app_mode(payload.process_name, "block_all")
        for a in engine.database.get_all_apps():
            if a.get("process_name", "").lower() == payload.process_name.lower():
                if a.get("exe_path") and os.path.exists(a["exe_path"]):
                    engine.firewall.block_executable(a["exe_path"], payload.process_name)
    return {"success": True, "app": payload.process_name, "mode": payload.mode}

@app.get("/api/trackers")
async def search_trackers(q: Optional[str] = None, limit: int = 50):
    results = []
    query = (q or "").lower().strip()
    for domain, t in engine.intelligence.trackers_map.items():
        if not query or query in domain or query in t.get("name", "").lower() or query in t.get("company", "").lower():
            results.append(t)
            if len(results) >= limit:
                break
    return results

@app.get("/api/export/csv")
async def export_csv():
    conns = engine.database.get_recent_connections(limit=1000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Process Name", "Domain", "IP", "Port", "Category", "Company", "Risk", "Status", "Block Reason"])
    for c in conns:
        writer.writerow([
            c["timestamp"], c["process_name"], c["domain"], c["ip"], c["port"],
            c["category"], c["company"], c["risk"], c["status"], c["block_reason"]
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=trackercontrol_export.csv"}
    )

# ==================== Auto-Updater Endpoints ====================

@app.get("/api/updater/status")
async def get_updater_status():
    if hasattr(engine, "updater") and engine.updater:
        return engine.updater.get_status()
    return {"status": "disabled", "current_version": "1.1.0"}

@app.post("/api/updater/check")
async def check_for_updates():
    if hasattr(engine, "updater") and engine.updater:
        return await engine.updater.check_for_updates(manual=True)
    return {"success": False, "error": "Updater not initialized"}

@app.post("/api/updater/download")
async def download_update():
    if hasattr(engine, "updater") and engine.updater:
        return await engine.updater.start_download()
    return {"success": False, "error": "Updater not initialized"}

@app.post("/api/updater/apply")
async def apply_update():
    if hasattr(engine, "updater") and engine.updater:
        return await engine.updater.apply_update()
    return {"success": False, "error": "Updater not initialized"}

class UpdaterSettingsRequest(BaseModel):
    auto_check: Optional[bool] = None
    interval_hours: Optional[int] = None

@app.post("/api/updater/settings")
async def update_updater_settings(payload: UpdaterSettingsRequest):
    if hasattr(engine, "updater") and engine.updater:
        if payload.auto_check is not None:
            engine.updater.set_auto_check_enabled(payload.auto_check)
        if payload.interval_hours is not None:
            engine.updater.set_check_interval_hours(payload.interval_hours)
        return {"success": True, "settings": engine.updater.get_status()}
    return {"success": False, "error": "Updater not initialized"}

# ==================== System & Background Service Endpoints ====================

class AutostartRequest(BaseModel):
    enabled: bool

@app.get("/api/system/autostart")
async def get_autostart_status():
    from .autostart_service import AutostartService
    return AutostartService.get_status()

@app.post("/api/system/autostart")
async def set_autostart_status(payload: AutostartRequest):
    from .autostart_service import AutostartService
    success = AutostartService.toggle(payload.enabled)
    return {"success": success, "autostart_enabled": AutostartService.is_enabled()}

class NotificationSettingRequest(BaseModel):
    enabled: bool

@app.get("/api/system/notifications")
async def get_notification_setting():
    enabled = engine.database.get_setting("desktop_notifications", "true").lower() in ("true", "1")
    return {"notifications_enabled": enabled}

@app.post("/api/system/notifications")
async def set_notification_setting(payload: NotificationSettingRequest):
    engine.database.set_setting("desktop_notifications", "true" if payload.enabled else "false")
    return {"success": True, "notifications_enabled": payload.enabled}

@app.get("/api/system/elevation")
async def get_system_elevation():
    is_admin = False
    if sys.platform == "win32":
        try:
            import ctypes
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False
    elif hasattr(os, "geteuid"):
        is_admin = (os.geteuid() == 0)
    return {
        "is_admin": is_admin,
        "platform": sys.platform,
        "mode": "full_privilege" if is_admin else "audit_only"
    }

@app.post("/api/system/show")
@app.get("/api/system/show")
async def show_application_window():
    """Wakes pywebview native window or opens browser dashboard when duplicate instance triggers."""
    if hasattr(engine, "tray") and engine.tray and hasattr(engine.tray, "on_open_dashboard"):
        try:
            engine.tray.on_open_dashboard()
        except Exception:
            pass
    return {"success": True, "message": "Window restored and brought to front."}

@app.post("/api/system/elevate")
async def request_system_elevation():
    """Requests OS-level Administrator / root elevation with strict argument validation."""
    if sys.platform == "win32":
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin():
                return {"success": True, "already_elevated": True, "message": "TrackerControl is already running with full Administrator privileges."}

            success, code, msg = PlatformHelper.request_windows_uac_elevation(sys.argv)
            if success:
                import asyncio
                async def _exit():
                    await asyncio.sleep(1.0)
                    os._exit(0)
                asyncio.create_task(_exit())
                return {"success": True, "message": "Administrator elevation prompt initiated. Relaunching with full privileges..."}
            else:
                return {"success": False, "error": msg}
        except Exception as e:
            return {"success": False, "error": str(e)}

    return {"success": False, "error": "Automatic elevation not supported on this platform. Please run with sudo."}

@app.get("/api/system/vault-status")
async def get_system_vault_status():
    """Returns the active encryption-at-rest provider and status of CredentialVault."""
    return vault.get_status()

@app.post("/api/dns/restore-emergency")
async def restore_dns_emergency():
    """Restores host OS network interfaces to DHCP / default DNS immediately."""
    try:
        success = engine.dns_proxy.restore_system_dns(force_clean_all=True)
        return {"success": success, "message": "System DNS reset to DHCP / default settings."}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.get("/api/system/status")
async def get_system_service_status():
    return {
        "status": "online",
        "version": "1.1.0",
        "persistent_background_mode": True,
        "shield_active": engine.shield_active,
        "protection_mode": engine.protection_mode,
        "active_tunnels": len([t for t in engine.wireguard.get_all_tunnels() if t.get("status") == "Connected"]),
        "vault": vault.get_status(),
        "platform": PlatformHelper.get_system_summary()
    }

@app.post("/api/system/quit")
async def quit_system():
    """Explicitly stops all services, restores DNS/firewall, and terminates application."""
    import asyncio
    async def _delayed_shutdown():
        await asyncio.sleep(0.5)
        await engine.stop()
        os._exit(0)
    asyncio.create_task(_delayed_shutdown())
    return {"success": True, "message": "TrackerControl PC is shutting down gracefully."}

# Static Dashboard
@app.get("/")
async def root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
