"""
Desktop Bridge & In-Memory ASGI Dispatcher for TrackerControl PC.
Provides direct in-process JavaScript-to-Python IPC for PyWebView / WebView2,
allowing the desktop GUI to execute API endpoints and receive real-time telemetry
with ZERO localhost port listening and zero network attack surface (GlassWire standard).
"""

import sys
import os
import asyncio
import json
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Callable


class DesktopBridge:
    """
    Exposed as window.pywebview.api in the native desktop GUI window.
    Handles all UI-to-Engine requests in-memory via ASGI.
    """
    def __init__(self, asgi_app, engine_instance):
        self.app = asgi_app
        self.engine = engine_instance
        self.window = None
        self._loop = None

        # Register event listener on engine for real-time telemetry streaming
        if hasattr(self.engine, "add_event_listener"):
            self.engine.add_event_listener(self.on_engine_event)

    def set_window(self, window):
        """Attaches the active PyWebView Window instance."""
        self.window = window

    def _get_loop(self):
        """Returns the active asyncio event loop of the engine."""
        if hasattr(self.engine, "loop") and self.engine.loop and self.engine.loop.is_running():
            return self.engine.loop
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def call_api(self, method: str, path: str, body: Any = None) -> Dict[str, Any]:
        """
        Executes an HTTP/REST endpoint directly in-memory via ASGI.
        Called directly by JavaScript in the native GUI. Never touches a network socket.
        """
        loop = self._get_loop()
        coro = self._call_asgi(method, path, body)
        if loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(coro, loop)
            return fut.result(timeout=15.0)
        else:
            return loop.run_until_complete(coro)

    async def _call_asgi(self, method: str, path: str, body: Any = None) -> Dict[str, Any]:
        method = (method or "GET").upper()
        parsed = urlparse(path)
        clean_path = parsed.path
        if not clean_path.startswith('/'):
            clean_path = '/' + clean_path
        query_string = parsed.query.encode('ascii')

        raw_body = b""
        headers = [
            (b"host", b"trackercontrol.local"),
            (b"x-requested-with", b"TrackerControl"),
            (b"origin", b"null"),
            (b"sec-fetch-site", b"same-origin")
        ]
        if body is not None:
            if isinstance(body, (dict, list)):
                raw_body = json.dumps(body).encode('utf-8')
                headers.append((b"content-type", b"application/json"))
            elif isinstance(body, str):
                raw_body = body.encode('utf-8')
                headers.append((b"content-type", b"text/plain; charset=utf-8"))
            elif isinstance(body, bytes):
                raw_body = body

        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": clean_path,
            "raw_path": clean_path.encode("ascii"),
            "query_string": query_string,
            "headers": headers,
            "server": ("127.0.0.1", 0),
            "client": ("127.0.0.1", 0),
        }

        response_body = []
        response_status = 200
        response_headers = []

        async def receive():
            return {
                "type": "http.request",
                "body": raw_body,
                "more_body": False
            }

        async def send(message):
            nonlocal response_status, response_headers, response_body
            if message["type"] == "http.response.start":
                response_status = message["status"]
                response_headers = message.get("headers", [])
            elif message["type"] == "http.response.body":
                response_body.append(message.get("body", b""))

        try:
            await self.app(scope, receive, send)
        except Exception as e:
            return {
                "status": 500,
                "data": {"success": False, "error": f"Internal in-memory ASGI error: {e}"}
            }

        full_body = b"".join(response_body)
        data = None
        content_type = ""
        for h, v in response_headers:
            if h.lower() == b"content-type":
                content_type = v.decode("latin-1")
                break

        if "application/json" in content_type:
            try:
                data = json.loads(full_body.decode("utf-8"))
            except Exception:
                data = full_body.decode("utf-8", errors="replace")
        else:
            try:
                data = full_body.decode("utf-8")
            except Exception:
                data = str(full_body)

        return {
            "status": response_status,
            "data": data
        }

    def on_engine_event(self, message_dict: Dict[str, Any]):
        """Dispatches an engine telemetry event straight into the native GUI via evaluate_js."""
        if not self.window:
            return
        try:
            payload = json.dumps(message_dict)
            js = f"if (window.__onDesktopEvent) {{ window.__onDesktopEvent({payload}); }}"
            self.window.evaluate_js(js)
        except Exception:
            pass

    def get_initial_state(self) -> Dict[str, Any]:
        """Provides instant telemetry snapshot when the GUI window opens."""
        try:
            stats = self.engine.get_stats()
            return {
                "stats": stats,
                "shield_active": getattr(self.engine, "shield_active", True),
                "protection_mode": getattr(self.engine, "protection_mode", "MAX_PRIVACY"),
                "bandwidth_history": getattr(self.engine, "bandwidth_history", []),
                "recent_connections": getattr(self.engine, "recent_events_cache", []),
                "recent_alerts": getattr(self.engine, "alerts", [])[-20:] if hasattr(self.engine, "alerts") else []
            }
        except Exception as e:
            return {"error": str(e)}

    # Native Windowing Controls for Custom Titlebar / UI
    def minimize_window(self):
        if self.window:
            try:
                self.window.minimize()
            except Exception:
                pass

    def hide_window(self):
        if self.window:
            try:
                self.window.hide()
            except Exception:
                pass

    def show_window(self):
        if self.window:
            try:
                self.window.show()
                self.window.restore()
            except Exception:
                pass
