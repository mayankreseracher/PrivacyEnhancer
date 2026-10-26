"""
Desktop IPC (Inter-Process Communication) Service for TrackerControl PC.
Provides secure, high-speed single-instance communication via Win32 Named Pipes
on Windows and Unix Domain Sockets on Linux/macOS (GlassWire-Standard Architecture).
Never exposes any open TCP/HTTP port on localhost.
"""

import sys
import os
import threading
import time
from typing import Callable, Optional, Dict, Any
from multiprocessing.connection import Listener, Client

from .platform_helper import PlatformHelper

IS_WINDOWS = sys.platform == "win32"
PIPE_NAME_WIN = r"\\.\pipe\TrackerControlPC_IPC_v1"


def get_ipc_address() -> str:
    """Returns canonical OS-native IPC pipe/socket address."""
    if IS_WINDOWS:
        return PIPE_NAME_WIN
    else:
        data_dir = PlatformHelper.get_data_dir()
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "trackercontrol_ipc.sock")


def get_ipc_family() -> str:
    """Returns address family for multiprocessing.connection ('AF_PIPE' or 'AF_UNIX')."""
    return "AF_PIPE" if IS_WINDOWS else "AF_UNIX"


class DesktopIPCServer:
    """
    Background daemon listener for local single-instance control and wakeup commands.
    Operates completely in-process using OS-level named pipes or domain sockets.
    """
    def __init__(self, message_handler: Callable[[Dict[str, Any]], None]):
        self.message_handler = message_handler
        self._listener: Optional[Listener] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_server, daemon=True, name="DesktopIPCServer")
        self._thread.start()

    def _run_server(self):
        addr = get_ipc_address()
        family = get_ipc_family()

        # Clean up stale Unix domain socket if present
        if not IS_WINDOWS and os.path.exists(addr):
            try:
                os.unlink(addr)
            except Exception:
                pass

        try:
            self._listener = Listener(addr, family)
        except Exception as e:
            print(f"[DesktopIPC] Could not initialize IPC listener on {addr}: {e}")
            self._running = False
            return

        while self._running:
            try:
                conn = self._listener.accept()
                msg = conn.recv()
                try:
                    conn.send({"status": "acknowledged"})
                except Exception:
                    pass
                conn.close()

                if isinstance(msg, dict) and self.message_handler:
                    try:
                        self.message_handler(msg)
                    except Exception as handler_err:
                        print(f"[DesktopIPC] Error handling message: {handler_err}")
            except Exception:
                if not self._running:
                    break
                time.sleep(0.1)

    def stop(self):
        self._running = False
        if self._listener:
            try:
                self._listener.close()
            except Exception:
                pass
            self._listener = None

        if not IS_WINDOWS:
            addr = get_ipc_address()
            if os.path.exists(addr):
                try:
                    os.unlink(addr)
                except Exception:
                    pass


def send_ipc_message(message: Dict[str, Any], timeout: float = 2.0) -> bool:
    """
    Sends a command to the running TrackerControl primary instance via Named Pipe or Domain Socket.
    Returns True if successfully delivered, False otherwise.
    """
    addr = get_ipc_address()
    family = get_ipc_family()

    # Fast check for Unix socket existence
    if not IS_WINDOWS and not os.path.exists(addr):
        return False

    try:
        client = Client(addr, family)
        client.send(message)
        try:
            client.recv()
        except Exception:
            pass
        client.close()
        return True
    except Exception:
        return False
