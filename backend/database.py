"""
Database module for TrackerControl PC.
Manages persistent SQLite storage for connection events, monitored apps,
custom firewall/blocking rules, and system privacy settings.
"""

import sqlite3
import os
import time
from typing import Dict, List, Any, Optional
from .platform_helper import PlatformHelper

def get_default_db_path() -> str:
    return os.path.join(PlatformHelper.get_data_dir(), "trackercontrol.db")

class Database:
    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or get_default_db_path()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Connections table: every intercepted or monitored network request
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    pid INTEGER,
                    process_name TEXT,
                    exe_path TEXT,
                    domain TEXT,
                    ip TEXT,
                    port INTEGER,
                    protocol TEXT,
                    category TEXT,
                    company TEXT,
                    risk TEXT,
                    status TEXT, -- 'blocked' or 'allowed'
                    block_reason TEXT,
                    country TEXT,
                    flag TEXT
                )
            """)

            # Apps table: per-application profile, privacy score, and control mode
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS apps (
                    exe_path TEXT PRIMARY KEY,
                    process_name TEXT NOT NULL,
                    display_name TEXT,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    total_requests INTEGER DEFAULT 0,
                    blocked_requests INTEGER DEFAULT 0,
                    trackers_detected INTEGER DEFAULT 0,
                    control_mode TEXT DEFAULT 'block_trackers' -- 'block_all', 'block_trackers', 'allow_all', 'audit'
                )
            """)

            # Custom rules table: User custom whitelist and blacklist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_type TEXT NOT NULL, -- 'domain', 'ip', 'app', 'category'
                    target_value TEXT NOT NULL UNIQUE,
                    action TEXT NOT NULL,      -- 'block', 'allow'
                    notes TEXT,
                    created_at REAL NOT NULL
                )
            """)

            # Settings / Privacy state
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            # Indexes for ultra-fast dashboard queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_ts ON connections(timestamp DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_proc ON connections(process_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_domain ON connections(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_status ON connections(status)")

            conn.commit()

    def log_connection(self, event: Dict[str, Any]):
        """Logs a connection event and updates app metrics."""
        now = time.time()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO connections (
                    timestamp, pid, process_name, exe_path, domain, ip, port,
                    protocol, category, company, risk, status, block_reason, country, flag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.get("timestamp", now),
                event.get("pid"),
                event.get("process_name", "Unknown"),
                event.get("exe_path", ""),
                event.get("domain", ""),
                event.get("ip", ""),
                event.get("port", 0),
                event.get("protocol", "TCP"),
                event.get("category", "Functional"),
                event.get("company", "Unknown"),
                event.get("risk", "Low"),
                event.get("status", "allowed"),
                event.get("block_reason", ""),
                event.get("country", "Unknown"),
                event.get("flag", "🌐")
            ))

            # Upsert app record
            exe_path = event.get("exe_path") or event.get("process_name", "Unknown")
            proc_name = event.get("process_name", "Unknown")
            is_blocked = 1 if event.get("status") == "blocked" else 0
            is_tracker = 1 if event.get("category") not in ["Functional", "CDN/Infrastructure", "Unknown"] else 0

            cursor.execute("""
                INSERT INTO apps (
                    exe_path, process_name, display_name, first_seen, last_seen,
                    total_requests, blocked_requests, trackers_detected
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(exe_path) DO UPDATE SET
                    last_seen = ?,
                    total_requests = total_requests + 1,
                    blocked_requests = blocked_requests + ?,
                    trackers_detected = trackers_detected + ?
            """, (
                exe_path, proc_name, proc_name, now, now,
                is_blocked, is_tracker,
                now, is_blocked, is_tracker
            ))

            conn.commit()

    def get_recent_connections(self, limit: int = 100, filter_status: Optional[str] = None, filter_app: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM connections"
            params = []
            conditions = []

            if filter_status and filter_status != "all":
                conditions.append("status = ?")
                params.append(filter_status)
            if filter_app and filter_app != "all":
                conditions.append("process_name = ?")
                params.append(filter_app)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_all_apps(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM apps ORDER BY total_requests DESC")
            return [dict(row) for row in cursor.fetchall()]

    def set_app_mode(self, exe_path: str, mode: str):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE apps SET control_mode = ? WHERE exe_path = ? OR process_name = ?", (mode, exe_path, exe_path))
            conn.commit()

    def add_or_update_app(self, exe_path: str, process_name: str, display_name: str, control_mode: str = "block_trackers"):
        now = time.time()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO apps (
                    exe_path, process_name, display_name, first_seen, last_seen,
                    total_requests, blocked_requests, trackers_detected, control_mode
                ) VALUES (?, ?, ?, ?, ?, 0, 0, 0, ?)
                ON CONFLICT(exe_path) DO UPDATE SET
                    process_name = excluded.process_name,
                    display_name = excluded.display_name,
                    control_mode = excluded.control_mode
            """, (exe_path, process_name, display_name, now, now, control_mode))
            conn.commit()

    def get_app_mode(self, exe_path: str, process_name: str) -> str:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT control_mode FROM apps WHERE exe_path = ? OR process_name = ?", (exe_path, process_name))
            row = cursor.fetchone()
            if row:
                return row["control_mode"]
            return "block_trackers"

    def get_stats(self) -> Dict[str, Any]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM connections")
            total_conns = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM connections WHERE status = 'blocked'")
            blocked_conns = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(DISTINCT process_name) FROM connections")
            monitored_apps = cursor.fetchone()[0]

            cursor.execute("""
                SELECT company, COUNT(*) as count 
                FROM connections 
                WHERE company != 'Unknown' AND company != 'Generic'
                GROUP BY company 
                ORDER BY count DESC 
                LIMIT 5
            """)
            top_companies = [dict(row) for row in cursor.fetchall()]

            cursor.execute("""
                SELECT category, COUNT(*) as count 
                FROM connections 
                GROUP BY category 
                ORDER BY count DESC
            """)
            category_breakdown = [dict(row) for row in cursor.fetchall()]

            return {
                "total_requests": total_conns,
                "blocked_trackers": blocked_conns,
                "monitored_apps": monitored_apps,
                "top_companies": top_companies,
                "category_breakdown": category_breakdown
            }

    def get_custom_rules(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM custom_rules ORDER BY id DESC")
            return [dict(row) for row in cursor.fetchall()]

    def add_custom_rule(self, target_type: str, target_value: str, action: str, notes: str = ""):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO custom_rules (target_type, target_value, action, notes, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (target_type, target_value.lower().strip(), action, notes, time.time()))
            conn.commit()

    def delete_custom_rule(self, rule_id: int):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
            conn.commit()

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a configuration setting value by key."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
            row = cursor.fetchone()
            if row:
                return row["value"]
            return default

    def set_setting(self, key: str, value: str):
        """Sets or updates a configuration setting value."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """, (key, str(value)))
            conn.commit()
