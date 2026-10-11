"""
Tracker Intelligence Engine for TrackerControl PC.
High-speed domain and IP classification engine using:
- 4,500+ Exodus Privacy, Disconnect.me, and WindowsSpyBlocker signatures
- Company & Ownership resolution (Alphabet, Meta, Microsoft, Amazon, ByteDance, etc.)
- Country & Geo-attribution
- Category classification (Advertising, Analytics, Social, Windows Telemetry, Fingerprinting)
"""

import json
import os
import re
from typing import Dict, Any, Optional, Tuple
from .platform_helper import PlatformHelper

DATA_DIR = PlatformHelper.get_data_dir()
TRACKERS_FILE = os.path.join(DATA_DIR, "trackers.json")
COMPANIES_FILE = os.path.join(DATA_DIR, "companies.json")

# Heuristic patterns for detecting novel trackers
TRACKER_KEYWORDS = [
    (re.compile(r"(^|\.)(telemetry|diagtrack|vortex|watson)[\.-]", re.I), "Windows Telemetry", "Microsoft Corporation", "High"),
    (re.compile(r"(^|\.)(analytics|analysis|analytic)[\.-]", re.I), "Analytics", "Third-Party Analytics", "Medium"),
    (re.compile(r"(^|\.)(telemetry|metrics|stats|usage)[\.-]", re.I), "Telemetry", "App Telemetry", "Medium"),
    (re.compile(r"(^|\.)(doubleclick|adservice|adserver|pagead|googlesyndication)[\.-]", re.I), "Advertising", "Alphabet Inc.", "High"),
    (re.compile(r"(^|\.)(pixel|beacon|tracker|tracking|collector|snoop)[\.-]", re.I), "Fingerprinting", "Tracking Network", "High"),
    (re.compile(r"(^|\.)(crashlytics|bugsnag|sentry|raygun)[\.-]", re.I), "Analytics", "Diagnostics / Crash Reporter", "Low"),
    (re.compile(r"(^|\.)(criteo|taboola|outbrain|applovin|unityads|vungle)[\.-]", re.I), "Advertising", "Ad Exchange", "High"),
    (re.compile(r"(^|\.)(segment|mixpanel|amplitude|branch|appsflyer|adjust)[\.-]", re.I), "Analytics", "Cross-App Tracking", "High"),
]

# Offline IP/ASN Corporation mapping for direct IP connections
KNOWN_IP_RANGES = [
    # Google
    (re.compile(r"^(142\.250\.|172\.217\.|216\.58\.|172\.253\.|74\.125\.|108\.177\.|64\.233\.|66\.102\.|66\.249\.)"), "Alphabet Inc.", "US", "🇺🇸"),
    # Microsoft / Azure
    (re.compile(r"^(20\.|40\.|52\.|13\.|104\.40\.|104\.41\.|104\.42\.|104\.43\.|137\.116\.|137\.117\.|138\.91\.|168\.61\.|168\.62\.|168\.63\.)"), "Microsoft Corporation", "US", "🇺🇸"),
    # Meta / Facebook
    (re.compile(r"^(157\.240\.|31\.13\.|69\.171\.|66\.220\.|69\.63\.|179\.60\.|185\.60\.)"), "Meta Platforms Inc.", "US", "🇺🇸"),
    # Amazon AWS
    (re.compile(r"^(54\.|52\.|3\.|18\.|34\.|35\.|99\.84\.|99\.86\.|13\.32\.|13\.33\.|13\.35\.)"), "Amazon Web Services", "US", "🇺🇸"),
    # Cloudflare
    (re.compile(r"^(104\.(1[6-9]|2[0-7])\.|172\.(6[4-9]|7[0-1])\.|162\.15[8-9]\.|198\.41\.|108\.162\.)"), "Cloudflare CDN", "US", "🇺🇸"),
    # Akamai
    (re.compile(r"^(23\.|104\.([0-9]|1[0-5])\.|184\.|92\.122\.|92\.123\.)"), "Akamai Technologies", "US", "🇺🇸"),
]

class TrackerIntelligence:
    def __init__(self):
        self.trackers_map: Dict[str, Dict[str, Any]] = {}
        self.companies_map: Dict[str, Dict[str, Any]] = {}
        self.load_data()

    def load_data(self):
        if os.path.exists(TRACKERS_FILE):
            try:
                with open(TRACKERS_FILE, "r", encoding="utf-8") as f:
                    trackers = json.load(f)
                    for t in trackers:
                        domain = t.get("domain", "").lower().strip()
                        if domain:
                            self.trackers_map[domain] = t
                print(f"[Intelligence] Loaded {len(self.trackers_map)} tracker signatures in memory.")
            except Exception as e:
                print(f"[Intelligence] Error loading trackers.json: {e}")

        if os.path.exists(COMPANIES_FILE):
            try:
                with open(COMPANIES_FILE, "r", encoding="utf-8") as f:
                    self.companies_map = json.load(f)
            except Exception as e:
                print(f"[Intelligence] Error loading companies.json: {e}")

    def inspect_domain(self, domain: str) -> Dict[str, Any]:
        """
        Classifies a domain into tracker category, owner company, risk level, and country flag.
        """
        if not domain:
            return self._unknown_result()

        domain = domain.lower().strip().rstrip(".")

        # 1. Exact match in database
        if domain in self.trackers_map:
            t = self.trackers_map[domain]
            return {
                "is_tracker": True,
                "category": t.get("category", "Analytics"),
                "name": t.get("name", "Known Tracker"),
                "company": t.get("company", "Known Tracking Entity"),
                "risk": t.get("risk", "High"),
                "rule_matched": f"Signature: {domain}",
                "country": "US",
                "flag": "🇺🇸"
            }

        # 2. Suffix / Parent domain match (e.g. 'ads.google.com' -> 'google.com' or 'adservice.google.com')
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if parent in self.trackers_map:
                t = self.trackers_map[parent]
                return {
                    "is_tracker": True,
                    "category": t.get("category", "Analytics"),
                    "name": t.get("name", "Parent Domain Tracker"),
                    "company": t.get("company", "Known Tracking Entity"),
                    "risk": t.get("risk", "High"),
                    "rule_matched": f"Parent Signature: *.{parent}",
                    "country": "US",
                    "flag": "🇺🇸"
                }

        # 3. Known Company Hostname Patterns
        if "microsoft.com" in domain or "windows.com" in domain or "msn.com" in domain:
            if any(term in domain for term in ["telemetry", "events", "v10", "v20", "watson", "diagtrack", "activity", "feedback"]):
                return {
                    "is_tracker": True,
                    "category": "Windows Telemetry",
                    "name": "Windows OS Telemetry",
                    "company": "Microsoft Corporation",
                    "risk": "High",
                    "rule_matched": "Windows Telemetry Heuristic",
                    "country": "US",
                    "flag": "🇺🇸"
                }

        if "discord.gg" in domain or "discordapp.com" in domain:
            if "telemetry" in domain or "science" in domain:
                return {
                    "is_tracker": True,
                    "category": "Telemetry",
                    "name": "Discord Analytics",
                    "company": "Discord Inc.",
                    "risk": "Medium",
                    "rule_matched": "Discord Telemetry Endpoint",
                    "country": "US",
                    "flag": "🇺🇸"
                }

        if "spotify.com" in domain:
            if "telemetry" in domain or "crashdump" in domain or "ad" in domain:
                return {
                    "is_tracker": True,
                    "category": "Advertising",
                    "name": "Spotify Tracking/Ads",
                    "company": "Spotify AB",
                    "risk": "Medium",
                    "rule_matched": "Spotify Tracker Endpoint",
                    "country": "SE",
                    "flag": "🇸🇪"
                }

        # 4. Regex & Keyword Heuristics
        for pattern, category, company, risk in TRACKER_KEYWORDS:
            if pattern.search(domain):
                return {
                    "is_tracker": True,
                    "category": category,
                    "name": f"Suspected {category} ({domain})",
                    "company": company,
                    "risk": risk,
                    "rule_matched": f"Heuristic: {pattern.pattern}",
                    "country": "US",
                    "flag": "🇺🇸"
                }

        # 5. Non-tracker / Functional
        company = "Unknown"
        flag = "🌐"
        country = "Global"

        if "github.com" in domain or "githubusercontent.com" in domain:
            company = "Microsoft (GitHub)"
            country = "US"
            flag = "🇺🇸"
        elif "google.com" in domain or "1e100.net" in domain or "youtube.com" in domain:
            company = "Alphabet Inc."
            country = "US"
            flag = "🇺🇸"
        elif "cloudflare.com" in domain:
            company = "Cloudflare CDN"
            country = "US"
            flag = "🇺🇸"
        elif "wikipedia.org" in domain:
            company = "Wikimedia Foundation"
            country = "US"
            flag = "🇺🇸"

        return {
            "is_tracker": False,
            "category": "Functional",
            "name": domain,
            "company": company,
            "risk": "Clean",
            "rule_matched": "No tracking signature found",
            "country": country,
            "flag": flag
        }

    def inspect_ip(self, ip: str) -> Dict[str, Any]:
        """Classifies direct IP connections using known CIDR/ASN ranges."""
        if not ip or ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
            return {
                "company": "Local Loopback / Intranet",
                "country": "LAN",
                "flag": "🏠",
                "category": "Local Network"
            }

        for pattern, company, country, flag in KNOWN_IP_RANGES:
            if pattern.match(ip):
                return {
                    "company": company,
                    "country": country,
                    "flag": flag,
                    "category": "Cloud / Infrastructure"
                }

        return {
            "company": "Public Internet",
            "country": "Global",
            "flag": "🌐",
            "category": "Infrastructure"
        }

    def _unknown_result(self) -> Dict[str, Any]:
        return {
            "is_tracker": False,
            "category": "Unknown",
            "name": "Unknown Destination",
            "company": "Unknown",
            "risk": "Low",
            "rule_matched": "None",
            "country": "Global",
            "flag": "🌐"
        }
