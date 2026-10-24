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

# Heuristic patterns for detecting novel trackers and advertising networks
TRACKER_KEYWORDS = [
    # Windows OS Telemetry & Diagnostics
    (re.compile(r"(^|\.)(telemetry|diagtrack|vortex|watson)[\.-]", re.I), "Windows Telemetry", "Microsoft Corporation", "High"),
    # General Web & App Analytics
    (re.compile(r"(^|\.)(analytics|analysis|analytic|statcounter|hotjar|crazyegg|fullstory|mouseflow|inspectlet)[\.-]", re.I), "Analytics", "Third-Party Analytics", "Medium"),
    # Performance, Metrics, Health Tracking
    (re.compile(r"(^|\.)(telemetry|metrics|stats|usage|counter|beacon|collector|snoop)[\.-]", re.I), "Telemetry", "App Telemetry", "Medium"),
    # Google Advertising, AdSense & DoubleClick
    (re.compile(r"(^|\.)(doubleclick|adservice|adserver|pagead|googlesyndication|googleadservices|googleads)[\.-]", re.I), "Advertising", "Alphabet Inc.", "High"),
    # Ad Exchanges, Programmatic Ad Networks, Video Ads
    (re.compile(r"(^|\.)(criteo|taboola|outbrain|applovin|unityads|vungle|adcolony|ironsrc|adnxs|pubmatic|rubiconproject|openx|smartadserver|media\.net|triplelift|casalemedia|bidswitch|moatads|serving-sys|doubleverify|flashtalking|zemanta|teads|sovrn|yieldmo|indexexchange|sharethrough|magnite|thetradedesk)[\.-]", re.I), "Advertising", "Ad Exchange", "High"),
    # General Ad Server subdomains & keywords
    (re.compile(r"(^|\.)(ad|ads|adserver|adservice|advert|advertising|banner|banners|popads|propellerads|admob)[\.-]", re.I), "Advertising", "Ad Network", "High"),
    # Mobile Attribution & Cross-App Profilers
    (re.compile(r"(^|\.)(segment|mixpanel|amplitude|branch|appsflyer|adjust|singular|kochava|braze|onesignal|airship|iterable|klaviyo)[\.-]", re.I), "Analytics", "Cross-App Tracking", "High"),
    # Crash Reporting & Diagnostics
    (re.compile(r"(^|\.)(crashlytics|bugsnag|sentry|raygun|rollbar)[\.-]", re.I), "Analytics", "Diagnostics / Crash Reporter", "Low"),
    # Tracking Pixels & Canvas / Device Fingerprinting
    (re.compile(r"(^|\.)(pixel|fingerprint|supercookie|audiencemanager|demdex|scorecardresearch)[\.-]", re.I), "Fingerprinting", "Audience Profiler", "High"),
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

# Whitelisted functional root domains and infrastructure providers.
# These must NEVER be classified as trackers or matched via parent domain wildcards.
EXEMPT_FUNCTIONAL_ROOT_DOMAINS = {
    "google.com",
    "google.co.in",
    "google.co.uk",
    "google.com.au",
    "google.ca",
    "google.de",
    "google.fr",
    "google.co.jp",
    "amazon.com",
    "amazon.in",
    "amazon.co.uk",
    "amazon.de",
    "cloudflare.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "githubusercontent.com",
    "windows.com",
    "live.com",
    "office.com",
    "office365.com",
    "azure.com",
    "netflix.com",
    "spotify.com",
    "wikipedia.org",
    "yahoo.com",
    "bing.com",
    "zendesk.com",
    "vimeo.com",
    "unpkg.com",
    "jsdelivr.net",
    "fastly.net",
    "akamai.net",
    "akamaitechnologies.com"
}

# Critical productivity and functional services that should never be blocked
EXEMPT_FUNCTIONAL_DOMAINS = {
    "docs.google.com",
    "drive.google.com",
    "mail.google.com",
    "calendar.google.com",
    "meet.google.com",
    "accounts.google.com",
    "apis.google.com",
    "play.google.com",
    "cloud.google.com",
    "console.cloud.google.com",
    "clients1.google.com",
    "clients2.google.com",
    "clients3.google.com",
    "clients4.google.com",
    "aws.amazon.com",
    "console.aws.amazon.com",
    "s3.amazonaws.com",
    "api.cloudflare.com",
    "dash.cloudflare.com",
    "portal.azure.com",
    "login.microsoftonline.com",
    "outlook.office.com",
    "outlook.live.com",
    "teams.microsoft.com",
    "login.live.com",
    "raw.githubusercontent.com",
    "api.github.com",
    "registry.npmjs.org",
    "pypi.org"
}

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
                        if domain and domain not in EXEMPT_FUNCTIONAL_ROOT_DOMAINS:
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

        # 0. Immediate Whitelist Exemption for critical functional services & root domains
        if domain in EXEMPT_FUNCTIONAL_DOMAINS or domain in EXEMPT_FUNCTIONAL_ROOT_DOMAINS:
            company = self._resolve_functional_company(domain)
            return {
                "is_tracker": False,
                "category": "Functional",
                "name": domain,
                "company": company,
                "risk": "Clean",
                "rule_matched": "Functional Whitelist Exemption",
                "country": "US",
                "flag": "🇺🇸"
            }

        # 1. Exact match in database
        if domain in self.trackers_map and domain not in EXEMPT_FUNCTIONAL_ROOT_DOMAINS:
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

        # 2. Suffix / Parent domain match (e.g. 'ads.google.com' -> 'adservice.google.com')
        parts = domain.split(".")
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            # NEVER allow parent match on generic infrastructure/company root domains
            if parent in EXEMPT_FUNCTIONAL_ROOT_DOMAINS:
                continue
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

    def _resolve_functional_company(self, domain: str) -> str:
        d = domain.lower()
        if "google" in d:
            return "Alphabet Inc."
        if "amazon" in d or "aws" in d:
            return "Amazon.com Inc."
        if "microsoft" in d or "windows" in d or "live.com" in d or "office" in d or "azure" in d:
            return "Microsoft Corporation"
        if "cloudflare" in d:
            return "Cloudflare Inc."
        if "apple" in d:
            return "Apple Inc."
        if "github" in d:
            return "Microsoft (GitHub)"
        if "spotify" in d:
            return "Spotify AB"
        if "netflix" in d:
            return "Netflix Inc."
        return "Clean / Functional Provider"

