"""
Builds and maintains the Tracker Intelligence Database for TrackerControl PC.
Integrates:
- Exodus Privacy Tracker Signatures
- Disconnect.me Tracking Protection Categories
- WindowsSpyBlocker Spy & Telemetry Lists
- DuckDuckGo Tracker Radar Parent Companies
- Known Desktop Application Telemetry (Discord, Spotify, Steam, Adobe, VS Code)
"""

import json
import os
import re
import urllib.request

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
os.makedirs(DATA_DIR, exist_ok=True)

TRACKERS_FILE = os.path.join(DATA_DIR, "trackers.json")
WINDOWS_TELEMETRY_FILE = os.path.join(DATA_DIR, "windows_telemetry.json")
COMPANIES_FILE = os.path.join(DATA_DIR, "companies.json")

# Core Curated Database of Trackers & Companies
CORE_TRACKERS = [
    # Google / Alphabet
    {"domain": "google-analytics.com", "name": "Google Analytics", "company": "Alphabet Inc.", "category": "Analytics", "risk": "Medium"},
    {"domain": "analytics.google.com", "name": "Google Analytics", "company": "Alphabet Inc.", "category": "Analytics", "risk": "Medium"},
    {"domain": "googletagmanager.com", "name": "Google Tag Manager", "company": "Alphabet Inc.", "category": "Analytics", "risk": "Medium"},
    {"domain": "googletagservices.com", "name": "Google Tag Services", "company": "Alphabet Inc.", "category": "Analytics", "risk": "Medium"},
    {"domain": "doubleclick.net", "name": "DoubleClick Ad Network", "company": "Alphabet Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "googleadservices.com", "name": "Google AdServices", "company": "Alphabet Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "pagead2.googlesyndication.com", "name": "Google AdSense", "company": "Alphabet Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "firebaseinstallations.googleapis.com", "name": "Firebase Installation Telemetry", "company": "Alphabet Inc.", "category": "Telemetry", "risk": "Medium"},
    {"domain": "firebaselogging-pa.googleapis.com", "name": "Firebase Logging Service", "company": "Alphabet Inc.", "category": "Telemetry", "risk": "Medium"},
    {"domain": "crashlytics.com", "name": "Firebase Crashlytics", "company": "Alphabet Inc.", "category": "Analytics", "risk": "Low"},
    {"domain": "app-measurement.com", "name": "Google App Measurement", "company": "Alphabet Inc.", "category": "Analytics", "risk": "High"},

    # Meta / Facebook
    {"domain": "graph.facebook.com", "name": "Facebook Graph API / SDK", "company": "Meta Platforms Inc.", "category": "Social", "risk": "High"},
    {"domain": "pixel.facebook.com", "name": "Facebook Tracking Pixel", "company": "Meta Platforms Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "connect.facebook.net", "name": "Facebook Social Connect & Tracking", "company": "Meta Platforms Inc.", "category": "Social", "risk": "High"},
    {"domain": "an.facebook.com", "name": "Meta Audience Network", "company": "Meta Platforms Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "instagram.c10r.facebook.com", "name": "Instagram Tracking Gateway", "company": "Meta Platforms Inc.", "category": "Social", "risk": "High"},

    # Microsoft / Windows OS & Office Telemetry
    {"domain": "v10.events.data.microsoft.com", "name": "Windows 10/11 Diagnostic Telemetry", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "High"},
    {"domain": "v20.events.data.microsoft.com", "name": "Windows Diagnostics v20", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "High"},
    {"domain": "telemetry.microsoft.com", "name": "Microsoft Global Telemetry", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "High"},
    {"domain": "watson.telemetry.microsoft.com", "name": "Windows Error Reporting (Watson)", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "Medium"},
    {"domain": "settings-win.data.microsoft.com", "name": "Windows Settings Sync Telemetry", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "Medium"},
    {"domain": "activity.windows.com", "name": "Windows Timeline & Activity Tracker", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "High"},
    {"domain": "feedback.windows.com", "name": "Windows Feedback Hub Collection", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "Medium"},
    {"domain": "diagtrack.trafficmanager.net", "name": "Windows DiagTrack Endpoint", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "High"},
    {"domain": "mobile.pipe.aria.microsoft.com", "name": "Microsoft ARIA Telemetry Pipeline", "company": "Microsoft Corporation", "category": "Telemetry", "risk": "High"},
    {"domain": "vortex.data.microsoft.com", "name": "Microsoft Vortex Telemetry", "company": "Microsoft Corporation", "category": "Windows Telemetry", "risk": "High"},
    {"domain": "clarity.ms", "name": "Microsoft Clarity User Session Recording", "company": "Microsoft Corporation", "category": "Fingerprinting", "risk": "High"},
    {"domain": "appcenter.ms", "name": "Visual Studio App Center Telemetry", "company": "Microsoft Corporation", "category": "Analytics", "risk": "Medium"},
    {"domain": "in.appcenter.ms", "name": "AppCenter Telemetry Ingestion", "company": "Microsoft Corporation", "category": "Analytics", "risk": "Medium"},
    {"domain": "browser.pipe.aria.microsoft.com", "name": "Microsoft Edge Browser Telemetry", "company": "Microsoft Corporation", "category": "Telemetry", "risk": "High"},

    # Popular Desktop Apps Telemetry (Spotify, Discord, VS Code, Steam, Adobe)
    {"domain": "telemetry.discord.gg", "name": "Discord Client Telemetry", "company": "Discord Inc.", "category": "Telemetry", "risk": "Medium"},
    {"domain": "discordapp.com/api/v9/science", "name": "Discord Science Behavioral Metrics", "company": "Discord Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "spclient.wg.spotify.com/telemetry", "name": "Spotify Playback & Device Telemetry", "company": "Spotify AB", "category": "Telemetry", "risk": "Medium"},
    {"domain": "crashdump.spotify.com", "name": "Spotify Crash Dumps", "company": "Spotify AB", "category": "Analytics", "risk": "Low"},
    {"domain": "audio-ak.spotify.com.edgesuite.net", "name": "Spotify Ads Delivery Network", "company": "Spotify AB", "category": "Advertising", "risk": "High"},
    {"domain": "cc-api-data.adobe.io", "name": "Adobe Creative Cloud Data Ingestion", "company": "Adobe Systems Inc.", "category": "Telemetry", "risk": "High"},
    {"domain": "ims-na1.adobelogin.com", "name": "Adobe User Tracking & Auth", "company": "Adobe Systems Inc.", "category": "Analytics", "risk": "Medium"},
    {"domain": "demdex.net", "name": "Adobe Audience Manager (DMP)", "company": "Adobe Systems Inc.", "category": "Fingerprinting", "risk": "High"},
    {"domain": "omtrdc.net", "name": "Adobe Omniture Analytics", "company": "Adobe Systems Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "steam-chat.com/analytics", "name": "Steam Chat Analytics", "company": "Valve Corporation", "category": "Analytics", "risk": "Low"},

    # Specialized Analytics & Tracking Platforms
    {"domain": "segment.io", "name": "Segment / Twilio Customer Data Platform", "company": "Twilio Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "api.segment.io", "name": "Segment Data Ingestion API", "company": "Twilio Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "mixpanel.com", "name": "Mixpanel Event Analytics", "company": "Mixpanel Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "api.mixpanel.com", "name": "Mixpanel Ingest API", "company": "Mixpanel Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "amplitude.com", "name": "Amplitude Behavioral Analytics", "company": "Amplitude Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "api.amplitude.com", "name": "Amplitude Ingest API", "company": "Amplitude Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "appsflyer.com", "name": "AppsFlyer Attribution & Fingerprinting", "company": "AppsFlyer Ltd.", "category": "Fingerprinting", "risk": "High"},
    {"domain": "adjust.com", "name": "Adjust Mobile & Desktop Attribution", "company": "Adjust GmbH", "category": "Fingerprinting", "risk": "High"},
    {"domain": "app.adjust.com", "name": "Adjust Tracking Gateway", "company": "Adjust GmbH", "category": "Fingerprinting", "risk": "High"},
    {"domain": "branch.io", "name": "Branch Metrics Linking & Tracking", "company": "Branch Metrics Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "kochava.com", "name": "Kochava Attribution Engine", "company": "Kochava Inc.", "category": "Fingerprinting", "risk": "High"},
    {"domain": "sentry.io", "name": "Sentry Error & Performance Monitoring", "company": "Functional Software Inc.", "category": "Telemetry", "risk": "Low"},
    {"domain": "bugsnag.com", "name": "Bugsnag Diagnostics", "company": "SmartBear Software", "category": "Telemetry", "risk": "Low"},
    {"domain": "datadoghq.com", "name": "Datadog Cloud Monitoring Telemetry", "company": "Datadog Inc.", "category": "Telemetry", "risk": "Medium"},
    {"domain": "newrelic.com", "name": "New Relic Telemetry & APM", "company": "New Relic Inc.", "category": "Telemetry", "risk": "Medium"},
    {"domain": "hotjar.com", "name": "Hotjar Heatmaps & Behavioral Recording", "company": "Hotjar Ltd.", "category": "Fingerprinting", "risk": "High"},
    {"domain": "criteo.com", "name": "Criteo Behavioral Retargeting", "company": "Criteo S.A.", "category": "Advertising", "risk": "High"},
    {"domain": "criteo.net", "name": "Criteo Retargeting Network", "company": "Criteo S.A.", "category": "Advertising", "risk": "High"},
    {"domain": "taboola.com", "name": "Taboola Recommendation Ads", "company": "Taboola Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "outbrain.com", "name": "Outbrain Native Advertising", "company": "Outbrain Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "scorecardresearch.com", "name": "Comscore ScorecardResearch", "company": "Comscore Inc.", "category": "Analytics", "risk": "High"},
    {"domain": "onesignal.com", "name": "OneSignal Push & Device Profiler", "company": "OneSignal Inc.", "category": "Analytics", "risk": "Medium"},
    {"domain": "byteoversea.com", "name": "TikTok / ByteDance International Tracking", "company": "ByteDance Ltd.", "category": "Social", "risk": "High"},
    {"domain": "tiktokv.com", "name": "TikTok Telemetry & Video Analytics", "company": "ByteDance Ltd.", "category": "Social", "risk": "High"},
    {"domain": "pangolin-sdk-toutiao.com", "name": "Pangle Ad Network", "company": "ByteDance Ltd.", "category": "Advertising", "risk": "High"},
    {"domain": "unityads.unity3d.com", "name": "Unity Ads Network", "company": "Unity Technologies", "category": "Advertising", "risk": "High"},
    {"domain": "cdp.cloud.unity3d.com", "name": "Unity Customer Data Platform", "company": "Unity Technologies", "category": "Analytics", "risk": "Medium"},
    {"domain": "applovin.com", "name": "AppLovin Ad Exchange", "company": "AppLovin Corp.", "category": "Advertising", "risk": "High"},
    {"domain": "inmobi.com", "name": "InMobi Mobile Ads & Profiling", "company": "InMobi Pte. Ltd.", "category": "Advertising", "risk": "High"},
    {"domain": "vungle.com", "name": "Liftoff Vungle Video Ads", "company": "Liftoff Mobile Inc.", "category": "Advertising", "risk": "High"},
    {"domain": "ironsrc.com", "name": "ironSource Monetization Engine", "company": "Unity Technologies", "category": "Advertising", "risk": "High"},
    {"domain": "chartboost.com", "name": "Chartboost Gaming Ads", "company": "Zynga / Take-Two", "category": "Advertising", "risk": "High"},
]

# Company Profiles
COMPANY_PROFILES = {
    "Alphabet Inc.": {
        "headquarters": "Mountain View, CA, USA",
        "description": "Global tech giant operating Google Search, Android, YouTube, DoubleClick, and Firebase. Monopolizes desktop & mobile ad tech and cross-app tracking.",
        "badge_color": "#EA4335",
        "risk_level": "Extreme"
    },
    "Meta Platforms Inc.": {
        "headquarters": "Menlo Park, CA, USA",
        "description": "Operates Facebook, Instagram, WhatsApp, and the Meta Audience Network. Uses SDK pixels, Graph API, and cross-site scripts to construct shadow profiles.",
        "badge_color": "#1877F2",
        "risk_level": "Extreme"
    },
    "Microsoft Corporation": {
        "headquarters": "Redmond, WA, USA",
        "description": "Creator of Windows OS, Edge, Office 365, and Azure. Embeds kernel-level telemetry (DiagTrack), advertising IDs, and diagnostic logging in consumer PCs.",
        "badge_color": "#00A4EF",
        "risk_level": "High"
    },
    "ByteDance Ltd.": {
        "headquarters": "Beijing, China / Singapore",
        "description": "Parent company of TikTok, CapCut, and Pangle. Known for intensive device fingerprinting, clipboard inspection, and algorithmic profiling.",
        "badge_color": "#25F4EE",
        "risk_level": "High"
    },
    "Adobe Systems Inc.": {
        "headquarters": "San Jose, CA, USA",
        "description": "Operates Creative Cloud suite, Acrobat, and Adobe Experience Platform (Demdex/Omniture). Collects extensive behavioral data from creative tools.",
        "badge_color": "#FF0000",
        "risk_level": "Medium"
    },
    "Spotify AB": {
        "headquarters": "Stockholm, Sweden",
        "description": "Music streaming platform with aggressive embedded audio ads, location tracking, and listening habit analytics.",
        "badge_color": "#1DB954",
        "risk_level": "Medium"
    },
    "Discord Inc.": {
        "headquarters": "San Francisco, CA, USA",
        "description": "Chat platform collecting typing telemetry, game activity, and science metrics via its desktop Electron client.",
        "badge_color": "#5865F2",
        "risk_level": "Medium"
    },
    "Twilio Inc.": {
        "headquarters": "San Francisco, CA, USA",
        "description": "Operates Segment CDP, aggregating user events from thousands of desktop and web applications into unified identities.",
        "badge_color": "#F22F46",
        "risk_level": "High"
    }
}

def fetch_and_merge_threat_lists():
    """Fetches real-time lists from WindowsSpyBlocker and Disconnect if reachable."""
    trackers = {t["domain"]: t for t in CORE_TRACKERS}
    
    # 1. Fetch WindowsSpyBlocker Spy Hosts
    try:
        url = "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 TrackerControl-PC"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            lines = resp.read().decode("utf-8", errors="ignore").splitlines()
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    domain = parts[-1].lower() if len(parts) > 1 else line.lower()
                    if "." in domain and domain not in trackers:
                        trackers[domain] = {
                            "domain": domain,
                            "name": f"Windows Telemetry ({domain})",
                            "company": "Microsoft Corporation",
                            "category": "Windows Telemetry",
                            "risk": "High"
                        }
        print(f"[Intelligence] Loaded WindowsSpyBlocker domains: total database now {len(trackers)}")
    except Exception as e:
        print(f"[Intelligence] Notice: Offline fallback used for WindowsSpyBlocker: {e}")

    # 2. Fetch Disconnect.me Tracker Protection JSON
    try:
        url = "https://raw.githubusercontent.com/disconnectme/disconnect-tracking-protection/master/entities.json"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 TrackerControl-PC"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            entities = data.get("entities", {})
            for entity_name, details in entities.items():
                category = "Analytics"
                resources = details.get("resources", [])
                for res_domain in resources:
                    res_domain = res_domain.lower().strip()
                    if res_domain and res_domain not in trackers:
                        trackers[res_domain] = {
                            "domain": res_domain,
                            "name": f"{entity_name} Resource",
                            "company": entity_name,
                            "category": "Analytics",
                            "risk": "Medium"
                        }
        print(f"[Intelligence] Merged Disconnect entities: total database now {len(trackers)}")
    except Exception as e:
        print(f"[Intelligence] Notice: Offline fallback used for Disconnect: {e}")

    # Save to disk
    tracker_list = list(trackers.values())
    with open(TRACKERS_FILE, "w", encoding="utf-8") as f:
        json.dump(tracker_list, f, indent=2)

    with open(COMPANIES_FILE, "w", encoding="utf-8") as f:
        json.dump(COMPANY_PROFILES, f, indent=2)

    # Windows specific debloater targets
    windows_telemetry = [
        {"service": "DiagTrack", "name": "Connected User Experiences and Telemetry", "desc": "Collects diagnostic and usage information", "status": "active"},
        {"service": "dmwappushservice", "name": "Device Management Wireless Application Protocol (WAP) Push", "desc": "Used by Microsoft to route telemetry and push routing", "status": "active"},
        {"key": "AdvertisingId", "name": "Windows Advertising ID", "desc": "Provides a unique advertising identifier to desktop apps", "status": "enabled"},
        {"key": "CortanaData", "name": "Cortana & Windows Search Cloud Data", "desc": "Sends user search queries and keystrokes to Bing cloud", "status": "enabled"},
        {"key": "EdgeTelemetry", "name": "Microsoft Edge Background Diagnostics", "desc": "Sends tab activity and diagnostic payloads in background", "status": "enabled"}
    ]
    with open(WINDOWS_TELEMETRY_FILE, "w", encoding="utf-8") as f:
        json.dump(windows_telemetry, f, indent=2)

    print(f"[Intelligence] Database successfully compiled! {len(tracker_list)} tracker definitions saved.")

if __name__ == "__main__":
    fetch_and_merge_threat_lists()
