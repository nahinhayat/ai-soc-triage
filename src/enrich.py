"""Enrich alerts with network context and threat intelligence.

Uses an offline static intel table so the demo runs with no API keys.
Swapping in live lookups (AbuseIPDB, VirusTotal, MaxMind GeoIP) only
requires replacing the two lookup functions below.
"""
import ipaddress
import json
import os
from typing import Optional

# Generated datasets ship their own intel/geo table (see generate_dataset.py);
# entries there take precedence over the built-in static tables below.
_INTEL_JSON = os.path.join("data", "intel.json")
DYNAMIC_INTEL = {}
if os.path.exists(_INTEL_JSON):
    with open(_INTEL_JSON) as f:
        DYNAMIC_INTEL = json.load(f)

# Static threat-intel table standing in for a live reputation feed.
THREAT_INTEL = {
    "185.220.101.7": {
        "reputation": "malicious",
        "tags": ["tor-exit-node", "ssh-bruteforce"],
        "reports_90d": 412,
    },
    "91.240.118.172": {
        "reputation": "malicious",
        "tags": ["mass-scanner", "ssh-bruteforce"],
        "reports_90d": 1280,
    },
    "203.0.113.45": {
        "reputation": "suspicious",
        "tags": ["recent-bruteforce-reports"],
        "reports_90d": 37,
    },
}

# Coarse geo table standing in for a GeoIP database.
GEO_PREFIXES = {
    "203.0.113.": "RU — Moscow (AS-DOC-NET)",
    "198.51.100.": "CN — Shenzhen (CN-TELECOM)",
    "185.220.101.": "DE — Frankfurt (Tor exit range)",
    "91.240.118.": "RU — St. Petersburg (bulletproof hosting)",
}


# RFC1918 only — ipaddress.is_private also flags documentation ranges
# (203.0.113.0/24 etc.) as private on patched Pythons, which would make
# the sample log's external attackers look internal.
_RFC1918 = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918)


def geo_lookup(ip: str) -> str:
    if is_internal(ip):
        return "internal network (RFC1918)"
    if ip in DYNAMIC_INTEL and DYNAMIC_INTEL[ip].get("geo"):
        return DYNAMIC_INTEL[ip]["geo"]
    for prefix, location in GEO_PREFIXES.items():
        if ip.startswith(prefix):
            return location
    return "unknown"


def intel_lookup(ip: str) -> Optional[dict]:
    if ip in DYNAMIC_INTEL:
        entry = DYNAMIC_INTEL[ip]
        return {k: entry.get(k) for k in ("reputation", "tags", "reports_90d")}
    return THREAT_INTEL.get(ip)


def enrich_alert(alert_summary: dict) -> dict:
    """Attach geo and reputation context to a parsed alert summary."""
    ip = alert_summary["src_ip"]
    intel = intel_lookup(ip)
    alert_summary["enrichment"] = {
        "internal_source": is_internal(ip),
        "geolocation": geo_lookup(ip),
        "threat_intel": intel if intel else {"reputation": "no records", "tags": []},
    }
    return alert_summary
