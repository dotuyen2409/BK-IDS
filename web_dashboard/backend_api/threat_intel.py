"""
BK-IDS SOC: Threat Intelligence Module
========================================================================
AbuseIPDB + VirusTotal Integration with Mock Data Fallback

API Endpoints:
  GET /threat-intel/lookup?ip=x.x.x.x
  GET /threat-intel/check-block?ip=x.x.x.x&min_score=50

Features:
  - Real AbuseIPDB API calls when key is configured
  - Mock data fallback when key is empty or API fails
  - In-memory cache with 1-hour TTL
  - Auto-escalation for high-risk IPs
"""

import os
import random
import hashlib
import json
import logging
from datetime import datetime, timedelta
from functools import lru_cache

logger = logging.getLogger(__name__)

# ========================================================================
# CONFIGURATION
# ========================================================================
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_URL = "https://www.virustotal.com/api/v3/ip-addresses"

# Cache settings
_cache = {}
CACHE_TTL = 3600  # 1 hour

# Mock data settings
MOCK_MODE = not ABUSEIPDB_API_KEY
if MOCK_MODE:
    logger.warning("[ThreatIntel] ABUSEIPDB_API_KEY not set — running in MOCK MODE")


# ========================================================================
# CACHE HELPERS
# ========================================================================
def _get_cached(ip):
    """Get cached result if not expired."""
    if ip in _cache:
        data, ts = _cache[ip]
        if (datetime.now() - ts).seconds < CACHE_TTL:
            return data
        else:
            del _cache[ip]
    return None


def _set_cache(ip, data):
    """Store result in cache with timestamp."""
    _cache[ip] = (data, datetime.now())


def _clear_cache():
    """Clear all cached data."""
    _cache.clear()


# ========================================================================
# RISK SCORING
# ========================================================================
def _score_to_risk(score):
    """Convert numeric score to risk level."""
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score >= 1:
        return "LOW"
    return "SAFE"


# ========================================================================
# MOCK DATA GENERATOR
# ========================================================================
def _generate_mock_data(ip):
    """
    Generate deterministic mock threat intel data for an IP.
    Uses IP hash so same IP always returns same mock data.
    This allows consistent testing without real API calls.
    """
    # Create deterministic seed from IP
    ip_hash = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
    rng = random.Random(ip_hash)

    # Generate realistic mock data
    score = rng.randint(0, 100)
    countries = ["CN", "RU", "US", "KP", "IR", "BR", "IN", "VN", "DE", "FR", "GB", "JP"]
    isps = [
        "China Telecom", "Rostelecom", "DigitalOcean", "OVH", "AWS",
        "Google Cloud", "Azure", "Alibaba Cloud", "Hetzner", "Linode",
        "Hostinger", "Namecheap", "GoDaddy", "Cloudflare"
    ]
    domains = [
        "proxy-server.net", "vpn-service.com", "hosting-provider.cloud",
        "isp-gateway.net", "cdn-provider.com", "residential-isp.net",
        "datacenter.host", "cloud-server.io"
    ]
    usage_types = [
        "Data Center/Web Hosting/Transit", "Commercial", "Residential",
        "Government", "Military", "Educational/Research", "Mobile ISP"
    ]

    total_reports = rng.randint(0, 500) if score > 10 else rng.randint(0, 5)
    last_reported = "Never"
    if total_reports > 0:
        days_ago = rng.randint(1, 90)
        last_reported = (datetime.now() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S+00:00")

    mock_data = {
        "ip": ip,
        "abuse_confidence_score": score,
        "country": rng.choice(countries),
        "isp": rng.choice(isps),
        "domain": rng.choice(domains),
        "total_reports": total_reports,
        "last_reported": last_reported,
        "usage_type": rng.choice(usage_types),
        "is_whitelisted": score < 5 and rng.random() > 0.7,
        "risk_level": _score_to_risk(score),
        "source": "MOCK_DATA",
        "is_mock": True,
        "checked_at": datetime.now().isoformat(),
        "note": "Mock data — set ABUSEIPDB_API_KEY env var for real data"
    }

    return mock_data


# ========================================================================
# ABUSEIPDB API
# ========================================================================
def check_abuseipdb(ip):
    """
    Query AbuseIPDB for IP reputation.
    Falls back to mock data if API key is missing or request fails.
    """
    # Check cache first
    cached = _get_cached(ip)
    if cached:
        return cached

    # If no API key, return mock data
    if not ABUSEIPDB_API_KEY:
        mock_data = _generate_mock_data(ip)
        _set_cache(ip, mock_data)
        logger.info(f"[ThreatIntel] Mock data for {ip}: score={mock_data['abuse_confidence_score']}, risk={mock_data['risk_level']}")
        return mock_data

    # Real API call
    import requests

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90,
        "verbose": ""
    }

    try:
        resp = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)

        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result = {
                "ip": ip,
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", "Never"),
                "usage_type": data.get("usageType", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "risk_level": _score_to_risk(data.get("abuseConfidenceScore", 0)),
                "source": "AbuseIPDB",
                "is_mock": False,
                "checked_at": datetime.now().isoformat()
            }
            _set_cache(ip, result)
            logger.info(f"[ThreatIntel] AbuseIPDB result for {ip}: score={result['abuse_confidence_score']}")
            return result

        elif resp.status_code == 429:
            logger.warning("[ThreatIntel] AbuseIPDB rate limit — falling back to mock")
            mock_data = _generate_mock_data(ip)
            mock_data["note"] = "Rate limited — mock fallback"
            _set_cache(ip, mock_data)
            return mock_data

        else:
            logger.error(f"[ThreatIntel] AbuseIPDB error {resp.status_code}: {resp.text[:200]}")
            mock_data = _generate_mock_data(ip)
            mock_data["note"] = f"API error {resp.status_code} — mock fallback"
            _set_cache(ip, mock_data)
            return mock_data

    except requests.exceptions.Timeout:
        logger.warning(f"[ThreatIntel] AbuseIPDB timeout for {ip} — mock fallback")
        mock_data = _generate_mock_data(ip)
        mock_data["note"] = "API timeout — mock fallback"
        _set_cache(ip, mock_data)
        return mock_data

    except Exception as e:
        logger.error(f"[ThreatIntel] AbuseIPDB exception: {e} — mock fallback")
        mock_data = _generate_mock_data(ip)
        mock_data["note"] = f"Exception: {str(e)[:50]} — mock fallback"
        _set_cache(ip, mock_data)
        return mock_data


# ========================================================================
# VIRUSTOTAL API (Optional secondary source)
# ========================================================================
def check_virustotal(ip):
    """Query VirusTotal for IP reputation. Optional secondary source."""
    if not VT_API_KEY:
        return None

    import requests

    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(f"{VT_URL}/{ip}", headers=headers, timeout=10)
        if resp.status_code == 200:
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "source": "VirusTotal",
                "checked_at": datetime.now().isoformat()
            }
    except Exception as e:
        logger.warning(f"[ThreatIntel] VirusTotal error for {ip}: {e}")

    return None


# ========================================================================
# ENRICHMENT
# ========================================================================
def enrich_alert_with_threat_intel(alert):
    """
    Enrich a SOC alert with threat intelligence data.
    Auto-escalates severity if IP is high-risk.
    """
    ip = alert.get("ip_src")
    if not ip or ip.startswith(("192.168.", "10.", "172.16.", "127.")):
        alert["threat_intel"] = {
            "ip": ip,
            "risk_level": "INTERNAL",
            "note": "Internal IP — skipped"
        }
        return alert

    intel = check_abuseipdb(ip)
    alert["threat_intel"] = intel

    # Auto-escalate if high risk
    if intel.get("risk_level") in ("CRITICAL", "HIGH"):
        alert["severity"] = "CRITICAL"
        alert["threat_intel_enriched"] = True
        logger.warning(f"[ThreatIntel] Auto-escalated alert for {ip} — risk: {intel['risk_level']}")

    return alert


def enrich_alerts_batch(alerts):
    """Enrich multiple alerts with threat intel."""
    return [enrich_alert_with_threat_intel(a) for a in alerts]


# ========================================================================
# STATS
# ========================================================================
def get_cache_stats():
    """Return cache statistics."""
    return {
        "cached_ips": len(_cache),
        "cache_ttl_seconds": CACHE_TTL,
        "mock_mode": MOCK_MODE,
        "abuseipdb_configured": bool(ABUSEIPDB_API_KEY),
        "virustotal_configured": bool(VT_API_KEY)
    }
