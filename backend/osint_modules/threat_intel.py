"""
OSINT Platform - Threat Intelligence Module
Cross-references domain and IP against public threat feeds, blacklists, and phishing indicators.
In production, integrate with VirusTotal API, AbuseIPDB, PhishTank, and URLScan.io.
"""

import requests
import hashlib
import logging
from typing import List
from urllib.parse import urlparse

from schemas import ThreatIntelResult
from config import settings

logger = logging.getLogger("osint.threat_intel")

# Phishing-related keywords commonly seen in malicious URLs
PHISHING_KEYWORDS = [
    "login", "signin", "account", "secure", "verify", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "netflix", "google",
    "credential", "password", "wallet", "crypto", "urgent", "suspended",
    "limited", "unusual", "activity", "click", "here", "free", "winner"
]

# Malware distribution patterns
MALWARE_KEYWORDS = [
    "download", "setup", "install", "crack", "keygen", "patch", "loader",
    ".exe", ".bat", ".cmd", ".msi", ".ps1", ".vbs", ".jar"
]

# Suspicious TLDs frequently associated with abuse
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".online",
    ".site", ".website", ".space", ".fun", ".icu", ".buzz", ".monster",
    ".work", ".link", ".click", ".win", ".gdn", ".stream"
}

# Legitimate major brand domains for impersonation detection
MAJOR_BRANDS = {
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "bankofamerica",
    "wellsfargo", "chase", "citibank", "dropbox", "icloud", "outlook"
}


def analyze_threats(url: str, domain: str, ip: str = None) -> ThreatIntelResult:
    """
    Multi-source threat correlation for a URL/domain/IP.
    Aggregates signals from public feeds and local heuristics.
    """
    logger.info(f"Threat intelligence analysis: {domain}")

    is_blacklisted = False
    blacklist_sources: List[str] = []
    phishing_indicators: List[str] = []
    malware_indicators: List[str] = []
    spam_indicators: List[str] = []
    threat_score = 0.0

    url_lower = url.lower()
    domain_lower = domain.lower()

    # ── Heuristic Phishing Signal Detection ────────────────────────────────
    matched_phishing = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if matched_phishing:
        phishing_indicators.extend([f"Phishing keyword in URL: '{kw}'" for kw in matched_phishing[:3]])
        threat_score += min(len(matched_phishing) * 5, 25)

    # ── Malware Keyword Detection ───────────────────────────────────────────
    matched_malware = [kw for kw in MALWARE_KEYWORDS if kw in url_lower]
    if matched_malware:
        malware_indicators.extend([f"Malware keyword: '{kw}'" for kw in matched_malware[:3]])
        threat_score += min(len(matched_malware) * 8, 30)

    # ── Suspicious TLD Check ────────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain_lower.endswith(tld):
            phishing_indicators.append(f"High-risk TLD detected: {tld}")
            threat_score += 15
            break

    # ── Brand Impersonation Check ───────────────────────────────────────────
    for brand in MAJOR_BRANDS:
        if brand in domain_lower and not domain_lower == f"{brand}.com":
            phishing_indicators.append(f"Possible brand impersonation: '{brand}'")
            threat_score += 20
            break

    # ── External Feed Checks (with graceful fallback) ───────────────────────
    # Google Safe Browsing (requires API key in production)
    # Here we simulate the check structure
    gsb_result = _check_google_safe_browsing(url)
    if gsb_result:
        is_blacklisted = True
        blacklist_sources.append("Google Safe Browsing")
        threat_score += 40

    # URLHaus (abuse.ch) - free, no auth required
    urlhaus_result = _check_urlhaus(url, domain)
    if urlhaus_result:
        is_blacklisted = True
        blacklist_sources.append("URLHaus (abuse.ch)")
        threat_score += 35

    # AbuseIPDB check
    if ip:
        abuseipdb_result = _check_abuseipdb(ip)
        if abuseipdb_result:
            spam_indicators.append(f"IP {ip} reported on AbuseIPDB")
            threat_score += 20

    # Cap score at 100
    threat_score = min(threat_score, 100.0)

    if is_blacklisted:
        logger.warning(f"BLACKLISTED domain detected: {domain} | sources: {blacklist_sources}")

    return ThreatIntelResult(
        is_blacklisted=is_blacklisted,
        blacklist_sources=blacklist_sources,
        phishing_indicators=phishing_indicators,
        malware_indicators=malware_indicators,
        spam_indicators=spam_indicators,
        threat_score=threat_score
    )


def _check_google_safe_browsing(url: str) -> bool:
    """
    Check URL against Google Safe Browsing Lookup API.
    Requires GOOGLE_SAFE_BROWSING_API_KEY in environment.
    Returns True if URL is flagged.
    """
    # Production: POST to https://safebrowsing.googleapis.com/v4/threatMatches:find
    # Here we return False as placeholder (no API key)
    return False


def _check_urlhaus(url: str, domain: str) -> bool:
    """
    Query URLHaus (abuse.ch) public API for known malware distribution URLs.
    Free API, no key required. Rate-limited to ~10 req/min.
    """
    try:
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("query_status") == "is_listed"
    except Exception as e:
        logger.debug(f"URLHaus check failed: {e}")
    return False


def _check_abuseipdb(ip: str) -> bool:
    """
    Query AbuseIPDB for IP reputation.
    Requires ABUSEIPDB_API_KEY in production.
    """
    # Production: GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}
    return False
