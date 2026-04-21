"""
OSINT Platform - Pattern Analysis Module
Statistical and structural analysis of the URL itself.
High-entropy domains, typosquatting, numeric substitution, and brand impersonation
are core signals in modern phishing infrastructure detection.
"""

import math
import re
import logging
from typing import List, Optional
from urllib.parse import urlparse

from schemas import PatternAnalysisResult

logger = logging.getLogger("osint.pattern_analysis")

# Suspicious TLDs (consistent with threat_intel for cross-module coherence)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".website", ".space", ".fun", ".icu",
    ".buzz", ".monster", ".work", ".link", ".click", ".win"
}

# Brand keywords that should not appear in third-party domains
BRAND_KEYWORDS = [
    "paypal", "paypai", "amazon", "amazom", "apple", "appleid",
    "microsoft", "micros0ft", "google", "g00gle", "facebook",
    "faceb00k", "netflix", "netfl1x", "instagram", "twitter",
    "linkedin", "bankofamerica", "wellsfargo", "chase", "citibank",
    "icloud", "dropbox", "outlook", "office365"
]

# Common numeric substitutions in phishing domains
LEET_PATTERNS = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "6": "g", "7": "t"
}

# Known path patterns in credential harvesting kits
SUSPICIOUS_PATH_PATTERNS = [
    r'/login', r'/signin', r'/auth', r'/verify', r'/account',
    r'/secure', r'/update', r'/confirm', r'/reset', r'/recover',
    r'/wp-admin', r'/wp-login', r'/admin', r'/panel',
    r'\.php\?', r'token=', r'session=', r'redirect='
]

MAX_SAFE_URL_LENGTH = 100
HIGH_ENTROPY_THRESHOLD = 3.8
MAX_SUBDOMAINS = 3


def analyze_patterns(url: str, domain: str) -> PatternAnalysisResult:
    """
    Statistical and heuristic analysis of URL and domain structure.
    This module works entirely offline — no external calls required.
    """
    logger.info(f"Pattern analysis: {domain}")

    parsed = urlparse(url)
    full_domain = parsed.hostname or domain
    path = parsed.path + ("?" + parsed.query if parsed.query else "")

    # ── Entropy Analysis ────────────────────────────────────────────────────
    # High Shannon entropy = likely random/DGA-generated domain
    entropy_score = _shannon_entropy(domain.replace(".", ""))
    is_high_entropy = entropy_score >= HIGH_ENTROPY_THRESHOLD

    # ── Subdomain Analysis ──────────────────────────────────────────────────
    parts = full_domain.split(".")
    subdomain_count = max(len(parts) - 2, 0)
    has_excessive_subdomains = subdomain_count > MAX_SUBDOMAINS

    # ── Suspicious Keywords ─────────────────────────────────────────────────
    url_lower = url.lower()
    suspicious_keywords = []
    for kw in ["login", "secure", "verify", "account", "banking", "wallet",
                "credential", "update", "suspend", "unusual", "free", "winner"]:
        if kw in url_lower:
            suspicious_keywords.append(kw)

    # ── Brand Impersonation ─────────────────────────────────────────────────
    brand_impersonation = _detect_brand_impersonation(domain)

    # ── Typosquatting Detection ─────────────────────────────────────────────
    typosquat_target = _detect_typosquatting(domain)

    # ── Suspicious TLD ──────────────────────────────────────────────────────
    tld = "." + domain.split(".")[-1] if "." in domain else ""
    suspicious_tld = tld.lower() in SUSPICIOUS_TLDS

    # ── Numeric Substitution ────────────────────────────────────────────────
    has_numeric_substitution = _has_leet_substitution(domain)

    # ── Path Suspicion ──────────────────────────────────────────────────────
    path_suspicious = any(
        re.search(pattern, path, re.IGNORECASE)
        for pattern in SUSPICIOUS_PATH_PATTERNS
    )

    # ── URL Length ──────────────────────────────────────────────────────────
    url_length_suspicious = len(url) > MAX_SAFE_URL_LENGTH

    return PatternAnalysisResult(
        entropy_score=round(entropy_score, 3),
        is_high_entropy=is_high_entropy,
        suspicious_keywords=suspicious_keywords[:5],
        brand_impersonation=brand_impersonation,
        typosquat_target=typosquat_target,
        suspicious_tld=suspicious_tld,
        has_numeric_substitution=has_numeric_substitution,
        has_excessive_subdomains=has_excessive_subdomains,
        subdomain_count=subdomain_count,
        path_suspicious=path_suspicious,
        url_length_suspicious=url_length_suspicious
    )


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _detect_brand_impersonation(domain: str) -> Optional[str]:
    """
    Check if the domain contains a known brand keyword while not being
    the legitimate brand domain. Returns the brand name if found.
    """
    domain_lower = domain.lower()
    # Normalize leet speak before checking
    normalized = _normalize_leet(domain_lower)

    for brand in BRAND_KEYWORDS:
        brand_normalized = _normalize_leet(brand.lower())
        if brand_normalized in normalized:
            # Not a false positive if domain IS the brand
            if domain_lower in (f"{brand}.com", f"www.{brand}.com"):
                continue
            return brand
    return None


def _detect_typosquatting(domain: str) -> Optional[str]:
    """
    Simple Levenshtein-distance based typosquat detection against a set of
    high-value targets. Returns the target domain if within edit distance 2.
    """
    targets = [
        "paypal.com", "amazon.com", "apple.com", "microsoft.com",
        "google.com", "facebook.com", "netflix.com", "instagram.com"
    ]
    domain_lower = domain.lower()

    for target in targets:
        target_base = target.split(".")[0]
        domain_base = domain_lower.split(".")[0]
        if domain_lower == target:
            continue
        dist = _levenshtein(domain_base, target_base)
        if 0 < dist <= 2:
            return target
    return None


def _has_leet_substitution(domain: str) -> bool:
    """Detect common character substitutions (0→o, 1→i, 3→e, etc.)"""
    normalized = _normalize_leet(domain)
    # If normalizing changes the domain, leet substitutions are present
    return normalized != domain.lower()


def _normalize_leet(s: str) -> str:
    """Replace common leet-speak characters with their letter equivalents."""
    result = s.lower()
    for digit, letter in LEET_PATTERNS.items():
        result = result.replace(digit, letter)
    return result


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]
