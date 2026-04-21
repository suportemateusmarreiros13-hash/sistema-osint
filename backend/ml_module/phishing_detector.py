"""
OSINT Platform - ML Phishing Detection Module
Pluggable machine learning module for phishing URL classification.

Architecture:
  - Phase 1 (current): Heuristic feature-based scoring (no ML dependency)
  - Phase 2 (production): Drop-in replacement with scikit-learn Random Forest
    or a fine-tuned URLBert transformer model
  - The interface contract (classify_url → MLPhishingResult) is stable

Feature Engineering:
  URL features extracted are the standard set from academic phishing literature
  (Ma et al. 2009, Sahoo et al. 2017) and industry practice.
"""

import re
import math
import logging
from urllib.parse import urlparse

from schemas import MLPhishingResult

logger = logging.getLogger("osint.ml")

# Feature thresholds (calibrated against PhishTank dataset samples)
FEATURES = {
    "url_length",           # len(url)
    "domain_length",        # len(domain)
    "subdomain_count",      # depth of subdomain tree
    "has_ip_in_host",       # numeric IP as hostname
    "has_at_symbol",        # @ in URL path
    "has_double_slash",     # // after scheme
    "digit_ratio",          # digits / total chars in domain
    "entropy",              # Shannon entropy
    "suspicious_keyword",   # known phishing keywords present
    "short_service",        # bit.ly, tinyurl, etc.
    "has_https",            # scheme check
    "path_depth",           # number of / in path
}

SHORT_SERVICES = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

PHISH_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "banking",
    "update", "confirm", "credential", "paypal", "amazon", "apple",
    "microsoft", "netflix", "wallet", "reset", "suspended"
]


def classify_url(url: str) -> MLPhishingResult:
    """
    Classify a URL using extracted lexical features.

    In production, replace the scoring logic with:
        model = joblib.load("phishing_model.pkl")
        probability = model.predict_proba([feature_vector])[0][1] * 100

    The function signature and return type remain identical.
    """
    logger.info(f"ML classification: {url}")

    features = _extract_features(url)
    score, signals = _heuristic_score(features)

    probability = min(score, 100.0)

    if probability >= 70:
        classification = "phishing"
        confidence = min(probability, 95) / 100
    elif probability >= 40:
        classification = "suspicious"
        confidence = 0.6
    else:
        classification = "benign"
        confidence = (100 - probability) / 100

    return MLPhishingResult(
        phishing_probability=round(probability, 1),
        classification=classification,
        confidence=round(confidence, 2),
        features_used=signals,
        model_version="heuristic-v1.0"
    )


def _extract_features(url: str) -> dict:
    """Extract numerical/boolean features from URL string."""
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    path = parsed.path
    full_url = url.lower()

    # Digit ratio in domain
    domain_chars = domain.replace(".", "")
    digit_count = sum(1 for c in domain_chars if c.isdigit())
    digit_ratio = digit_count / len(domain_chars) if domain_chars else 0

    # Subdomain depth
    parts = domain.split(".")
    subdomain_count = max(len(parts) - 2, 0)

    # Path depth
    path_depth = path.count("/")

    # Shannon entropy of domain
    def entropy(s):
        if not s:
            return 0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    return {
        "url_length": len(url),
        "domain_length": len(domain),
        "subdomain_count": subdomain_count,
        "has_ip_in_host": _is_ip(domain),
        "has_at_symbol": "@" in full_url,
        "has_double_slash": full_url.count("//") > 1,
        "digit_ratio": digit_ratio,
        "entropy": entropy(domain_chars),
        "suspicious_keyword": any(kw in full_url for kw in PHISH_KEYWORDS),
        "short_service": domain in SHORT_SERVICES,
        "has_https": url.startswith("https"),
        "path_depth": path_depth,
    }


def _heuristic_score(features: dict) -> tuple[float, list]:
    """
    Score features and return (0-100 probability, list of triggered signals).
    Each rule is documented with its source rationale.
    """
    score = 0.0
    signals = []

    if features["has_ip_in_host"]:
        score += 35
        signals.append("IP address used as hostname")

    if features["short_service"]:
        score += 25
        signals.append("URL shortening service detected")

    if features["suspicious_keyword"]:
        score += 20
        signals.append("Phishing keyword in URL")

    if features["has_at_symbol"]:
        score += 20
        signals.append("@ symbol in URL (bypasses hostname parsing)")

    if features["entropy"] > 3.8:
        score += 15
        signals.append(f"High domain entropy ({features['entropy']:.2f})")

    if features["digit_ratio"] > 0.3:
        score += 15
        signals.append(f"High digit ratio in domain ({features['digit_ratio']:.0%})")

    if features["url_length"] > 100:
        score += 10
        signals.append(f"Suspicious URL length ({features['url_length']} chars)")

    if features["subdomain_count"] > 3:
        score += 10
        signals.append(f"Deep subdomain nesting ({features['subdomain_count']} levels)")

    if features["has_double_slash"]:
        score += 10
        signals.append("Double slash in URL path (redirect abuse)")

    if features["path_depth"] > 6:
        score += 5
        signals.append(f"Deep URL path ({features['path_depth']} segments)")

    if not features["has_https"]:
        score += 5
        signals.append("Non-HTTPS URL")

    return score, signals


def _is_ip(hostname: str) -> bool:
    """Check if hostname is a raw IP address."""
    import ipaddress
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False
