"""
OSINT Platform - Domain Intelligence Module
Performs WHOIS analysis to extract registrar, age, registrant data, and expiration.
Domain age is one of the strongest single signals for phishing detection.
"""

import whois
import logging
from datetime import datetime
from typing import Optional

from schemas import DomainIntelResult

logger = logging.getLogger("osint.domain_intel")

# Domains registered within this window are flagged as newly registered
NEWLY_REGISTERED_THRESHOLD_DAYS = 90

# Known privacy/proxy registrar strings
PRIVACY_INDICATORS = [
    "privacy", "whoisguard", "domains by proxy", "perfect privacy",
    "contact privacy", "redacted", "data protected", "private registration"
]


def analyze_domain(domain: str) -> DomainIntelResult:
    """
    Execute WHOIS lookup and extract actionable intelligence fields.
    Gracefully handles lookup failures and partial data.
    """
    logger.info(f"Domain intelligence lookup: {domain}")
    try:
        w = whois.whois(domain)

        # Normalize date fields (some WHOIS returns lists)
        creation = _normalize_date(w.creation_date)
        expiration = _normalize_date(w.expiration_date)
        updated = _normalize_date(w.updated_date)

        # Calculate domain age
        domain_age_days = None
        is_newly_registered = False
        if creation:
            delta = datetime.utcnow() - creation
            domain_age_days = delta.days
            is_newly_registered = domain_age_days < NEWLY_REGISTERED_THRESHOLD_DAYS

        # Detect privacy protection
        registrant_str = str(w.get("registrant", "") or "").lower()
        registrar_str = str(w.registrar or "").lower()
        privacy_protected = any(
            kw in registrant_str or kw in registrar_str
            for kw in PRIVACY_INDICATORS
        )

        # Extract country
        country = None
        if hasattr(w, "country"):
            country = w.country
        elif hasattr(w, "registrant_country"):
            country = w.registrant_country

        # Grab first 500 chars of raw WHOIS for report context
        raw_snippet = None
        if hasattr(w, "text") and w.text:
            raw_snippet = w.text[:500].strip()

        result = DomainIntelResult(
            domain=domain,
            registrar=w.registrar,
            creation_date=creation.isoformat() if creation else None,
            expiration_date=expiration.isoformat() if expiration else None,
            updated_date=updated.isoformat() if updated else None,
            domain_age_days=domain_age_days,
            is_newly_registered=is_newly_registered,
            registrant_country=country,
            privacy_protected=privacy_protected,
            raw_whois_snippet=raw_snippet
        )

        if is_newly_registered:
            logger.warning(f"Newly registered domain detected: {domain} ({domain_age_days} days old)")

        return result

    except Exception as e:
        logger.error(f"WHOIS lookup failed for {domain}: {e}")
        return DomainIntelResult(
            domain=domain,
            error=f"WHOIS lookup failed: {str(e)}"
        )


def _normalize_date(date_value) -> Optional[datetime]:
    """Handle WHOIS returning a single date or a list of dates."""
    if date_value is None:
        return None
    if isinstance(date_value, list):
        date_value = date_value[0]
    if isinstance(date_value, datetime):
        return date_value
    # Try string parsing
    for fmt in ["%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%d-%b-%Y"]:
        try:
            return datetime.strptime(str(date_value)[:19], fmt)
        except ValueError:
            continue
    return None
