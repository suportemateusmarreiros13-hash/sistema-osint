"""
OSINT Platform - Risk Scoring Engine
Weighted aggregation of signals from all OSINT modules into a single Risk Intelligence Score.

Scoring Philosophy:
  - Each module contributes a weighted sub-score
  - Critical signals (blacklist, brand impersonation) carry multipliers
  - Score ranges: LOW 0-30 | MEDIUM 31-60 | HIGH 61-85 | CRITICAL 86-100
  - Scores are additive but capped at 100
"""

import logging
from typing import List, Tuple

from schemas import (
    RiskLevel, RiskFactor, DomainIntelResult, DNSIntelResult,
    InfrastructureResult, ThreatIntelResult, PatternAnalysisResult, MLPhishingResult
)
from config import settings

logger = logging.getLogger("osint.risk_scoring")

# Module weight allocation (should sum to 100)
WEIGHTS = {
    "threat_intel":     35,   # Blacklist/feed hits are the strongest signal
    "pattern_analysis": 25,   # Structural URL analysis
    "domain_intel":     20,   # Domain age and registrar data
    "infrastructure":   10,   # SSL, security headers
    "dns_intel":         5,   # ASN/hosting context
    "ml_analysis":       5,   # ML phishing probability (pluggable)
}


def calculate_risk_score(
    domain_intel: DomainIntelResult | None,
    dns_intel: DNSIntelResult | None,
    infrastructure: InfrastructureResult | None,
    threat_intel: ThreatIntelResult | None,
    pattern_analysis: PatternAnalysisResult | None,
    ml_analysis: MLPhishingResult | None
) -> Tuple[float, RiskLevel, List[RiskFactor]]:
    """
    Calculate the composite Risk Intelligence Score.
    Returns (score_0_to_100, risk_level, list_of_contributing_factors).
    """
    factors: List[RiskFactor] = []
    total_score = 0.0

    # ── Threat Intelligence (weight: 35) ───────────────────────────────────
    if threat_intel and not threat_intel.error:
        ti_score = 0.0

        if threat_intel.is_blacklisted:
            ti_score += 100   # Hard override — blacklisted = critical
            factors.append(RiskFactor(
                category="Threat Intelligence",
                description=f"Domain/URL found on blacklist: {', '.join(threat_intel.blacklist_sources)}",
                weight=WEIGHTS["threat_intel"],
                score_contribution=round(WEIGHTS["threat_intel"] * 1.0, 2)
            ))
        else:
            # Scale threat_score (0-100) to weight contribution
            normalized = min(threat_intel.threat_score / 100.0, 1.0)
            ti_score = normalized * 100

            if threat_intel.phishing_indicators:
                factors.append(RiskFactor(
                    category="Threat Intelligence",
                    description=f"Phishing indicators: {'; '.join(threat_intel.phishing_indicators[:2])}",
                    weight=WEIGHTS["threat_intel"],
                    score_contribution=round(WEIGHTS["threat_intel"] * normalized, 2)
                ))

        contribution = (ti_score / 100.0) * WEIGHTS["threat_intel"]
        total_score += contribution

    # ── Pattern Analysis (weight: 25) ──────────────────────────────────────
    if pattern_analysis:
        pa_score = 0.0
        pa_reasons = []

        if pattern_analysis.brand_impersonation:
            pa_score += 80
            pa_reasons.append(f"Brand impersonation: {pattern_analysis.brand_impersonation}")

        elif pattern_analysis.typosquat_target:
            pa_score += 70
            pa_reasons.append(f"Typosquatting: {pattern_analysis.typosquat_target}")

        if pattern_analysis.is_high_entropy:
            pa_score += 30
            pa_reasons.append(f"High domain entropy ({pattern_analysis.entropy_score:.2f})")

        if pattern_analysis.suspicious_tld:
            pa_score += 25
            pa_reasons.append("Suspicious TLD")

        if pattern_analysis.has_numeric_substitution:
            pa_score += 20
            pa_reasons.append("Numeric character substitution (leet speak)")

        if pattern_analysis.has_excessive_subdomains:
            pa_score += 15
            pa_reasons.append(f"Excessive subdomains ({pattern_analysis.subdomain_count})")

        if pattern_analysis.path_suspicious:
            pa_score += 15
            pa_reasons.append("Suspicious URL path pattern")

        if pattern_analysis.url_length_suspicious:
            pa_score += 10
            pa_reasons.append("Abnormally long URL")

        if len(pattern_analysis.suspicious_keywords) >= 3:
            pa_score += 10
            pa_reasons.append(f"Multiple suspicious keywords: {', '.join(pattern_analysis.suspicious_keywords[:3])}")

        pa_score = min(pa_score, 100)
        contribution = (pa_score / 100.0) * WEIGHTS["pattern_analysis"]
        total_score += contribution

        if pa_reasons:
            factors.append(RiskFactor(
                category="Pattern Analysis",
                description="; ".join(pa_reasons[:3]),
                weight=WEIGHTS["pattern_analysis"],
                score_contribution=round(contribution, 2)
            ))

    # ── Domain Intelligence (weight: 20) ───────────────────────────────────
    if domain_intel and not domain_intel.error:
        di_score = 0.0
        di_reasons = []

        if domain_intel.is_newly_registered:
            di_score += 70
            di_reasons.append(f"Newly registered domain ({domain_intel.domain_age_days} days old)")

        elif domain_intel.domain_age_days and domain_intel.domain_age_days < 365:
            di_score += 30
            di_reasons.append(f"Young domain ({domain_intel.domain_age_days} days old)")

        if domain_intel.privacy_protected:
            di_score += 15
            di_reasons.append("WHOIS privacy protection enabled")

        if domain_intel.registrar and any(
            sus in domain_intel.registrar.lower()
            for sus in ["namecheap", "dynadot", "porkbun"]
        ):
            di_score += 5
            di_reasons.append(f"Registrar associated with high-abuse rate: {domain_intel.registrar}")

        di_score = min(di_score, 100)
        contribution = (di_score / 100.0) * WEIGHTS["domain_intel"]
        total_score += contribution

        if di_reasons:
            factors.append(RiskFactor(
                category="Domain Intelligence",
                description="; ".join(di_reasons),
                weight=WEIGHTS["domain_intel"],
                score_contribution=round(contribution, 2)
            ))

    # ── Infrastructure (weight: 10) ─────────────────────────────────────────
    if infrastructure and not infrastructure.error:
        inf_score = 0.0
        inf_reasons = []

        if infrastructure.ssl_info and not infrastructure.ssl_info.is_valid:
            inf_score += 40
            inf_reasons.append("Invalid or expired SSL certificate")

        missing_headers = [h for h, present in infrastructure.security_headers.items() if not present]
        if len(missing_headers) >= 4:
            inf_score += 20
            inf_reasons.append(f"Missing {len(missing_headers)} security headers")

        if infrastructure.ssl_info and infrastructure.ssl_info.days_until_expiry is not None:
            if infrastructure.ssl_info.days_until_expiry < 7:
                inf_score += 20
                inf_reasons.append("SSL certificate expiring within 7 days")

        inf_score = min(inf_score, 100)
        contribution = (inf_score / 100.0) * WEIGHTS["infrastructure"]
        total_score += contribution

        if inf_reasons:
            factors.append(RiskFactor(
                category="Infrastructure",
                description="; ".join(inf_reasons),
                weight=WEIGHTS["infrastructure"],
                score_contribution=round(contribution, 2)
            ))

    # ── ML Analysis (weight: 5) ─────────────────────────────────────────────
    if ml_analysis:
        ml_contribution = (ml_analysis.phishing_probability / 100.0) * WEIGHTS["ml_analysis"]
        total_score += ml_contribution

        if ml_analysis.phishing_probability > 60:
            factors.append(RiskFactor(
                category="ML Classifier",
                description=f"Phishing probability: {ml_analysis.phishing_probability:.1f}% ({ml_analysis.classification})",
                weight=WEIGHTS["ml_analysis"],
                score_contribution=round(ml_contribution, 2)
            ))

    # ── Final Score & Level ─────────────────────────────────────────────────
    final_score = min(round(total_score, 1), 100.0)

    if final_score <= settings.RISK_LOW_MAX:
        risk_level = RiskLevel.LOW
    elif final_score <= settings.RISK_MEDIUM_MAX:
        risk_level = RiskLevel.MEDIUM
    elif final_score <= settings.RISK_HIGH_MAX:
        risk_level = RiskLevel.HIGH
    else:
        risk_level = RiskLevel.CRITICAL

    logger.info(f"Risk score: {final_score} ({risk_level})")
    return final_score, risk_level, factors
