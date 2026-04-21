"""
OSINT Platform - Report Generator
Transforms raw module outputs into a structured, human-readable investigation report.
Generates: executive summary, IOC list, recommendations, and full technical findings.
"""

import logging
from datetime import datetime
from typing import List, Optional

from schemas import (
    InvestigationReport, RiskLevel, RiskFactor,
    DomainIntelResult, DNSIntelResult, InfrastructureResult,
    ThreatIntelResult, PatternAnalysisResult, SubdomainResult, MLPhishingResult
)

logger = logging.getLogger("osint.report_generator")

# Risk-level color codes and descriptors for report context
RISK_DESCRIPTIONS = {
    RiskLevel.LOW: "The target shows no significant threat indicators. Standard monitoring recommended.",
    RiskLevel.MEDIUM: "The target exhibits moderate risk signals. Further investigation is advised before interaction.",
    RiskLevel.HIGH: "The target shows strong indicators of malicious or suspicious activity. Exercise extreme caution.",
    RiskLevel.CRITICAL: "The target is likely malicious. Do not interact. Block and escalate immediately."
}

RISK_EMOJIS = {
    RiskLevel.LOW: "🟢",
    RiskLevel.MEDIUM: "🟡",
    RiskLevel.HIGH: "🟠",
    RiskLevel.CRITICAL: "🔴"
}


def generate_report(
    scan_id: int,
    url: str,
    domain: str,
    scan_duration_ms: int,
    risk_score: float,
    risk_level: RiskLevel,
    risk_factors: List[RiskFactor],
    domain_intel: Optional[DomainIntelResult],
    dns_intel: Optional[DNSIntelResult],
    infrastructure: Optional[InfrastructureResult],
    threat_intel: Optional[ThreatIntelResult],
    pattern_analysis: Optional[PatternAnalysisResult],
    subdomains: Optional[SubdomainResult],
    ml_analysis: Optional[MLPhishingResult]
) -> InvestigationReport:
    """
    Construct the final InvestigationReport from all module outputs.
    """

    iocs = _extract_iocs(url, domain, dns_intel, threat_intel, pattern_analysis, infrastructure)
    summary = _generate_summary(url, domain, risk_score, risk_level, threat_intel, pattern_analysis, domain_intel)
    recommendations = _generate_recommendations(risk_level, threat_intel, pattern_analysis, domain_intel, infrastructure)

    return InvestigationReport(
        scan_id=scan_id,
        url=url,
        domain=domain,
        scan_timestamp=datetime.utcnow(),
        scan_duration_ms=scan_duration_ms,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_factors=risk_factors,
        domain_intel=domain_intel,
        dns_intel=dns_intel,
        infrastructure=infrastructure,
        threat_intel=threat_intel,
        pattern_analysis=pattern_analysis,
        subdomains=subdomains,
        ml_analysis=ml_analysis,
        summary=summary,
        indicators_of_compromise=iocs,
        recommendations=recommendations
    )


def _generate_summary(
    url: str, domain: str, risk_score: float, risk_level: RiskLevel,
    threat_intel, pattern_analysis, domain_intel
) -> str:
    """Generate a concise executive summary paragraph."""
    emoji = RISK_EMOJIS.get(risk_level, "⚪")
    risk_desc = RISK_DESCRIPTIONS.get(risk_level, "")

    highlights = []

    if threat_intel and threat_intel.is_blacklisted:
        highlights.append(f"domain is present on {len(threat_intel.blacklist_sources)} threat feed(s)")

    if pattern_analysis:
        if pattern_analysis.brand_impersonation:
            highlights.append(f"impersonates the brand '{pattern_analysis.brand_impersonation}'")
        if pattern_analysis.typosquat_target:
            highlights.append(f"appears to typosquat '{pattern_analysis.typosquat_target}'")
        if pattern_analysis.is_high_entropy:
            highlights.append("exhibits high domain entropy consistent with DGA")

    if domain_intel and not domain_intel.error:
        if domain_intel.is_newly_registered:
            highlights.append(f"was registered only {domain_intel.domain_age_days} days ago")

    highlight_text = ""
    if highlights:
        highlight_text = " Notable findings: " + "; ".join(highlights) + "."

    return (
        f"{emoji} Investigation of {domain} returned a Risk Intelligence Score of "
        f"{risk_score:.0f}/100 — classified as {risk_level.value}. "
        f"{risk_desc}{highlight_text}"
    )


def _extract_iocs(
    url, domain, dns_intel, threat_intel, pattern_analysis, infrastructure
) -> List[str]:
    """
    Extract Indicators of Compromise from all module results.
    IOCs are atomic, shareable threat intelligence artifacts.
    """
    iocs = []

    # Always include the primary URL and domain as IOCs
    iocs.append(f"URL: {url}")
    iocs.append(f"Domain: {domain}")

    if dns_intel:
        for ip in dns_intel.a_records:
            iocs.append(f"IP: {ip}")
        if dns_intel.asn:
            iocs.append(f"ASN: {dns_intel.asn} ({dns_intel.asn_org or 'unknown'})")

    if threat_intel and threat_intel.is_blacklisted:
        for source in threat_intel.blacklist_sources:
            iocs.append(f"Blacklist Hit: {source}")

    if infrastructure and infrastructure.ssl_info:
        ssl = infrastructure.ssl_info
        if ssl.subject:
            iocs.append(f"SSL CN: {ssl.subject}")
        if ssl.issuer:
            iocs.append(f"SSL Issuer: {ssl.issuer}")

    if pattern_analysis and pattern_analysis.brand_impersonation:
        iocs.append(f"Brand Impersonation Target: {pattern_analysis.brand_impersonation}")

    return iocs


def _generate_recommendations(
    risk_level, threat_intel, pattern_analysis, domain_intel, infrastructure
) -> List[str]:
    """Generate actionable analyst recommendations based on findings."""
    recs = []

    if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
        recs.append("Immediately block this domain and all resolved IPs at the network perimeter.")
        recs.append("Submit to Google Safe Browsing and VirusTotal for community protection.")
        recs.append("Preserve forensic evidence before the domain expires or infrastructure rotates.")

    if threat_intel and threat_intel.is_blacklisted:
        recs.append("Cross-reference your SIEM logs for access attempts to this domain/IP.")

    if pattern_analysis and pattern_analysis.brand_impersonation:
        recs.append(f"Report brand abuse to {pattern_analysis.brand_impersonation}'s security team (abuse@{pattern_analysis.brand_impersonation}.com).")
        recs.append("File a UDRP complaint if domain squatting is confirmed.")

    if domain_intel and domain_intel.is_newly_registered:
        recs.append("Monitor domain for infrastructure expansion — newly registered phishing domains often spin up additional subdomains within 48h.")

    if infrastructure and infrastructure.ssl_info and not infrastructure.ssl_info.is_valid:
        recs.append("Warn users: this site uses an invalid/expired SSL certificate — do not submit credentials.")

    if risk_level == RiskLevel.MEDIUM:
        recs.append("Schedule a 24-hour follow-up scan — medium-risk domains may escalate rapidly.")
        recs.append("Perform passive traffic analysis if this domain appears in your DNS logs.")

    if risk_level == RiskLevel.LOW:
        recs.append("No immediate action required. Standard monitoring cadence is appropriate.")

    return recs
