"""
OSINT Platform - Mock Report Generator for Testing
Provides fallback responses when backend modules fail or are unavailable.
"""

from datetime import datetime
from typing import Optional
from schemas import (
    InvestigationReport, RiskLevel, RiskFactor,
    DomainIntelResult, DNSIntelResult, InfrastructureResult,
    ThreatIntelResult, PatternAnalysisResult, MLPhishingResult
)


def generate_mock_report(
    scan_id: int,
    url: str,
    domain: str,
    error_msg: Optional[str] = None
) -> InvestigationReport:
    """
    Generate a mock investigation report for testing/fallback.
    Used when backend modules fail or are unavailable.
    """
    
    return InvestigationReport(
        scan_id=scan_id,
        url=url,
        domain=domain,
        scan_timestamp=datetime.utcnow(),
        scan_duration_ms=1500,
        risk_score=35.0,
        risk_level=RiskLevel.LOW,
        summary="Mock data - Backend testing mode",
        risk_factors=[
            RiskFactor(
                category="Backend Status",
                description=error_msg or "Backend testing - Mock data",
                weight=1.0,
                score_contribution=0.0
            )
        ],
        domain_intel=DomainIntelResult(
            domain=domain,
            registrar="Mock Registrar",
            creation_date="2020-01-01T00:00:00Z",
            expiration_date="2025-01-01T00:00:00Z",
            updated_date="2023-01-01T00:00:00Z",
            domain_age_days=365,
            is_newly_registered=False,
            registrant_country="US",
            privacy_protected=False,
            raw_whois_snippet="Mock WHOIS data",
            error="Mock data - Backend not fully initialized" if error_msg else None
        ),
        dns_intel=DNSIntelResult(
            domain=domain,
            a_records=["192.168.1.1"],
            mx_records=["mail.example.com"],
            ns_records=["ns1.example.com", "ns2.example.com"],
            txt_records=["v=spf1 -all"],
            primary_ip="192.168.1.1",
            asn="AS12345",
            asn_org="Mock ASN Org",
            hosting_provider="Mock Provider",
            country="US",
            reverse_dns="example.com",
            error="Mock data" if error_msg else None
        ),
        infrastructure=InfrastructureResult(
            server_header="Mock Server/1.0",
            powered_by="Mock Framework",
            technologies=["Mock Tech"],
            http_status=200,
            redirect_chain=[],
            ssl_info=None,
            security_headers={},
            content_type="text/html",
            error="Mock data" if error_msg else None
        ),
        threat_intel=ThreatIntelResult(
            is_blacklisted=False,
            blacklist_sources=[],
            phishing_indicators=[],
            malware_indicators=[],
            spam_indicators=[],
            threat_score=0.0,
            error="Mock data" if error_msg else None
        ),
        pattern_analysis=PatternAnalysisResult(
            entropy_score=0.5,
            is_high_entropy=False,
            suspicious_keywords=[],
            brand_impersonation=None,
            typosquat_target=None,
            suspicious_tld=False,
            has_numeric_substitution=False,
            has_excessive_subdomains=False,
            subdomain_count=0,
            path_suspicious=False,
            url_length_suspicious=False
        ),
        subdomains=None,
        ml_analysis=MLPhishingResult(
            phishing_probability=0.1,
            classification="benign",
            confidence=0.5,
            features_used=[],
            model_version="heuristic-v1"
        ),
        indicators_of_compromise=[],
        recommendations=[]
    )
