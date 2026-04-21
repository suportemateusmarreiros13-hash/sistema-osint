"""
OSINT Platform - Pydantic Schemas
Request/response validation models. These enforce strict typing at the API boundary.
"""

from pydantic import BaseModel, HttpUrl, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ─── Request Models ───────────────────────────────────────────────────────────

class InvestigationRequest(BaseModel):
    url: str
    deep_scan: bool = False        # Enable subdomain discovery (slower)
    include_ml: bool = True        # Run ML phishing classifier

    @validator("url")
    def validate_url_format(cls, v):
        if len(v) > 2048:
            raise ValueError("URL exceeds maximum length")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.strip()


# ─── Module Result Models ─────────────────────────────────────────────────────

class DomainIntelResult(BaseModel):
    domain: str
    registrar: Optional[str]
    creation_date: Optional[str]
    expiration_date: Optional[str]
    updated_date: Optional[str]
    domain_age_days: Optional[int]
    is_newly_registered: bool = False   # <90 days
    registrant_country: Optional[str]
    privacy_protected: bool = False
    raw_whois_snippet: Optional[str]
    error: Optional[str]


class DNSIntelResult(BaseModel):
    domain: str
    a_records: List[str] = []
    mx_records: List[str] = []
    ns_records: List[str] = []
    txt_records: List[str] = []
    primary_ip: Optional[str]
    asn: Optional[str]
    asn_org: Optional[str]
    hosting_provider: Optional[str]
    country: Optional[str]
    reverse_dns: Optional[str]
    error: Optional[str]


class SSLCertInfo(BaseModel):
    subject: Optional[str]
    issuer: Optional[str]
    valid_from: Optional[str]
    valid_until: Optional[str]
    is_valid: bool = False
    days_until_expiry: Optional[int]
    san_domains: List[str] = []


class InfrastructureResult(BaseModel):
    server_header: Optional[str]
    powered_by: Optional[str]
    technologies: List[str] = []
    http_status: Optional[int]
    redirect_chain: List[str] = []
    ssl_info: Optional[SSLCertInfo]
    security_headers: Dict[str, bool] = {}   # header name → present
    content_type: Optional[str]
    error: Optional[str]


class ThreatIntelResult(BaseModel):
    is_blacklisted: bool = False
    blacklist_sources: List[str] = []
    phishing_indicators: List[str] = []
    malware_indicators: List[str] = []
    spam_indicators: List[str] = []
    threat_score: float = 0.0
    error: Optional[str]


class PatternAnalysisResult(BaseModel):
    entropy_score: float = 0.0
    is_high_entropy: bool = False
    suspicious_keywords: List[str] = []
    brand_impersonation: Optional[str]       # e.g. "paypal" if faking PayPal
    typosquat_target: Optional[str]
    suspicious_tld: bool = False
    has_numeric_substitution: bool = False
    has_excessive_subdomains: bool = False
    subdomain_count: int = 0
    path_suspicious: bool = False
    url_length_suspicious: bool = False


class SubdomainResult(BaseModel):
    subdomains: List[str] = []
    total_found: int = 0
    error: Optional[str]


class MLPhishingResult(BaseModel):
    phishing_probability: float = 0.0
    classification: str = "benign"    # benign / suspicious / phishing
    confidence: float = 0.0
    features_used: List[str] = []
    model_version: str = "heuristic-v1"


# ─── Aggregated Report ────────────────────────────────────────────────────────

class RiskFactor(BaseModel):
    category: str
    description: str
    weight: float
    score_contribution: float


class InvestigationReport(BaseModel):
    # Metadata
    scan_id: int
    url: str
    domain: str
    scan_timestamp: datetime
    scan_duration_ms: int

    # Risk
    risk_score: float
    risk_level: RiskLevel
    risk_factors: List[RiskFactor] = []

    # Module results
    domain_intel: Optional[DomainIntelResult]
    dns_intel: Optional[DNSIntelResult]
    infrastructure: Optional[InfrastructureResult]
    threat_intel: Optional[ThreatIntelResult]
    pattern_analysis: Optional[PatternAnalysisResult]
    subdomains: Optional[SubdomainResult]
    ml_analysis: Optional[MLPhishingResult]

    # Summary
    summary: str
    indicators_of_compromise: List[str] = []
    recommendations: List[str] = []


# ─── History / List Responses ─────────────────────────────────────────────────

class ScanSummary(BaseModel):
    id: int
    url: str
    domain: Optional[str]
    risk_score: Optional[float]
    risk_level: Optional[str]
    created_at: datetime
    scan_duration_ms: Optional[int]

    class Config:
        from_attributes = True
