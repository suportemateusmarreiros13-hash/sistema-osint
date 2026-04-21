"""
OSINT Platform - Pipeline Orchestrator
Coordinates parallel execution of all OSINT modules and feeds results
to the risk scoring engine. This is the central coordinator.
 
Design principle: modules run in parallel where independent, sequentially where
results depend on each other (e.g., DNS before infrastructure for IP validation).
 
FIXES APPLIED:
  - asyncio.get_event_loop() → asyncio.get_running_loop() (Python 3.10+ compat)
  - domain=None guard before Phase 1 (prevents cascade failures)
  - PatternAnalysisResult() default now passes required fields
  - ThreatIntelResult default now passes error field
  - InfrastructureResult default now passes error field
  - Explicit error logging per module in Phase 1
  - Thread pool shared safely across calls
"""
 
import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
 
from schemas import (
    InvestigationReport, RiskLevel,
    DomainIntelResult, DNSIntelResult, InfrastructureResult,
    ThreatIntelResult, PatternAnalysisResult, SubdomainResult, MLPhishingResult
)
from security import extract_domain
from analysis_engine.risk_scoring import calculate_risk_score
from reporting.report_generator import generate_report
from osint_modules.domain_intel import analyze_domain
from osint_modules.dns_intel import analyze_dns
from osint_modules.infrastructure import analyze_infrastructure
from osint_modules.threat_intel import analyze_threats
from osint_modules.pattern_analysis import analyze_patterns
from osint_modules.subdomain_discovery import discover_subdomains
from ml_module.phishing_detector import classify_url
 
logger = logging.getLogger("osint.orchestrator")
 
# Thread pool for blocking I/O — sized for typical OSINT workload
_executor = ThreadPoolExecutor(max_workers=8)
 
 
async def run_investigation(
    scan_id: int,
    url: str,
    deep_scan: bool = False,
    include_ml: bool = True
) -> InvestigationReport:
    """
    Full investigation pipeline.
 
    Phase 1 (parallel): Domain WHOIS + DNS resolution + Pattern analysis + ML
    Phase 2 (parallel, uses Phase 1 IP): Infrastructure probe + Threat intel
    Phase 3 (optional deep scan): Subdomain discovery
    Phase 4: Risk scoring
    Phase 5: Report generation
    """
    start_time = time.time()
 
    # ── Domain extraction guard ─────────────────────────────────────────────
    domain = extract_domain(url)
    if not domain:
        raise ValueError(f"Could not extract a valid domain from URL: {url}")
 
    # FIX: use get_running_loop() — safe inside async context, Python 3.7+
    loop = asyncio.get_running_loop()
 
    logger.info(f"Investigation started | scan_id={scan_id} | url={url} | domain={domain}")
 
    # ── Phase 1: Parallel independent modules ──────────────────────────────
    phase1_tasks = [
        loop.run_in_executor(_executor, analyze_domain, domain),       # index 0
        loop.run_in_executor(_executor, analyze_dns, domain),          # index 1
        loop.run_in_executor(_executor, analyze_patterns, url, domain),# index 2
    ]
    if include_ml:
        phase1_tasks.append(
            loop.run_in_executor(_executor, classify_url, url)         # index 3
        )
 
    logger.info(f"Phase 1 started — {len(phase1_tasks)} parallel tasks")
    phase1_results = await asyncio.gather(*phase1_tasks, return_exceptions=True)
 
    # Log each Phase 1 result individually for easy debugging
    phase1_names = ["DomainIntel", "DNSIntel", "PatternAnalysis", "MLClassifier"]
    for i, result in enumerate(phase1_results):
        name = phase1_names[i] if i < len(phase1_names) else f"Task{i}"
        if isinstance(result, Exception):
            logger.error(f"  ❌ Phase1[{name}] failed: {type(result).__name__}: {result}")
        else:
            logger.info(f"  ✅ Phase1[{name}] OK")
 
    # Extract results with safe fallbacks
    domain_intel: DomainIntelResult = _safe_result(
        phase1_results, 0,
        DomainIntelResult(
            domain=domain,
            registrar=None,
            creation_date=None,
            expiration_date=None,
            updated_date=None,
            domain_age_days=None,
            registrant_country=None,
            raw_whois_snippet=None,
            error="Module failed or timed out"
        )
    )  # type: ignore
    dns_intel: DNSIntelResult = _safe_result(
        phase1_results, 1,
        DNSIntelResult(
            domain=domain,
            primary_ip=None,
            asn=None,
            asn_org=None,
            hosting_provider=None,
            country=None,
            reverse_dns=None,
            error="Module failed or timed out"
        )
    )  # type: ignore
    pattern_analysis: PatternAnalysisResult = _safe_result(
        phase1_results, 2,
        PatternAnalysisResult(
            entropy_score=0.0,
            brand_impersonation=None,
            typosquat_target=None
        )
    )  # type: ignore
    ml_analysis: Optional[MLPhishingResult] = (
        _safe_result(phase1_results, 3, None) if include_ml else None
    )  # type: ignore
 
    # Primary IP from DNS — used by downstream Phase 2 modules
    primary_ip: Optional[str] = (
        dns_intel.primary_ip if dns_intel and not dns_intel.error else None
    )
    logger.info(f"Primary IP resolved: {primary_ip or 'None'}")
 
    # ── Phase 2: Parallel modules that benefit from Phase 1 results ────────
    phase2_tasks = [
        loop.run_in_executor(_executor, analyze_infrastructure, url),              # index 0
        loop.run_in_executor(_executor, analyze_threats, url, domain, primary_ip or ""), # index 1
    ]
 
    logger.info("Phase 2 started — infrastructure + threat intel")
    phase2_results = await asyncio.gather(*phase2_tasks, return_exceptions=True)
 
    phase2_names = ["Infrastructure", "ThreatIntel"]
    for i, result in enumerate(phase2_results):
        name = phase2_names[i] if i < len(phase2_names) else f"Task{i}"
        if isinstance(result, Exception):
            logger.error(f"  ❌ Phase2[{name}] failed: {type(result).__name__}: {result}")
        else:
            logger.info(f"  ✅ Phase2[{name}] OK")
 
    infrastructure: InfrastructureResult = _safe_result(
        phase2_results, 0,
        InfrastructureResult(
            server_header=None,
            powered_by=None,
            http_status=None,
            ssl_info=None,
            content_type=None,
            error="Module failed or timed out"
        )
    )  # type: ignore
    threat_intel: ThreatIntelResult = _safe_result(
        phase2_results, 1,
        ThreatIntelResult(error="Module failed or timed out")
    )  # type: ignore
 
    # ── Phase 3: Optional deep scan (subdomain discovery) ──────────────────
    subdomains: Optional[SubdomainResult] = None
    if deep_scan:
        logger.info(f"Deep scan enabled — subdomain discovery for {domain}")
        try:
            subdomains = await loop.run_in_executor(
                _executor, discover_subdomains, domain
            )
            if subdomains:
                logger.info(f"  ✅ Subdomains found: {subdomains.total_found}")
        except Exception as e:
            logger.error(f"  ❌ Subdomain discovery failed: {type(e).__name__}: {e}")
            subdomains = SubdomainResult(error=str(e))
 
    # ── Phase 4: Risk Scoring ───────────────────────────────────────────────
    logger.info("Phase 4 — risk scoring")
    risk_score, risk_level, risk_factors = calculate_risk_score(
        domain_intel=domain_intel,
        dns_intel=dns_intel,
        infrastructure=infrastructure,
        threat_intel=threat_intel,
        pattern_analysis=pattern_analysis,
        ml_analysis=ml_analysis
    )
 
    scan_duration_ms = int((time.time() - start_time) * 1000)
    logger.info(
        f"Investigation complete | scan_id={scan_id} | "
        f"score={risk_score} | level={risk_level} | duration={scan_duration_ms}ms"
    )
 
    # ── Phase 5: Report Generation ──────────────────────────────────────────
    report = generate_report(
        scan_id=scan_id,
        url=url,
        domain=domain,
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
        ml_analysis=ml_analysis
    )
  
    return report
 
 
def _safe_result(results: list, index: int, default):
    """
    Safely extract a result from asyncio.gather() output.
    Returns default if index is out of bounds or result is an Exception.
    """
    if index >= len(results):
        logger.warning(f"_safe_result: index {index} out of bounds (len={len(results)})")
        return default
    r = results[index]
    if isinstance(r, Exception):
        logger.error(f"_safe_result: index {index} contains exception — using default. Error: {r}")
        return default
    return r
 