"""
OSINT Platform - FastAPI Main Server
Entry point for the investigation API. Handles routing, middleware,
rate limiting, and database session management.
"""

import json
import logging
import logging.config
from datetime import datetime
from typing import List, Optional
import os

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from config import settings
from database import init_db, get_db, ScanRecord
from schemas import InvestigationRequest, InvestigationReport, ScanSummary
from security import (
    sanitize_url, extract_domain, rate_limiter,
    log_investigation, log_suspicious_activity
)
from analysis_engine.orchestrator import run_investigation
from analysis_engine.mock_generator import generate_mock_report

# ─── Logging Setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(settings.LOG_FILE)
    ]
)
logger = logging.getLogger("osint.main")

# ─── App Initialization ─────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Professional OSINT URL investigation platform for cybersecurity analysts.",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    """Initialize database on startup."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    init_db()
    logger.info("Database initialized")


# ─── Middleware: Rate Limiting ──────────────────────────────────────────────────
@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Apply per-IP rate limiting to all /api/ endpoints."""
    if request.url.path.startswith("/api/investigate"):
        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            log_suspicious_activity("RATE_LIMIT", f"client={client_ip}", client_ip)
            return JSONResponse(
                status_code=429,
                content={"error": "Rate limit exceeded", "retry_after_seconds": retry_after},
                headers={"Retry-After": str(retry_after)}
            )
    return await call_next(request)


# ─── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "platform": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "docs": "/api/docs"
    }


@app.get("/index.html")
async def serve_frontend():
    """Serve the frontend index.html"""
    frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    if os.path.exists(frontend_path):
        return FileResponse(frontend_path, media_type="text/html")
    return {"error": "Frontend not found"}


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.post("/api/test-investigate", response_model=InvestigationReport)
async def test_investigate(request: InvestigationRequest):
    """Test endpoint - returns mock report for debugging"""
    logger.info(f"🧪 Test investigation for: {request.url}")
    
    domain = "example.com"
    report = generate_mock_report(
        scan_id=999,
        url=request.url,
        domain=domain,
        error_msg="Test mode - using mock data"
    )
    
    logger.info(f"✅ Test report generated: {report.risk_level}")
    return report


@app.get("/api/debug/status")
async def debug_status():
    """Debug endpoint - returns server and system status"""
    import sys
    return {
        "server": "online",
        "timestamp": datetime.utcnow().isoformat(),
        "python_version": sys.version,
        "api_base": "http://127.0.0.1:8001",
        "endpoints": {
            "health": "/api/health",
            "investigate": "/api/investigate",
            "test": "/api/test-investigate",
            "docs": "/api/docs"
        },
        "database": "sqlite",
        "modules": {
            "fastapi": "available",
            "sqlalchemy": "available",
            "pydantic": "available"
        }
    }


@app.post("/api/investigate", response_model=InvestigationReport)
async def investigate_url(
    request: InvestigationRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    """
    Main investigation endpoint.
    Accepts a URL, runs the full OSINT pipeline, persists results, and returns the report.
    """
    client_ip = http_request.client.host if http_request.client else "unknown"

    # ── Input Validation ────────────────────────────────────────────────────
    is_valid, clean_url, error_msg = sanitize_url(request.url)
    if not is_valid:
        log_suspicious_activity("INVALID_URL", f"url={request.url}", client_ip)
        raise HTTPException(status_code=400, detail=error_msg)

    domain = extract_domain(clean_url)
    if not domain:
        raise HTTPException(status_code=400, detail="Could not extract domain from URL")

    log_investigation(clean_url, client_ip)

    # ── Create DB record (pending) ──────────────────────────────────────────
    scan_record = ScanRecord(
        url=clean_url,
        domain=domain,
        requester_ip=client_ip
    )
    db.add(scan_record)
    db.commit()
    db.refresh(scan_record)
    scan_id: int = scan_record.id  # type: ignore
    
    # ── Run Investigation Pipeline ──────────────────────────────────────────
    try:
        logger.info(f"Running investigation for: {clean_url}")
        report = await run_investigation(
            scan_id=scan_id,
            url=clean_url,
            deep_scan=request.deep_scan,
            include_ml=request.include_ml
        )
        logger.info(f"Investigation completed successfully for: {clean_url}")
    except Exception as e:
        logger.error(f"❌ Investigation pipeline error for {clean_url}: {e}", exc_info=True)
        error_msg = str(e) if str(e) else "Investigation failed"
        
        # Fallback: Return mock report for testing
        logger.warning(f"⚠️  Using mock report due to error: {error_msg}")
        report = generate_mock_report(
            scan_id=scan_id,
            url=clean_url,
            domain=domain,
            error_msg=f"Backend error: {error_msg}"
        )
        
        # Still log the error in database
        scan_record.error = error_msg  # type: ignore
        db.commit()

    # ── Persist Results ─────────────────────────────────────────────────────
    try:
        scan_record.risk_score = float(report.risk_score)  # type: ignore
        scan_record.risk_level = str(report.risk_level.value)  # type: ignore
        scan_record.scan_duration_ms = int(report.scan_duration_ms)  # type: ignore
        scan_record.ip_address = report.dns_intel.primary_ip if report.dns_intel and report.dns_intel.primary_ip else None  # type: ignore
        scan_record.is_blacklisted = bool(report.threat_intel.is_blacklisted) if report.threat_intel else False  # type: ignore
        scan_record.has_ssl = (  # type: ignore
            bool(report.infrastructure.ssl_info.is_valid)
            if report.infrastructure and report.infrastructure.ssl_info else False
        )
        scan_record.domain_age_days = (  # type: ignore
            int(report.domain_intel.domain_age_days) if report.domain_intel and report.domain_intel.domain_age_days else None
        )
        scan_record.is_newly_registered = (  # type: ignore
            bool(report.domain_intel.is_newly_registered) if report.domain_intel else False
        )
        scan_record.report_json = str(report.model_dump_json())  # type: ignore
        db.commit()
    except Exception as e:
        logger.error(f"Failed to persist scan results: {e}")

    log_investigation(clean_url, client_ip, risk_level=report.risk_level.value)
    
    # Ensure report is properly serializable
    try:
        report.model_validate(report.model_dump())
        logger.debug(f"Report validation passed for {scan_id}")
    except Exception as e:
        logger.error(f"Report validation error: {e}")
        raise HTTPException(status_code=500, detail=f"Invalid report format: {e}")
    
    return report


@app.get("/api/history", response_model=List[ScanSummary])
async def get_scan_history(
    limit: int = 20,
    offset: int = 0,
    domain_filter: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Return paginated scan history with optional domain filter."""
    query = db.query(ScanRecord).order_by(ScanRecord.created_at.desc())
    if domain_filter:
        query = query.filter(ScanRecord.domain.contains(domain_filter))
    records = query.offset(offset).limit(min(limit, 100)).all()
    return records


@app.get("/api/scan/{scan_id}", response_model=InvestigationReport)
async def get_scan_report(scan_id: int, db: Session = Depends(get_db)):
    """Retrieve a cached investigation report by scan ID."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    report_data: Optional[str] = str(record.report_json) if record.report_json else None  # type: ignore
    if not report_data or len(report_data) == 0:
        raise HTTPException(status_code=404, detail="Report data not available for this scan")
    try:
        return InvestigationReport.model_validate_json(report_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to deserialize report: {e}")


@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    """Delete a scan record."""
    record = db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    db.delete(record)
    db.commit()
    return {"deleted": scan_id}


@app.get("/api/stats")
async def get_platform_stats(db: Session = Depends(get_db)):
    """Return aggregate platform statistics."""
    total = db.query(ScanRecord).count()
    critical = db.query(ScanRecord).filter(ScanRecord.risk_level == "CRITICAL").count()
    high = db.query(ScanRecord).filter(ScanRecord.risk_level == "HIGH").count()
    blacklisted = db.query(ScanRecord).filter(ScanRecord.is_blacklisted == True).count()
    return {
        "total_scans": total,
        "critical_findings": critical,
        "high_findings": high,
        "blacklisted_findings": blacklisted,
        "platform_version": settings.APP_VERSION
    }


# ─── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
