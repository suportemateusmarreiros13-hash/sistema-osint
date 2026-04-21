"""
OSINT Platform - Database Models & Session Management
SQLite-backed persistence for scan history and cached results.
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False}  # Required for SQLite
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class ScanRecord(Base):
    """Stores every investigation request and its results."""
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(2048), index=True, nullable=False)
    domain = Column(String(512), index=True, nullable=True)
    ip_address = Column(String(64), nullable=True)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(16), nullable=True)          # LOW / MEDIUM / HIGH / CRITICAL
    scan_duration_ms = Column(Integer, nullable=True)
    report_json = Column(Text, nullable=True)               # Full JSON report
    error = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    requester_ip = Column(String(64), nullable=True)        # For audit logging

    # Quick-access flags derived from analysis
    is_blacklisted = Column(Boolean, default=False)
    has_ssl = Column(Boolean, default=False)
    domain_age_days = Column(Integer, nullable=True)
    is_newly_registered = Column(Boolean, default=False)


class ThreatFeedCache(Base):
    """Caches threat feed lookups to avoid excessive external calls."""
    __tablename__ = "threat_feed_cache"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(512), index=True, unique=True)
    indicator_type = Column(String(32))                     # domain / ip / url
    is_malicious = Column(Boolean, default=False)
    source = Column(String(256))
    last_checked = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)


def init_db():
    """Initialize database tables on startup."""
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency — yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
