"""
OSINT Platform - Security Layer
Implements SSRF protection, rate limiting, input sanitization, and audit logging.
This module is the first gate every request passes through.
"""

import re
import socket
import ipaddress
import logging
from urllib.parse import urlparse
from typing import Optional
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps

from config import settings

logger = logging.getLogger("osint.security")


# ─── Input Sanitization ───────────────────────────────────────────────────────

# Strict URL validation regex — rejects encoded tricks
URL_PATTERN = re.compile(
    r'^https?://'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z]{2,})'
    r'(?::\d{1,5})?'
    r'(?:[/?#][^\s]*)?$',
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'\.[a-zA-Z]{2,}$'
)


def sanitize_url(url: str) -> tuple[bool, str, Optional[str]]:
    """
    Validate and sanitize a URL input.
    Returns (is_valid, cleaned_url, error_message).
    """
    # Length check
    if len(url) > settings.MAX_URL_LENGTH:
        return False, url, f"URL exceeds maximum length of {settings.MAX_URL_LENGTH}"

    # Strip whitespace and null bytes
    url = url.strip().replace("\x00", "")

    # Scheme check
    parsed = urlparse(url)
    if parsed.scheme not in settings.ALLOWED_SCHEMES:
        return False, url, f"Scheme '{parsed.scheme}' not allowed. Use http or https."

    # Block IP literals in the host part directly
    host = parsed.hostname or ""
    if _is_private_or_reserved(host):
        logger.warning(f"SSRF attempt blocked: {url}")
        return False, url, "Target resolves to a private or reserved address"

    # Regex pattern check
    if not URL_PATTERN.match(url):
        return False, url, "URL format is invalid"

    return True, url, None


def extract_domain(url: str) -> Optional[str]:
    """Extract the bare domain/hostname from a URL."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Strip www. prefix for analysis purposes
        return host.lstrip("www.") if host.startswith("www.") else host
    except Exception:
        return None


# ─── SSRF Protection ──────────────────────────────────────────────────────────

def _is_private_or_reserved(host: str) -> bool:
    """
    Check if a hostname or IP string resolves to a private/reserved range.
    This prevents Server-Side Request Forgery by blocking calls to internal infrastructure.
    """
    if not host:
        return True

    # Direct IP check
    try:
        addr = ipaddress.ip_address(host)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_reserved or
            addr.is_multicast or
            addr.is_unspecified
        )
    except ValueError:
        pass  # Not an IP literal — proceed to DNS resolution check

    # Prefix check for string-based blocking
    for prefix in settings.BLOCKED_IP_PREFIXES:
        if host.startswith(prefix):
            return True

    # Resolve and check resolved IPs
    try:
        resolved_ips = socket.getaddrinfo(host, None)
        for result in resolved_ips:
            ip_str = result[4][0]
            try:
                addr = ipaddress.ip_address(ip_str)
                if (addr.is_private or addr.is_loopback or
                        addr.is_link_local or addr.is_reserved):
                    logger.warning(f"SSRF: {host} resolved to private IP {ip_str}")
                    return True
            except ValueError:
                continue
    except socket.gaierror:
        pass  # DNS failure — not necessarily a threat

    return False


def validate_probe_target(ip: str) -> bool:
    """
    Final validation before any HTTP probe is sent.
    Call this just before requests.get() on any derived/resolved IP.
    """
    return not _is_private_or_reserved(ip)


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token-bucket rate limiter keyed by client IP.
    Tracks request timestamps per IP and enforces a per-minute cap.
    """
    def __init__(self):
        self._requests: dict = defaultdict(list)

    def is_allowed(self, client_ip: str) -> tuple[bool, int]:
        """
        Returns (allowed, retry_after_seconds).
        """
        now = datetime.utcnow()
        window = now - timedelta(minutes=1)
        
        # Prune old entries
        self._requests[client_ip] = [
            ts for ts in self._requests[client_ip] if ts > window
        ]

        count = len(self._requests[client_ip])
        if count >= settings.RATE_LIMIT_PER_MINUTE:
            oldest = self._requests[client_ip][0]
            retry_after = int((oldest + timedelta(minutes=1) - now).total_seconds()) + 1
            logger.warning(f"Rate limit hit for {client_ip} ({count} requests/min)")
            return False, max(retry_after, 1)

        self._requests[client_ip].append(now)
        return True, 0


# Global rate limiter instance
rate_limiter = RateLimiter()


# ─── Audit Logging ────────────────────────────────────────────────────────────

def log_investigation(url: str, client_ip: str, risk_level: Optional[str] = None):
    """
    Structured audit log entry for every investigation.
    HIGH/CRITICAL scans are flagged for security review.
    """
    entry = {
        "event": "investigation",
        "url": url,
        "client_ip": client_ip,
        "risk_level": risk_level,
        "timestamp": datetime.utcnow().isoformat()
    }
    if risk_level in ("HIGH", "CRITICAL"):
        logger.warning(f"HIGH-RISK SCAN: {entry}")
    else:
        logger.info(f"SCAN: {entry}")


def log_suspicious_activity(event: str, detail: str, client_ip: str):
    """Dedicated logger for security events."""
    logger.warning(f"[SECURITY] {event} | {detail} | client={client_ip}")
