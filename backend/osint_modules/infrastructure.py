"""
OSINT Platform - Infrastructure Intelligence Module
Probes HTTP headers, SSL certificates, and fingerprints server technologies.
Provides deep visibility into the target's technical stack.
"""

import requests
import ssl
import socket
import logging
from datetime import datetime
from typing import Optional, List, Dict
from urllib.parse import urlparse

from schemas import InfrastructureResult, SSLCertInfo
from config import settings
from security import validate_probe_target

logger = logging.getLogger("osint.infrastructure")

# Security header checklist — absence indicates misconfiguration or phishing kit
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy"
]

# Technology fingerprinting signatures — maps header/value patterns to product names
TECH_SIGNATURES = {
    "server": {
        "apache": "Apache HTTP Server",
        "nginx": "Nginx",
        "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "litespeed": "LiteSpeed",
        "openresty": "OpenResty/Nginx"
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Node.js/Express",
        "django": "Django"
    },
    "via": {
        "cloudfront": "AWS CloudFront",
        "squid": "Squid Proxy",
        "varnish": "Varnish Cache"
    }
}


def analyze_infrastructure(url: str) -> InfrastructureResult:
    """
    Probe the target URL for HTTP headers, SSL data, and tech stack.
    Performs SSRF guard before initiating any connection.
    """
    logger.info(f"Infrastructure probe: {url}")
    parsed = urlparse(url)
    host = parsed.hostname

    # SSRF guard: verify resolved IP is not private
    if not validate_probe_target(host):
        return InfrastructureResult(error="Target blocked by SSRF protection policy")

    headers_result: Dict = {}
    redirect_chain: List[str] = []
    http_status = None
    server_header = None
    powered_by = None
    technologies: List[str] = []
    content_type = None

    # ── HTTP Probe ──────────────────────────────────────────────────────────
    try:
        session = requests.Session()
        session.max_redirects = 5

        resp = session.get(
            url,
            timeout=settings.HTTP_TIMEOUT,
            headers={"User-Agent": settings.HTTP_USER_AGENT},
            allow_redirects=True,
            verify=False  # We inspect SSL separately
        )
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        http_status = resp.status_code
        headers_result = dict(resp.headers)
        content_type = resp.headers.get("content-type", "").split(";")[0]

        # Collect redirect chain
        for r in resp.history:
            redirect_chain.append(r.url)
        if resp.url != url:
            redirect_chain.append(resp.url)

        # Extract server identity
        server_header = resp.headers.get("server")
        powered_by = resp.headers.get("x-powered-by")

        # Fingerprint technologies
        technologies = _fingerprint_technologies(resp.headers)

    except requests.exceptions.TooManyRedirects:
        logger.warning(f"Too many redirects for {url}")
    except requests.exceptions.ConnectionError as e:
        logger.info(f"Connection failed for {url}: {e}")
        # Still try SSL
    except Exception as e:
        logger.error(f"HTTP probe error for {url}: {e}")

    # ── Security Header Audit ───────────────────────────────────────────────
    security_headers = {
        h: h in {k.lower() for k in headers_result.keys()}
        for h in SECURITY_HEADERS
    }

    # ── SSL Certificate Analysis ────────────────────────────────────────────
    ssl_info = None
    if url.startswith("https://"):
        ssl_info = _analyze_ssl(host, parsed.port or 443)

    return InfrastructureResult(
        server_header=server_header,
        powered_by=powered_by,
        technologies=technologies,
        http_status=http_status,
        redirect_chain=redirect_chain,
        ssl_info=ssl_info,
        security_headers=security_headers,
        content_type=content_type
    )


def _fingerprint_technologies(headers: Dict) -> List[str]:
    """Match response headers against known technology signatures."""
    found = []
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

    for header_name, patterns in TECH_SIGNATURES.items():
        header_val = headers_lower.get(header_name, "")
        for pattern, tech_name in patterns.items():
            if pattern in header_val:
                if tech_name not in found:
                    found.append(tech_name)

    # Check for CDN/WAF via response headers
    if "cf-ray" in headers_lower:
        found.append("Cloudflare CDN/WAF")
    if "x-amz-request-id" in headers_lower or "x-amzn-requestid" in headers_lower:
        found.append("Amazon AWS")
    if "x-cache" in headers_lower and "hit" in headers_lower.get("x-cache", ""):
        found.append("CDN Cache Hit")

    return list(set(found))


def _analyze_ssl(hostname: str, port: int) -> Optional[SSLCertInfo]:
    """Extract SSL certificate details via direct TLS handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return SSLCertInfo(is_valid=False)

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        # Parse validity dates
        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        valid_until = None
        days_until_expiry = None
        if not_after:
            try:
                valid_until = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_until_expiry = (valid_until - datetime.utcnow()).days
            except ValueError:
                pass

        valid_from = None
        if not_before:
            try:
                valid_from = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                pass

        # Extract SAN domains
        san_domains = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_domains.append(san_value)

        is_valid = days_until_expiry is not None and days_until_expiry > 0

        return SSLCertInfo(
            subject=subject.get("commonName"),
            issuer=issuer.get("organizationName"),
            valid_from=valid_from.isoformat() if valid_from else None,
            valid_until=valid_until.isoformat() if valid_until else None,
            is_valid=is_valid,
            days_until_expiry=days_until_expiry,
            san_domains=san_domains[:10]  # Cap at 10 for display
        )

    except Exception as e:
        logger.debug(f"SSL analysis failed for {hostname}:{port}: {e}")
        return SSLCertInfo(is_valid=False)
