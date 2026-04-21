"""
OSINT Platform - Subdomain Discovery Module
Passive subdomain enumeration via DNS brute-force and certificate transparency logs.
Active brute-force against real targets requires explicit permission (bug bounty scope).
This module uses only PASSIVE techniques: crt.sh and DNS resolution.
"""

import requests
import dns.resolver
import logging
from typing import List, Set
from concurrent.futures import ThreadPoolExecutor, as_completed

from schemas import SubdomainResult
from config import settings

logger = logging.getLogger("osint.subdomains")

# Common subdomain prefixes for light DNS bruteforce
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "app", "portal",
    "admin", "ftp", "m", "mobile", "shop", "store", "cdn", "static",
    "media", "images", "img", "beta", "test", "demo", "docs", "support",
    "help", "status", "git", "gitlab", "jenkins", "jira", "confluence"
]

MAX_SUBDOMAINS_TO_RETURN = 50


def discover_subdomains(domain: str) -> SubdomainResult:
    """
    Passive subdomain enumeration.
    Sources: crt.sh (certificate transparency) + DNS word list resolution.
    """
    logger.info(f"Subdomain discovery: {domain}")
    found: Set[str] = set()

    # Source 1: Certificate Transparency (crt.sh)
    crt_subdomains = _query_crtsh(domain)
    found.update(crt_subdomains)
    logger.info(f"crt.sh found {len(crt_subdomains)} subdomains for {domain}")

    # Source 2: DNS wordlist resolution
    dns_subdomains = _dns_bruteforce(domain, COMMON_SUBDOMAINS)
    found.update(dns_subdomains)
    logger.info(f"DNS bruteforce found {len(dns_subdomains)} subdomains for {domain}")

    # Remove the apex domain itself
    found.discard(domain)
    found.discard(f"www.{domain}")

    # Sort and cap results
    sorted_subs = sorted(found)[:MAX_SUBDOMAINS_TO_RETURN]

    return SubdomainResult(
        subdomains=sorted_subs,
        total_found=len(found)
    )


def _query_crtsh(domain: str) -> List[str]:
    """
    Query crt.sh certificate transparency database.
    Returns all unique subdomains seen in publicly-issued TLS certificates.
    This is entirely passive — no active probing of the target.
    """
    subdomains = []
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15,
            headers={"User-Agent": settings.HTTP_USER_AGENT}
        )
        if resp.status_code == 200:
            data = resp.json()
            seen = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                # crt.sh may return multi-line values
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        if name not in seen:
                            seen.add(name)
                            subdomains.append(name)
    except Exception as e:
        logger.debug(f"crt.sh query failed for {domain}: {e}")

    return subdomains


def _dns_bruteforce(domain: str, wordlist: List[str]) -> List[str]:
    """
    Attempt DNS resolution for each subdomain in the wordlist.
    Uses thread pool for parallel resolution.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = 2.0
    resolver.lifetime = 4.0

    found = []

    def resolve_subdomain(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        try:
            resolver.resolve(fqdn, "A")
            return fqdn
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(resolve_subdomain, prefix): prefix for prefix in wordlist}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return found
