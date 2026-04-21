"""
OSINT Platform - DNS Intelligence Module
Resolves DNS records and maps infrastructure via ASN/IP geolocation.
Bulletproof DNS analysis reveals hosting patterns, bulletproof hosters, and infrastructure overlap.
"""

import dns.resolver
import dns.reversename
import logging
import socket
import requests
from typing import List, Optional

from schemas import DNSIntelResult
from config import settings

logger = logging.getLogger("osint.dns_intel")

# Known bulletproof / abuse-friendly hosting ASNs (sample set)
SUSPICIOUS_ASNS = {
    "AS174", "AS9009", "AS60781", "AS16509",  # Not all are bad, but worth flagging
}


def analyze_dns(domain: str) -> DNSIntelResult:
    """
    Comprehensive DNS analysis: A/MX/NS/TXT records + ASN/geo enrichment.
    Uses configurable resolvers for consistency and auditability.
    """
    logger.info(f"DNS intelligence lookup: {domain}")

    resolver = dns.resolver.Resolver()
    resolver.nameservers = settings.DNS_RESOLVERS
    resolver.timeout = settings.DNS_TIMEOUT
    resolver.lifetime = settings.DNS_TIMEOUT * 2

    a_records = _query_records(resolver, domain, "A")
    mx_records = _query_records(resolver, domain, "MX")
    ns_records = _query_records(resolver, domain, "NS")
    txt_records = _query_records(resolver, domain, "TXT")

    # Primary IP for enrichment
    primary_ip = a_records[0] if a_records else None
    asn = asn_org = hosting_provider = country = reverse_dns = None

    if primary_ip:
        try:
            reverse_dns = _get_reverse_dns(primary_ip)
            ip_info = _get_ip_info(primary_ip)
            asn = ip_info.get("asn")
            asn_org = ip_info.get("org")
            hosting_provider = ip_info.get("isp") or ip_info.get("org")
            country = ip_info.get("country")
        except Exception as e:
            logger.warning(f"IP enrichment failed for {primary_ip}: {e}")

    return DNSIntelResult(
        domain=domain,
        a_records=a_records,
        mx_records=mx_records,
        ns_records=ns_records,
        txt_records=txt_records,
        primary_ip=primary_ip,
        asn=asn,
        asn_org=asn_org,
        hosting_provider=hosting_provider,
        country=country,
        reverse_dns=reverse_dns
    )


def _query_records(resolver: dns.resolver.Resolver, domain: str, rtype: str) -> List[str]:
    """Query a single DNS record type and return cleaned string list."""
    try:
        answers = resolver.resolve(domain, rtype)
        if rtype == "MX":
            return [str(r.exchange).rstrip(".") for r in answers]
        elif rtype == "TXT":
            results = []
            for r in answers:
                for string in r.strings:
                    results.append(string.decode("utf-8", errors="replace"))
            return results
        else:
            return [str(r).rstrip(".") for r in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception as e:
        logger.debug(f"DNS {rtype} query failed for {domain}: {e}")
        return []


def _get_reverse_dns(ip: str) -> Optional[str]:
    """Perform PTR record lookup for an IP address."""
    try:
        rev_name = dns.reversename.from_address(ip)
        result = socket.gethostbyaddr(ip)
        return result[0]
    except Exception:
        return None


def _get_ip_info(ip: str) -> dict:
    """
    Fetch ASN, ISP, and geo data from ip-api.com (free, no auth required).
    In production, swap for MaxMind GeoIP or Shodan for more reliable data.
    """
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,isp,org,as",
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as", "").split(" ")[0]  # Extract "AS12345"
                }
    except Exception as e:
        logger.debug(f"IP info lookup failed for {ip}: {e}")
    return {}
