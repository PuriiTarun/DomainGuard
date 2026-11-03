"""Shared scan orchestration used by the CLI and local API."""

from datetime import datetime, timezone

from domain_guard.checks.dns import check_dns, RECORD_TYPES
from domain_guard.checks.headers import check_security_headers
from domain_guard.checks.https import check_https
from domain_guard.checks.redirects import check_http_redirect
from domain_guard.checks.tls import check_tls
from domain_guard.network import check_public_dns
from domain_guard.validation import is_valid_domain


class UnsafeTargetError(ValueError):
    """Raised when a target does not pass network safety checks."""


def scan_domain(domain):
    """Run each diagnostic independently and preserve partial failures."""
    domain = domain.strip().lower()
    if not is_valid_domain(domain):
        raise ValueError("Enter a domain name such as example.com")

    network = check_public_dns(domain)
    if not network["safe"]:
        raise UnsafeTargetError(network["message"])

    addresses = network["addresses"]

    try:
        https = check_https(domain, addresses)
    except Exception:
        https = {
            "success": False, "status_code": None,
            "message": "HTTPS check failed unexpectedly", "headers": {}
        }

    try:
        tls = check_tls(domain, addresses)
    except Exception:
        tls = {
            "valid": False, "expires": None, "days_remaining": None,
            "message": "TLS check failed unexpectedly"
        }

    try:
        dns = check_dns(domain)
    except Exception:
        error = {"status": "error", "values": []}
        dns = {
            "records": {name: error.copy() for name in RECORD_TYPES},
            "spf": error.copy(), "dmarc": error.copy()
        }

    try:
        headers = check_security_headers(https)
    except Exception:
        headers = {
            "status": "unknown", "checks": {},
            "message": "Could not analyze security headers"
        }

    try:
        redirects = check_http_redirect(domain, addresses)
    except Exception:
        redirects = {
            "status": "unknown", "http_status": None,
            "location": None, "message": "Redirect check failed unexpectedly"
        }

    return {
        "domain": domain,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "network": network,
        "https": https,
        "tls": tls,
        "dns": dns,
        "headers": headers,
        "redirects": redirects
    }
