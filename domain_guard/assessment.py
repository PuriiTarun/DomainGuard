"""Shared bounded assessment for the CLI's checks and the local website."""
import time
from domain_guard.checks.dns import RECORD_TYPES, check_dns
from domain_guard.checks.email import EMAIL_PREFIXES, email_observations
from domain_guard.checks.https import check_https
from domain_guard.checks.headers import check_headers
from domain_guard.checks.tls import check_tls
from domain_guard.network import check_public_dns
from domain_guard.validation import normalize_domain
from domain_guard.results import bound_report

SCAN_SECONDS = 20

def scan_domain(value):
    """Return a JSON-compatible assessment of one canonical domain."""
    domain = normalize_domain(value)
    deadline = time.monotonic() + SCAN_SECONDS
    network = check_public_dns(domain, deadline=deadline)
    empty = {"status": "incomplete", "values": []}
    result = {
        "domain": domain,
        "schema_version": 1,
        "status": network.get("status", "rejected") if not network["safe"] else "complete",
        "addresses": network["addresses"] if network["safe"] else [],
        "checks": {},
        "records": {kind: empty.copy() for kind in RECORD_TYPES},
        **{kind: empty.copy() for kind in ("spf", *EMAIL_PREFIXES)}
    }
    if(not network["safe"]):
        result["checks"]["address"] = {"status": result["status"], "message": network["message"]}
        return bound_report(result)

    result["checks"]["address"] = {"status": "pass", "message": "Public addresses verified"}
    remaining = max(0, deadline - time.monotonic())
    https = check_https(domain, network["addresses"], timeout=remaining)
    https_status = "pass" if https["success"] else "incomplete" if remaining <= 0 else "fail" if "certificate verification failed" in https["message"].lower() else "unavailable"
    result["checks"]["https"] = {
        "status": https_status,
        "message": https["message"], "status_code": https["status_code"]
    }
    if(https["success"] and "headers" in https):
        result["checks"]["headers"] = check_headers(https["headers"])
    else:
        result["checks"]["headers"] = {"status": "unavailable", "message": "HTTPS headers unavailable"}
    if(https["success"]):
        redirect = https["status_code"] in (301, 302, 303, 307, 308)
        result["checks"]["redirects"] = https.get("redirect", {"status": "info", "message": "Redirect observed; destination not followed" if redirect else "No redirect observed on the HTTPS root response"})
    remaining = max(0, deadline - time.monotonic())
    tls = check_tls(domain, network["addresses"], timeout=remaining)
    tls_status = "pass" if tls["valid"] else "incomplete" if remaining <= 0 else "fail" if tls["message"] in ("TLS certificate verification failed", "TLS certificate expired", "TLS certificate not yet valid") else "unavailable"
    result["checks"]["tls"] = {
        "status": tls_status,
        "message": tls["message"], "expires": tls["expires"], "days_remaining": tls["days_remaining"]
    }
    dns = check_dns(domain, deadline=deadline, address_records=network.get("records"))
    result["records"] = dns["records"]
    for kind in ("spf", *EMAIL_PREFIXES):
        if(kind in dns):
            record = dns[kind]
            result[kind] = {**record, "findings": email_observations(kind, record)}
    if(any(check["status"] in ("incomplete", "unavailable") for check in result["checks"].values()) or
       any(record["status"] in ("incomplete", "error", "nxdomain") for record in dns["records"].values()) or
       any(result[kind]["status"] in ("incomplete", "error") for kind in ("spf", *EMAIL_PREFIXES) if kind in dns)):
        result["status"] = "incomplete"
    return bound_report(result)
