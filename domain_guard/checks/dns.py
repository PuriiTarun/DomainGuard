import time

import dns.exception
import dns.resolver
from domain_guard.validation import is_valid_domain
from domain_guard.checks.email import EMAIL_PREFIXES, candidate

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")
MAX_RECORDS = 64
MAX_VALUE_BYTES = 2048
MAX_TOTAL_BYTES = 8192

def lookup_records(domain, record_type, lifetime=5):
    """
    Look up DNS records for a domain.

    Return the records found, or indicate whether the records
    are missing or the DNS lookup failed.
    """
    target = domain
    if(isinstance(domain, str) and record_type == "TXT"):
        for prefix in EMAIL_PREFIXES.values():
            if(domain.startswith(prefix)):
                target = domain.removeprefix(prefix)
                break
    if(record_type not in RECORD_TYPES or not is_valid_domain(target) or len(domain) > 253):
        return {"status": "error", "values": []}
    if(lifetime <= 0):
        return {"status": "incomplete", "values": []}
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=min(lifetime, 5), search=False)

    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "values": []}

    except dns.resolver.NoAnswer:
        return {
            "status": "missing",
            "values": []
        }

    except dns.exception.DNSException:
        return {
            "status": "error",
            "values": []
        }

    values = []

    try:
        total = 0
        for record in answers:
            if(len(values) >= MAX_RECORDS):
                return {"status": "error", "values": []}
            if(record_type == "TXT"):
                # TXT strings are chunks of one record, not separate records.
                chunks = record.strings
                if(sum(len(chunk) for chunk in chunks) > MAX_VALUE_BYTES):
                    return {"status": "error", "values": []}
                value = b"".join(chunks).decode("utf-8", errors="replace")
            else:
                value = record.to_text()
            size = len(value.encode("utf-8"))
            total += size
            if(total > MAX_TOTAL_BYTES or size > MAX_VALUE_BYTES):
                return {"status": "error", "values": []}
            values.append(value)
    except (AttributeError, TypeError, ValueError):
        return {"status": "error", "values": []}

    return {
        "status": "found" if values else "missing",
        "values": values
    }

def check_email_record(lookup, record_type):
    """
    Check whether SPF or DMARC records are published.

    Detect missing or duplicate records without assuming
    that a detected record is correctly configured.
    """
    if(lookup["status"] in ("error", "nxdomain", "incomplete")):
        return {
            "status": lookup["status"],
            "values": []
        }

    matches = []

    for value in lookup["values"]:
        text = value.strip().lower()

        if(candidate(text, record_type)):
            matches.append(value)

    if(len(matches) > 1):
        status = "multiple"
    elif(matches):
        status = "found"
    else:
        status = "missing"

    return {
        "status": status,
        "values": matches
    }

def check_dns(domain, deadline=None, address_records=None):
    """
    Check the domain's DNS records and look for SPF and DMARC.

    Return the DNS records and email authentication results.
    """
    if(not is_valid_domain(domain)):
        rejected = {"status": "error", "values": []}
        return {"records": {kind: rejected.copy() for kind in RECORD_TYPES}, **{kind: rejected.copy() for kind in ("spf", *EMAIL_PREFIXES)}}
    records = {}
    def query(name, kind):
        if(deadline is None):
            return lookup_records(name, kind)
        return lookup_records(name, kind, max(0, deadline - time.monotonic()))
    for record_type in RECORD_TYPES:
        if(address_records is not None and record_type in address_records):
            records[record_type] = address_records[record_type]
        else:
            records[record_type] = query(domain, record_type)
    result = {"records": records, "spf": check_email_record(records["TXT"], "SPF")}
    for kind, prefix in EMAIL_PREFIXES.items():
        result[kind] = check_email_record(query(f"{prefix}{domain}", "TXT"), kind.upper())
    return result
