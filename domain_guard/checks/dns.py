import dns.exception
import dns.resolver

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")

def lookup_records(domain, record_type):
    """
    Look up DNS records for a domain.

    Return the records found, or indicate whether the records
    are missing or the DNS lookup failed.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
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

    for record in answers:
        if(record_type == "TXT"):
            # Combine TXT record segments into one string
            value = b"".join(record.strings).decode("utf-8", errors="replace")
        else:
            value = record.to_text()
        values.append(value)

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
    if(lookup["status"] == "error"):
        return {
            "status": "error",
            "values": []
        }

    matches = []

    for value in lookup["values"]:
        text = value.strip().lower()

        if(record_type == "SPF" and text.split(" ", 1)[0] == "v=spf1"):
            matches.append(value)
        if(record_type == "DMARC" and text.split(";", 1)[0].strip() == "v=dmarc1"):
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

def check_dns(domain):
    """
    Check the domain's DNS records and look for SPF and DMARC.

    Return the DNS records and email authentication results.
    """
    records = {}

    for record_type in RECORD_TYPES:
        records[record_type] = lookup_records(domain, record_type)

    # DMARC records are published under the _dmarc hostname
    dmarc_lookup = lookup_records(f"_dmarc.{domain}", "TXT")

    return {
        "records": records,
        "spf": check_email_record(records["TXT"], "SPF"),
        "dmarc": check_email_record(dmarc_lookup, "DMARC")
    }