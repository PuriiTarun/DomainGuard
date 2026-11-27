import re

EMAIL_PREFIXES = {"dmarc": "_dmarc.", "mta_sts": "_mta-sts.", "tlsrpt": "_smtp._tls."}
VERSIONS = {"DMARC": "v=dmarc1", "MTA_STS": "v=stsv1", "TLSRPT": "v=tlsrptv1"}

def candidate(text, kind):
    if(kind == "SPF"):
        return bool(re.match(r"^v=spf1(?:\s|$)", text))
    return kind in VERSIONS and text.split(";", 1)[0].strip() == VERSIONS[kind]

def finding(name, status, message):
    return {"name": name, "status": status, "message": message}

def spf_observations(value):
    terms = value.split()[1:]
    all_terms = [term.lower() for term in terms if re.fullmatch(r"[+?~-]?all", term, re.I)]
    if(not all_terms):
        return [finding("All mechanism", "info", "No explicit all mechanism observed; includes and redirects were not evaluated")]
    term = all_terms[0]
    if(term in ("all", "+all")):
        return [finding("All mechanism", "warning", "Permissive all mechanism published; reachability and full SPF syntax were not evaluated")]
    messages = {"-all": "Hard-fail all mechanism published", "~all": "Soft-fail all mechanism published", "?all": "Neutral all mechanism published"}
    return [finding("All mechanism", "info", messages[term] + "; full SPF policy not evaluated")]

def dmarc_observations(value):
    # Report direct policy tags only, not organizational-domain discovery or receiver decisions.
    tags = {}
    for part in value.strip().rstrip(";").split(";"):
        key, sep, data = part.partition("=")
        key = key.strip()
        if(not sep or not key or key in tags):
            return [finding("Policy tags", "warning", "Repeated or malformed tag; full record validity not assessed")]
        tags[key] = data.strip()
    findings = []
    policy = tags.get("p")
    if(policy in ("none", "quarantine", "reject")):
        findings.append(finding("Published policy", "info", f"p={policy} observed; receiver enforcement not verified"))
    elif(policy is None):
        findings.append(finding("Published policy", "warning", "No explicit p tag observed; effective policy not determined"))
    else:
        findings.append(finding("Published policy", "warning", "Unrecognized p tag value; effective policy not determined"))
    if(tags.get("t") == "y"):
        findings.append(finding("Testing mode", "info", "t=y published; the domain owner signals testing mode"))
    return findings

def email_observations(kind, record):
    if(record["status"] != "found" or len(record["values"]) != 1):
        return []
    value = record["values"][0]
    if(kind == "spf"):
        return spf_observations(value)
    if(kind == "dmarc"):
        return dmarc_observations(value)
    if(kind == "mta_sts"):
        return [finding("DNS announcement", "info", "MTA-STS version record detected; HTTPS policy and SMTP delivery were not checked")]
    return [finding("DNS announcement", "info", "SMTP TLS reporting record detected; reporting destination and delivery were not checked")]
