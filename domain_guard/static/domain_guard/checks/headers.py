import re

MAX_HEADER_BYTES = 4096
MAX_HEADER_VALUES = 8
HEADER_NAMES = ("Strict-Transport-Security", "Content-Security-Policy", "Content-Security-Policy-Report-Only", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "X-Frame-Options")

def collect_headers(headers):
    result = {}
    for name in HEADER_NAMES:
        values = headers.getlist(name)
        if(len(values) > MAX_HEADER_VALUES or any(not isinstance(value, str) or len(value.encode("utf-8")) > MAX_HEADER_BYTES for value in values)):
            result[name] = None
        else:
            result[name] = list(values)
    return result

def assess_hsts(values):
    if(len(values) != 1):
        return "warning", "Missing or repeated HSTS header"
    directives = [part.strip() for part in values[0].split(";")]
    ages = [part.split("=", 1)[1].strip() for part in directives if "=" in part and part.split("=", 1)[0].strip().lower() == "max-age"]
    if(len(ages) != 1 or not re.fullmatch(r"[0-9]{1,16}", ages[0]) or int(ages[0]) == 0):
        return "warning", "HSTS max-age is missing, invalid, repeated or zero"
    return "pass", "Positive HSTS max-age observed"

def assess_one(name, values, headers):
    if(values is None):
        return "unavailable", "Header exceeds assessment limits"
    if(name == "Strict-Transport-Security"):
        return assess_hsts(values)
    if(name == "X-Content-Type-Options"):
        if(len(values) == 1 and values[0].strip().lower() == "nosniff"):
            return "pass", "nosniff observed"
        return "warning", "Missing or unexpected nosniff value"
    if(name == "Content-Security-Policy"):
        if(any(value.strip() for value in values)):
            return "info", "Enforcing CSP header present; policy strength not assessed"
        if(headers.get("Content-Security-Policy-Report-Only")):
            return "warning", "Only report-only CSP observed; it does not enforce a policy"
        return "warning", "No enforcing CSP observed"
    if(name == "X-Frame-Options"):
        if(len(values) == 1 and values[0].strip().upper() in ("DENY", "SAMEORIGIN")):
            return "pass", "Recognized frame restriction observed"
        if(any(re.search(r"(?:^|;)\s*frame-ancestors(?:\s|$)", value, re.I) for value in (headers.get("Content-Security-Policy") or []))):
            return "info", "CSP frame-ancestors present; policy strength not assessed"
        return "warning", "No recognized frame restriction observed"
    if(name == "Referrer-Policy"):
        if(any(value.strip() for value in values)):
            return "info", "Referrer policy present; full policy not assessed"
        return "info", "No explicit referrer policy observed; browser defaults may apply"
    if(name == "Permissions-Policy"):
        return "info", "Permissions policy present; full policy not assessed" if any(value.strip() for value in values) else "No explicit permissions policy observed"
    return "info", "Header present" if values else "Header not observed"

def check_headers(headers):
    findings = []
    for name in HEADER_NAMES:
        if(name == "Content-Security-Policy-Report-Only"):
            continue
        status, message = assess_one(name, headers.get(name, []), headers)
        findings.append({"name": name, "status": status, "message": message})
    if(any(item["status"] == "unavailable" for item in findings)):
        status = "incomplete"
    else:
        status = "warning" if any(item["status"] == "warning" for item in findings) else "info"
    return {"status": status, "message": "Header observations from one HTTPS response, not a vulnerability assessment", "findings": findings}
