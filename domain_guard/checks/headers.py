"""Review browser security headers from an existing verified HTTPS response."""

HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Frame-Options",
)


def check_security_headers(https_result):
    """
    Review security response headers without making another network request.
    Missing headers are observations, not proof of vulnerabilities.
    """
    if not https_result.get("success"):
        return {
            "status": "unknown",
            "checks": {},
            "message": "HTTPS response unavailable; headers not checked"
        }

    headers = {
        name.lower(): value
        for name, value in https_result.get("headers", {}).items()
        if isinstance(value, str)
    }
    is_html = "text/html" in headers.get("content-type", "").lower()
    checks = {}

    for name in HEADERS:
        value = headers.get(name.lower())
        status = "present" if value else "missing"
        message = (
            "Header detected; policy not fully validated"
            if value else "Header not present on this response"
        )

        if name == "Strict-Transport-Security" and value:
            parts = [part.strip().lower() for part in value.split(";")]
            ages = [
                part.partition("=")[2].strip()
                for part in parts if part.startswith("max-age=")
            ]
            if not ages or not ages[0].isdigit() or int(ages[0]) == 0:
                status = "review"
                message = "HSTS requires a positive max-age"

        if name == "X-Content-Type-Options" and value:
            if value.strip().lower() != "nosniff":
                status = "review"
                message = "Expected X-Content-Type-Options: nosniff"

        if name == "Content-Security-Policy" and not value and not is_html:
            message = "No CSP found; relevance depends on the content type"

        if name == "X-Frame-Options" and not value:
            if "frame-ancestors" in headers.get("content-security-policy", "").lower():
                status = "alternative"
                message = "CSP frame-ancestors is present instead"

        checks[name] = {"status": status, "value": value, "message": message}

    return {
        "status": "checked",
        "checks": checks,
        "message": "Header presence reviewed, not a full policy audit"
    }
