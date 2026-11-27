import pytest
from urllib3._collections import HTTPHeaderDict
from domain_guard.checks.headers import check_headers, collect_headers, MAX_HEADER_BYTES

def get(headers, name):
    result = check_headers(collect_headers(HTTPHeaderDict(headers)))
    return next(item for item in result["findings"] if item["name"] == name)

@pytest.mark.parametrize("value,status", [("max-age=31536000; includeSubDomains", "pass"), ("max-age=0", "warning"), ("max-age=invalid", "warning"), ("max-age=1; max-age=2", "warning"), ("", "warning")])
def test_hsts(value, status):
    assert get({"Strict-Transport-Security": value}, "Strict-Transport-Security")["status"] == status

def test_report_only_is_not_enforcement():
    result = get({"Content-Security-Policy-Report-Only": "default-src 'self'"}, "Content-Security-Policy")
    assert result["status"] == "warning"
    assert "does not enforce" in result["message"]

def test_csp_presence_does_not_claim_policy_strength():
    result = get({"Content-Security-Policy": "default-src *; frame-ancestors 'none'"}, "Content-Security-Policy")
    assert result["status"] == "info"
    assert "not assessed" in result["message"]
    assert get({"Content-Security-Policy": "frame-ancestors 'none'"}, "X-Frame-Options")["status"] == "info"

def test_duplicate_and_oversized_headers():
    headers = HTTPHeaderDict()
    headers.add("X-Content-Type-Options", "nosniff")
    headers.add("X-Content-Type-Options", "other")
    assert check_headers(collect_headers(headers))["status"] == "warning"
    assert get({"Strict-Transport-Security": "x" * (MAX_HEADER_BYTES + 1)}, "Strict-Transport-Security")["status"] == "unavailable"

def test_no_raw_header_content_in_findings():
    value = "<script>alert(1)</script>"
    assert value not in str(check_headers(collect_headers(HTTPHeaderDict({"Content-Security-Policy": value}))))
