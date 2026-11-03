import pytest
from domain_guard.checks.headers import check_security_headers


def test_failed_https_is_unknown():
    result = check_security_headers({"success": False})
    assert result["status"] == "unknown"
    assert result["checks"] == {}


def test_headers_are_detected_case_insensitively():
    result = check_security_headers({"success": True, "headers": {
        "strict-transport-security": "max-age=31536000",
        "CONTENT-SECURITY-POLICY": "default-src 'self'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff",
        "Content-Type": "text/html"
    }})
    assert result["checks"]["Strict-Transport-Security"]["status"] == "present"
    assert result["checks"]["X-Content-Type-Options"]["status"] == "present"
    assert result["checks"]["X-Frame-Options"]["status"] == "alternative"


def test_missing_headers_are_observations():
    result = check_security_headers({"success": True, "headers": {}})
    assert result["checks"]["Content-Security-Policy"]["status"] == "missing"


@pytest.mark.parametrize("value", ["max-age=0", "includeSubDomains", "max-age=banana"])
def test_hsts_values_requiring_review(value):
    result = check_security_headers({
        "success": True, "headers": {"Strict-Transport-Security": value}
    })
    assert result["checks"]["Strict-Transport-Security"]["status"] == "review"


def test_wrong_nosniff_value():
    result = check_security_headers({
        "success": True, "headers": {"X-Content-Type-Options": "maybe"}
    })
    assert result["checks"]["X-Content-Type-Options"]["status"] == "review"
