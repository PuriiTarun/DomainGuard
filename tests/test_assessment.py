from unittest.mock import patch
import pytest
from domain_guard.assessment import scan_domain

def test_scan_rejects_unsafe_destination_without_checks():
    with patch("domain_guard.assessment.check_public_dns", return_value={"safe": False, "addresses": [], "message": "Non-public address"}), \
         patch("domain_guard.assessment.check_https") as https:
        result = scan_domain("EXAMPLE.COM")
    assert result["domain"] == "example.com"
    assert result["status"] == "rejected"
    assert result["addresses"] == []
    https.assert_not_called()

def test_scan_returns_structured_results():
    dns = {"records": {"A": {"status": "found", "values": ["8.8.8.8"]}},
           "spf": {"status": "missing", "values": []}, "dmarc": {"status": "missing", "values": []}}
    with patch("domain_guard.assessment.check_public_dns", return_value={"safe": True, "addresses": ["8.8.8.8"]}), \
         patch("domain_guard.assessment.check_https", return_value={"success": True, "status_code": 200, "message": "OK", "headers": {}}), \
         patch("domain_guard.assessment.check_tls", return_value={"valid": True, "expires": "2030-01-01", "days_remaining": 30, "message": "OK"}), \
         patch("domain_guard.assessment.check_dns", return_value=dns):
        result = scan_domain("example.com")
    assert result["status"] == "complete"
    assert result["checks"]["https"]["status"] == "pass"
    assert result["records"]["A"]["values"] == ["8.8.8.8"]

def test_scan_invalid_name_raises_before_resolution():
    with patch("domain_guard.assessment.check_public_dns") as resolve:
        with pytest.raises(ValueError):
            scan_domain("http://localhost")
    resolve.assert_not_called()
