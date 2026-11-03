from unittest.mock import patch
import pytest
from domain_guard.scanner import scan_domain, UnsafeTargetError


def test_rejects_invalid_domain_before_dns():
    with patch("domain_guard.scanner.check_public_dns") as network:
        with pytest.raises(ValueError):
            scan_domain("https://example.com")
        network.assert_not_called()


def test_rejects_private_network_without_scanning():
    with patch("domain_guard.scanner.check_public_dns") as network, patch("domain_guard.scanner.check_https") as https:
        network.return_value = {"safe": False, "addresses": ["127.0.0.1"], "message": "Private IP"}
        with pytest.raises(UnsafeTargetError):
            scan_domain("example.com")
        https.assert_not_called()


def test_partial_https_failure_does_not_mark_headers_as_found():
    with patch("domain_guard.scanner.check_public_dns", return_value={"safe": True, "addresses": ["8.8.8.8"], "message": "ok"}), \
         patch("domain_guard.scanner.check_https", side_effect=RuntimeError("failure")), \
         patch("domain_guard.scanner.check_tls", return_value={"valid": False, "expires": None, "days_remaining": None, "message": "failed"}), \
         patch("domain_guard.scanner.check_dns", return_value={"records": {}, "spf": {"status": "missing", "values": []}, "dmarc": {"status": "missing", "values": []}}), \
         patch("domain_guard.scanner.check_http_redirect", return_value={"status": "unknown", "http_status": None, "location": None, "message": "not checked"}):
        result = scan_domain("example.com")
        assert result["https"]["success"] is False
        assert result["headers"]["status"] == "unknown"
        assert result["dns"]["spf"]["status"] == "missing"
