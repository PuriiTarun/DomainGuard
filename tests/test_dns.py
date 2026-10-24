from unittest.mock import patch
import dns.exception
import dns.resolver
import pytest

from domain_guard.checks.dns import (
    check_dns,
    check_email_record,
    lookup_records
)

class FakeRecord:
    def __init__(self, value):
        self.value = value
    def to_text(self):
        return self.value

class FakeTXT:
    def __init__(self, *chunks):
        self.strings = [chunk.encode() for chunk in chunks]

def test_a_records():
    with patch("domain_guard.checks.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.return_value = [FakeRecord("93.184.215.14")]
        result = lookup_records("example.com", "A")
        assert result["status"] == "found"
        assert result["values"] == ["93.184.215.14"]
        mock_resolve.assert_called_once_with("example.com", "A", lifetime=5)

def test_txt_chunks():
    # Check that split TXT record segments are joined correctly
    with patch("domain_guard.checks.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.return_value = [FakeTXT("v=spf1 include:", "mail.example.com -all")]
        result = lookup_records("example.com", "TXT")
        assert result["values"] == ["v=spf1 include:mail.example.com -all"]

@pytest.mark.parametrize("error", [dns.resolver.NoAnswer(), dns.resolver.NXDOMAIN()])
def test_missing_records(error):
    with patch("domain_guard.checks.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = error
        result = lookup_records("example.com", "MX")
        assert result["status"] == "missing"

def test_dns_timeout():
    with patch("domain_guard.checks.dns.dns.resolver.resolve") as mock_resolve:
        mock_resolve.side_effect = dns.exception.Timeout()
        result = lookup_records("example.com", "MX")
        assert result["status"] == "error"

def test_spf_detected():
    lookup = {
        "status": "found",
        "values": [
            "google-site-verification=abc",
            "v=spf1 -all"
        ]
    }

    result = check_email_record(lookup, "SPF")
    assert result["status"] == "found"
    assert result["values"] == ["v=spf1 -all"]

def test_spf_prefix_not_confused():
    lookup = {
        "status": "found",
        "values": ["v=spf10 -all"]
    }

    result = check_email_record(lookup, "SPF")
    assert result["status"] == "missing"

def test_multiple_spf():
    lookup = {
        "status": "found",
        "values": [
            "v=spf1 -all",
            "v=spf1 +all"
        ]
    }

    result = check_email_record(lookup, "SPF")
    assert result["status"] == "multiple"

def test_dmarc_found():
    lookup = {
        "status": "found",
        "values": ["v=DMARC1; p=reject; rua=mailto:admin@example.com"]
    }

    result = check_email_record(lookup, "DMARC")
    assert result["status"] == "found"

def test_multiple_dmarc():
    lookup = {
        "status": "found",
        "values": [
            "v=DMARC1; p=none",
            "v=DMARC1; p=reject"
        ]
    }

    result = check_email_record(lookup, "DMARC")
    assert result["status"] == "multiple"

def test_dns_error_not_reported_as_missing():
    lookup = {
        "status": "error",
        "values": []
    }

    result = check_email_record(lookup, "DMARC")
    assert result["status"] == "error"

def test_dns_checks_dmarc_location():
    # Verify that DMARC is queried at _dmarc.example.com
    with patch("domain_guard.checks.dns.lookup_records") as mock_lookup:
        mock_lookup.return_value = {
            "status": "missing",
            "values": []
        }

        result = check_dns("example.com")
        mock_lookup.assert_any_call("_dmarc.example.com", "TXT")
        assert set(result["records"]) == {"A", "AAAA", "MX", "NS", "TXT"}
        assert result["spf"]["status"] == "missing"
        assert result["dmarc"]["status"] == "missing"