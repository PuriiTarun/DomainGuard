from unittest.mock import patch
import pytest
from urllib3._collections import HTTPHeaderDict
from domain_guard.results import bound_report, MAX_RESULT_BYTES, serialize
from domain_guard.checks.redirects import observe_redirect
from domain_guard.assessment import scan_domain

@pytest.mark.parametrize("location,status,fragment", [
    ("/next", "info", "relative reference"), ("https://example.com/", "info", "requested hostname"),
    ("https://other.com/", "info", "another hostname"), ("//other.com/", "info", "another hostname"),
    ("http://example.com/", "warning", "HTTP"), ("https://127.0.0.1/", "warning", "hostname"),
    ("https://name@example.com/", "warning", "credentials"), ("https://example.com:8443/", "warning", "port"),
    ("https://[broken", "warning", "parsed"), ("https:/path", "warning", "hostname"),
    ("javascript:alert(1)", "warning", "scheme"), ("///example.com", "warning", "hostname"),
    ("/x\r\n", "warning", "malformed"), ("/x\\y", "warning", "malformed"), ("/" + "x" * 2048, "warning", "malformed")])
def test_redirect_observation_never_connects(location, status, fragment):
    result = observe_redirect("example.com", 302, HTTPHeaderDict({"Location": location}))
    assert result["status"] == status
    assert fragment in result["message"] and "not followed" in result["message"]
    assert "alert(1)" not in result["message"]

def test_redirect_missing_or_multiple_locations():
    assert observe_redirect("example.com", 301, HTTPHeaderDict())["status"] == "warning"
    headers = HTTPHeaderDict()
    headers.add("Location", "/one")
    headers.add("Location", "/two")
    assert observe_redirect("example.com", 301, headers)["status"] == "warning"
    assert observe_redirect("example.com", 200, headers)["status"] == "info"

def test_oversized_report_keeps_bounded_data_and_marks_incomplete():
    def record():
        return {"status": "found", "values": ["\U0001f600" * 512] * 15}
    report = {"domain": "example.com", "status": "complete", "addresses": ["8.8.8.8"], "records": {"TXT": record(), "MX": record()}, "checks": {}, "spf": record()}
    result = bound_report(report)
    assert len(serialize(result)) <= MAX_RESULT_BYTES
    assert result["status"] == "incomplete"
    assert result["records"]["TXT"]["values"]
    for lookup in [*result["records"].values(), result["spf"]]:
        assert lookup["status"] == "incomplete" and "omitted" in lookup["message"]

def test_small_report_unchanged():
    report = {"domain": "example.com", "status": "complete", "addresses": [], "checks": {}, "records": {}}
    assert bound_report(report) is report

def test_last_resort_report_bound():
    report = {"domain": "example.com", "status": "complete", "addresses": ["8.8.8.8"], "records": {}, "checks": {"unexpected": "x" * 70000}}
    result = bound_report(report)
    assert len(serialize(result)) < MAX_RESULT_BYTES
    assert result["checks"]["output"]["status"] == "incomplete"
