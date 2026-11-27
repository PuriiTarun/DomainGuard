from unittest.mock import patch
import pytest
from domain_guard.checks.dns import check_dns, lookup_records
from domain_guard.checks.email import email_observations
from domain_guard.network import check_public_dns
from domain_guard.assessment import scan_domain

def observations(kind, value):
    return email_observations(kind, {"status": "found", "values": [value]})

@pytest.mark.parametrize("value,status", [("v=spf1 +all", "warning"), ("v=spf1 all", "warning"), ("v=spf1 -all", "info"), ("v=spf1 ~all", "info"), ("v=spf1 ?all", "info"), ("v=spf1 redirect=other.com", "info")])
def test_spf_observations_are_not_full_validation(value, status):
    item = observations("spf", value)[0]
    assert item["status"] == status
    assert "evaluated" in item["message"]

@pytest.mark.parametrize("policy", ["none", "reject", "quarantine"])
def test_dmarc_policy_observed_not_verified(policy):
    item = observations("dmarc", f"v=DMARC1; p={policy};")[0]
    assert item["status"] == "info" and f"p={policy}" in item["message"]

@pytest.mark.parametrize("value", ["v=DMARC1; p=invalid", "v=DMARC1", "v=DMARC1; p=none; p=reject", "v=DMARC1; nonsense"])
def test_dmarc_uncertain_policy(value):
    assert observations("dmarc", value)[0]["status"] == "warning"

def test_dmarc_testing_mode():
    assert observations("dmarc", "v=DMARC1; p=reject; t=y")[1]["name"] == "Testing mode"

@pytest.mark.parametrize("kind,value", [("mta_sts", "v=STSv1; id=123"), ("tlsrpt", "v=TLSRPTv1; rua=mailto:reports@example.com")])
def test_transport_observation(kind, value):
    assert "not checked" in observations(kind, value)[0]["message"]
    assert email_observations(kind, {"status": "multiple", "values": [value, value]}) == []

def test_only_fixed_email_query_prefixes():
    with patch("domain_guard.checks.dns.dns.resolver.resolve", return_value=[]) as resolver:
        for name in ("_mta-sts.example.com", "_smtp._tls.example.com"):
            assert lookup_records(name, "TXT")["status"] == "missing"
        for name in ("_other.example.com", "_smtp._tls.internal", "_mta-sts._dmarc.example.com"):
            assert lookup_records(name, "TXT")["status"] == "error"
        assert lookup_records("_mta-sts.example.com", "A")["status"] == "error"
        assert resolver.call_count == 2

def test_assessment_reuses_screened_address_records():
    def resolve(domain, kind, *args):
        values = {("example.com", "A"): ["8.8.8.8"], ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=123"], ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:r@example.com"]}.get((domain, kind), [])
        return {"status": "found" if values else "missing", "values": values}
    with patch("domain_guard.network.lookup_records", side_effect=resolve) as screen, patch("domain_guard.checks.dns.lookup_records", side_effect=resolve) as dns, patch("domain_guard.assessment.check_https", return_value={"success": True, "status_code": 200, "message": "OK", "headers": {}}), patch("domain_guard.assessment.check_tls", return_value={"valid": True, "expires": "2030-01-01", "days_remaining": 30, "message": "OK"}):
        result = scan_domain("example.com")
    assert result["records"]["A"]["values"] == result["addresses"] == ["8.8.8.8"]
    assert result["mta_sts"]["status"] == result["tlsrpt"]["status"] == "found"
    assert screen.call_count == 2 and dns.call_count == 8
    assert all(call.args[1] not in ("A", "AAAA") for call in dns.call_args_list)
