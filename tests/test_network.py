from unittest.mock import patch
import pytest
from domain_guard.network import check_public_dns, is_public_address, MAX_ADDRESSES, validate_addresses

def lookup(a=None, aaaa=None):
    def resolve(domain, kind, lifetime):
        values = a if kind == "A" else aaaa
        return {"status": "found" if values else "missing", "values": values or []}
    return resolve

@pytest.mark.parametrize("a,aaaa", [(["8.8.8.8"], None), (None, ["2606:4700:4700::1111"]), (["8.8.8.8"], ["2606:4700:4700::1111"])])
def test_public_addresses(a, aaaa):
    with patch("domain_guard.network.lookup_records", side_effect=lookup(a, aaaa)) as resolve:
        result = check_public_dns("example.com")
    assert result["safe"] is True
    assert set(result["addresses"]) == set((a or []) + (aaaa or []))
    assert [call.args[1] for call in resolve.call_args_list] == ["A", "AAAA"]
    assert all(0 < call.args[2] <= 5 for call in resolve.call_args_list)

@pytest.mark.parametrize("address", ["127.0.0.1", "192.168.1.10", "10.0.0.5", "169.254.169.254", "100.64.1.1", "::1", "fc00::1", "224.0.0.1", "239.255.255.250", "ff02::1", "ff0e::1", "240.0.0.1", "64:ff9b::808:808", "64:ff9b:1::808:808", "2002:c000:0201::", "2001::c000:201", "::ffff:8.8.8.8", "2001:db8::1", "3fff::1", "2606:4700::1%eth0", None, 134744072])
def test_non_public_addresses(address):
    assert is_public_address(address) is False

def test_mixed_addresses():
    with patch("domain_guard.network.lookup_records", side_effect=lookup(["8.8.8.8"], ["::1"])):
        assert check_public_dns("example.com")["safe"] is False

@pytest.mark.parametrize("status", ["error", "incomplete", "nxdomain"])
def test_dns_errors_fail_closed(status):
    with patch("domain_guard.network.lookup_records", side_effect=[{"status": "found", "values": ["8.8.8.8"]}, {"status": status, "values": []}]):
        assert check_public_dns("example.com")["safe"] is False

def test_no_addresses():
    with patch("domain_guard.network.lookup_records", side_effect=lookup()):
        result = check_public_dns("example.com")
    assert result["safe"] is False
    assert result["addresses"] == []

def test_invalid_domain_does_not_resolve():
    with patch("domain_guard.network.lookup_records") as resolve:
        assert check_public_dns("localhost")["safe"] is False
        resolve.assert_not_called()

@pytest.mark.parametrize("answer", ["invalid", "::1", "2606:4700::1", None, 134744072])
def test_malformed_dns_answer_fails_closed(answer):
    with patch("domain_guard.network.lookup_records", side_effect=lookup([answer])):
        assert check_public_dns("example.com")["safe"] is False

def test_excessive_address_answers_rejected():
    with patch("domain_guard.network.lookup_records", side_effect=lookup(["8.8.8.8"] * (MAX_ADDRESSES + 1))):
        assert check_public_dns("example.com")["safe"] is False

def test_expired_deadline_does_not_resolve():
    with patch("domain_guard.network.lookup_records") as resolve:
        assert check_public_dns("example.com", deadline=0)["status"] == "incomplete"
        resolve.assert_not_called()

def test_address_list_validation():
    for addresses in (None, "8.8.8.8", [], ["8.8.8.8", "ff02::1"], ["8.8.8.8"] * 33):
        assert not validate_addresses(addresses)
    assert validate_addresses(["8.8.8.8"])

@pytest.mark.parametrize("address", ["192.0.0.9", "192.0.0.10", "192.88.99.1", "198.18.0.1"])
def test_special_ipv4_ranges_rejected(address):
    from domain_guard.network import is_public_address
    assert not is_public_address(address)

@pytest.mark.parametrize("answer", [None, {}, {"status": "found", "values": None}, {"status": "missing", "values": ["8.8.8.8"]}, {"status": "found", "values": []}])
def test_inconsistent_lookup_contract_rejected(answer):
    with patch("domain_guard.network.lookup_records", return_value=answer):
        assert not check_public_dns("example.com")["safe"]
