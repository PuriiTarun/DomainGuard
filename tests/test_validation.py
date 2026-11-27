import pytest
from domain_guard.validation import is_valid_domain, normalize_domain

@pytest.mark.parametrize("domain", ["example.com", "vealthmedia.ca", "sub.example.com", "my-website.com"])

def test_valid_domains(domain):
    assert is_valid_domain(domain) is True

@pytest.mark.parametrize("domain", ["", "localhost", "example..com", "hello_world.com", "https://example.com", "192.168.1.1", "-example.com", "example.com/"])

def test_invalid_domains(domain):
    assert is_valid_domain(domain) is False

@pytest.mark.parametrize("domain", [None, 42, "EXAMPLE.COM", "example.com\r\nHost: localhost", "example.com\x1b[31m", "example.com.", "xn--.com"])
def test_invalid_domain_types_and_control_characters(domain):
    assert is_valid_domain(domain) is False

def test_normalize_domain():
    assert normalize_domain("  EXAMPLE.COM  ") == "example.com"

@pytest.mark.parametrize("value", ["xn--test.com", "example.com.", "https://example.com", "x" * 64 + ".com", "éxample.com"])
def test_normalize_rejects_ambiguous_names(value):
    with pytest.raises(ValueError):
        normalize_domain(value)

@pytest.mark.parametrize("value", ["\nexample.com", "example.com\t", "\u212a.com", "\u00a0example.com", "app.internal", "app.localhost", "app.test", "app.onion"])
def test_reject_non_ascii_controls_and_local_suffixes(value):
    with pytest.raises(ValueError):
        normalize_domain(value)

@pytest.mark.parametrize("domain", ["home.arpa", "resolver.arpa", "host.localdomain", "host.alt", "host.corp", "host.intranet", "host.private", " " * 512 + "example.com"])
def test_special_names_and_oversized_raw_input(domain):
    with pytest.raises(ValueError):
        normalize_domain(domain)
