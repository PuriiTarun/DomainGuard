import pytest
from domain_guard.validation import is_valid_domain

@pytest.mark.parametrize("domain", ["example.com", "vealthmedia.ca", "sub.example.com", "my-website.com"])

def test_valid_domains(domain):
    assert is_valid_domain(domain) is True

@pytest.mark.parametrize("domain", ["", "localhost", "example..com", "hello_world.com", "https://example.com", "192.168.1.1", "-example.com", "example.com/"])

def test_invalid_domains(domain):
    assert is_valid_domain(domain) is False
