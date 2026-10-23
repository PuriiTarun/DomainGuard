import socket
from unittest.mock import patch
import pytest
from domain_guard.network import check_public_dns

def fake_dns_result(address):
    # Create a fake DNS result for testing
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return (family, socket.SOCK_STREAM, 6, "", (address, 443))

@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111"])

def test_public_addresses(address):
    with patch("domain_guard.network.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [fake_dns_result(address)]
        result = check_public_dns("example.com")
        assert result["safe"] is True
        assert address in result["addresses"]

@pytest.mark.parametrize("address", ["127.0.0.1", "192.168.1.10", "10.0.0.5", "169.254.169.254", "100.64.1.1", "::1", "fc00::1"])

def test_non_public_addresses(address):
    with patch("domain_guard.network.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [fake_dns_result(address)]
        result = check_public_dns("example.com")
        assert result["safe"] is False

def test_mixed_addresses():
    # Reject domains with both public and private IP addresses
    addresses = [fake_dns_result("8.8.8.8"), fake_dns_result("192.168.1.10")]

    with patch("domain_guard.network.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = addresses
        result = check_public_dns("example.com")
        assert result["safe"] is False

def test_dns_error():
    with patch("domain_guard.network.socket.getaddrinfo") as mock_dns:
        mock_dns.side_effect = socket.gaierror()
        result = check_public_dns("example.com")
        assert result["safe"] is False
        assert result["message"] == "Could not resolve the domain"

def test_no_addresses():
    with patch("domain_guard.network.socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = []
        result = check_public_dns("example.com")
        assert result["safe"] is False
        assert result["addresses"] == []