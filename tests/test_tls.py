import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import pytest
from domain_guard.checks.tls import check_tls

@pytest.fixture
def tls_mocks():
    """Create mock socket and TLS connections for testing."""
    with patch("domain_guard.checks.tls.socket.create_connection") as mock_connect:
        with patch("domain_guard.checks.tls.ssl.create_default_context") as mock_context:
            tls_socket = mock_context.return_value.wrap_socket.return_value.__enter__.return_value
            yield mock_connect, mock_context, tls_socket

def test_valid_certificate(tls_mocks):
    mock_connect, mock_context, tls_socket = tls_mocks

    expiration = datetime.now(timezone.utc) + timedelta(days=60)
    tls_socket.getpeercert.return_value = {
        "notAfter": expiration.strftime("%b %d %H:%M:%S %Y GMT")
    }

    result = check_tls("example.com", ["8.8.8.8"])
    assert result["valid"] is True
    assert result["expires"] == expiration.strftime("%Y-%m-%d")
    assert 59 <= result["days_remaining"] <= 60
    assert result["message"] == "TLS certificate verified"

    # Verify the connection uses the approved IP and original hostname
    mock_connect.assert_called_once_with(("8.8.8.8", 443), timeout=5)
    mock_context.return_value.wrap_socket.assert_called_once_with(
        mock_connect.return_value.__enter__.return_value,
        server_hostname="example.com"
    )


def test_certificate_expiring_soon(tls_mocks):
    _, _, tls_socket = tls_mocks
    expiration = datetime.now(timezone.utc) + timedelta(days=10)
    tls_socket.getpeercert.return_value = {
        "notAfter": expiration.strftime("%b %d %H:%M:%S %Y GMT")
    }

    result = check_tls("example.com", ["8.8.8.8"])
    assert result["valid"] is True
    assert 0 <= result["days_remaining"] < 30


@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["8.8.8.8", "192.168.1.10"], ["not-an-ip"]])
def test_rejected_addresses(addresses):
    with patch("domain_guard.checks.tls.socket.create_connection") as mock_connect:
        result = check_tls("example.com", addresses)

    assert result["valid"] is False
    mock_connect.assert_not_called()

def test_certificate_error(tls_mocks):
    _, mock_context, _ = tls_mocks
    mock_context.return_value.wrap_socket.side_effect = ssl.SSLError()
    result = check_tls("example.com", ["8.8.8.8"])
    assert result["valid"] is False
    assert result["message"] == "TLS certificate verification failed"

def test_timeout(tls_mocks):
    mock_connect, _, _ = tls_mocks
    mock_connect.side_effect = TimeoutError()
    result = check_tls("example.com", ["8.8.8.8"])
    assert result["valid"] is False
    assert result["message"] == "TLS connection timed out"

def test_missing_certificate(tls_mocks):
    _, _, tls_socket = tls_mocks
    tls_socket.getpeercert.return_value = {}
    result = check_tls("example.com", ["8.8.8.8"])
    assert result["valid"] is False
    assert result["message"] == "Certificate information unavailable"

def test_missing_expiration(tls_mocks):
    _, _, tls_socket = tls_mocks
    tls_socket.getpeercert.return_value = {
        "subject": (("commonName", "example.com"),)
    }
    result = check_tls("example.com", ["8.8.8.8"])
    assert result["valid"] is False
    assert result["message"] == "Could not inspect the TLS certificate"

def test_connection_error(tls_mocks):
    mock_connect, _, _ = tls_mocks
    mock_connect.side_effect = OSError()
    result = check_tls("example.com", ["8.8.8.8"])
    assert result["valid"] is False
    assert result["message"] == "Could not inspect the TLS certificate"