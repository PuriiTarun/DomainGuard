from unittest.mock import patch
import pytest
import urllib3
from domain_guard.checks.https import check_https

@pytest.mark.parametrize("status_code", [200, 403])
def test_https_success(status_code):
    # Simulate a successful HTTPS connection
    with patch("domain_guard.checks.https.urllib3.HTTPSConnectionPool") as mock_pool:
        mock_pool.return_value.urlopen.return_value.status = status_code
        result = check_https("example.com", ["8.8.8.8"])
        assert result["success"] is True
        assert result["status_code"] == status_code
        assert result["message"] == "HTTPS connection successful"

        # Verify the connection uses the approved IP and original hostname
        assert mock_pool.call_args.args[0] == "8.8.8.8"
        assert mock_pool.call_args.kwargs["server_hostname"] == "example.com"
        assert mock_pool.call_args.kwargs["assert_hostname"] == "example.com"
        options = mock_pool.return_value.urlopen.call_args.kwargs
        assert options["headers"]["Host"] == "example.com"
        assert options["redirect"] is False
        assert options["preload_content"] is False
        assert options["retries"] is False

@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["8.8.8.8", "192.168.1.10"], ["invalid-ip"]])
def test_rejected_addresses(addresses):
    # Reject missing, private, or invalid IP addresses
    with patch("domain_guard.checks.https.urllib3.HTTPSConnectionPool") as mock_pool:
        result = check_https("example.com", addresses)
        assert result["success"] is False
        assert result["status_code"] is None
        mock_pool.assert_not_called()

def test_ssl_error():
    # Simulate a TLS certificate verification failure
    with patch("domain_guard.checks.https.urllib3.HTTPSConnectionPool") as mock_pool:
        mock_pool.return_value.urlopen.side_effect = urllib3.exceptions.SSLError(
            "Certificate verification failed"
        )
        result = check_https("example.com", ["8.8.8.8"])
        assert result["success"] is False
        assert result["status_code"] is None
        assert result["message"] == "SSL certificate verification failed"

def test_timeout():
    # Simulate a connection timeout
    with patch("domain_guard.checks.https.urllib3.HTTPSConnectionPool") as mock_pool:
        mock_pool.return_value.urlopen.side_effect = (
            urllib3.exceptions.ConnectTimeoutError(None, "Connection timed out")
        )
        result = check_https("example.com", ["8.8.8.8"])
        assert result["success"] is False
        assert result["status_code"] is None
        assert result["message"] == "Connection timed out"

def test_connection_error():
    # Simulate a failed connection
    with patch("domain_guard.checks.https.urllib3.HTTPSConnectionPool") as mock_pool:
        mock_pool.return_value.urlopen.side_effect = (
            urllib3.exceptions.NewConnectionError(None, "Connection failed")
        )
        result = check_https("example.com", ["8.8.8.8"])
        assert result["success"] is False
        assert result["status_code"] is None
        assert result["message"] == "Could not connect to the website"