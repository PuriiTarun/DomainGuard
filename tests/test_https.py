from unittest.mock import patch
import requests
from domain_guard.checks.https import check_https

def test_https_success():
    # Simulate a website that returns HTTP 200
    with patch("domain_guard.checks.https.requests.get") as mock_get:
        mock_get.return_value.__enter__.return_value.status_code = 200
        result = check_https("example.com")
        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["message"] == "HTTPS connection successful"

def test_ssl_error():
    # Simulate an invalid SSL certificate
    with patch("domain_guard.checks.https.requests.get") as mock_get:
        mock_get.side_effect = requests.exceptions.SSLError()
        result = check_https("example.com")
        assert result["success"] is False
        assert result["status_code"] is None
        assert result["message"] == "SSL certificate verification failed"

def test_timeout():
    # Simulate a connection timeout
    with patch("domain_guard.checks.https.requests.get") as mock_get:
        mock_get.side_effect = requests.exceptions.Timeout()
        result = check_https("example.com")
        assert result["success"] is False
        assert result["message"] == "Connection timed out"

def test_connection_error():
    # Simulate a failed connection
    with patch("domain_guard.checks.https.requests.get") as mock_get:
        mock_get.side_effect = requests.exceptions.ConnectionError()
        result = check_https("example.com")
        assert result["success"] is False
        assert result["message"] == "Could not connect to the website"