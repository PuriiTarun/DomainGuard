from unittest.mock import patch

import pytest
import urllib3

from domain_guard.checks.redirects import check_http_redirect


@pytest.mark.parametrize("code", [301, 302, 307, 308])
def test_http_redirects_to_https(code):
    with patch("domain_guard.checks.redirects.urllib3.HTTPConnectionPool") as pool:
        response = pool.return_value.urlopen.return_value
        response.status = code
        response.headers = {"Location": "https://example.com/secure"}
        result = check_http_redirect("example.com", ["8.8.8.8"])
        assert result["status"] == "pass"
        assert result["http_status"] == code
        assert pool.call_args.args[0] == "8.8.8.8"
        options = pool.return_value.urlopen.call_args.kwargs
        assert options["redirect"] is False
        assert options["retries"] is False
        assert options["preload_content"] is False


@pytest.mark.parametrize("location", [
    "http://example.com/",
    "https://attacker.example/",
    "//example.com/",
    "https://example.com:8443/",
    "https://user@example.com/",
    "https://example.com:bad/"
])
def test_non_upgrading_redirects(location):
    with patch("domain_guard.checks.redirects.urllib3.HTTPConnectionPool") as pool:
        response = pool.return_value.urlopen.return_value
        response.status = 301
        response.headers = {"Location": location}
        assert check_http_redirect("example.com", ["8.8.8.8"])["status"] == "review"


@pytest.mark.parametrize("addresses", [
    [], ["127.0.0.1"], ["8.8.8.8", "192.168.1.10"], ["not-ip"]
])
def test_rejects_addresses_before_network(addresses):
    with patch("domain_guard.checks.redirects.urllib3.HTTPConnectionPool") as pool:
        result = check_http_redirect("example.com", addresses)
        assert result["status"] == "unknown"
        pool.assert_not_called()


def test_invalid_domain_rejected_before_network():
    with patch("domain_guard.checks.redirects.urllib3.HTTPConnectionPool") as pool:
        result = check_http_redirect("example.com\r\nHost:evil.example", ["8.8.8.8"])
        assert result["status"] == "unknown"
        pool.assert_not_called()


def test_http_without_redirect():
    with patch("domain_guard.checks.redirects.urllib3.HTTPConnectionPool") as pool:
        response = pool.return_value.urlopen.return_value
        response.status = 200
        response.headers = {}
        assert check_http_redirect("example.com", ["8.8.8.8"])["status"] == "review"


def test_timeout_is_unknown():
    with patch("domain_guard.checks.redirects.urllib3.HTTPConnectionPool") as pool:
        pool.return_value.urlopen.side_effect = urllib3.exceptions.ConnectTimeoutError(None, "Timed out")
        assert check_http_redirect("example.com", ["8.8.8.8"])["status"] == "unknown"
