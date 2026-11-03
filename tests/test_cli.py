from unittest.mock import patch
import sys
import pytest
import main


def test_cli_does_not_scan_invalid_target():
    with patch.object(sys, "argv", ["main.py", "127.0.0.1"]), \
         patch("main.scan_domain", side_effect=ValueError("Invalid domain")):
        with pytest.raises(SystemExit):
            main.main()


def test_cli_prints_partial_failures(capsys):
    payload = {
        "domain": "example.com",
        "https": {"success": False, "status_code": None, "message": "unavailable"},
        "tls": {"valid": False, "message": "unavailable"},
        "dns": {"records": {}, "spf": {"status": "error"},
                "dmarc": {"status": "missing"}},
        "headers": {"status": "unknown", "checks": {}, "message": "not checked"},
        "redirects": {"status": "unknown", "message": "not checked", "location": None}
    }
    with patch.object(sys, "argv", ["main.py", "example.com"]), \
         patch("main.scan_domain", return_value=payload):
        main.main()
    output = capsys.readouterr().out
    assert "HTTPS: FAILED" in output
    assert "not checked" in output
