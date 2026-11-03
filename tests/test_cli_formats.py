import json
import sys
from unittest.mock import patch

from rich.console import Console
from domain_guard.cli_rich import show_report
import main


def test_cli_json_is_machine_readable(capsys):
    with patch.object(sys, "argv", ["main.py", "example.com", "--format", "json"]), \
         patch("main.scan_domain", return_value={"domain": "example.com"}):
        main.main()
    assert json.loads(capsys.readouterr().out)["domain"] == "example.com"


def test_rich_unknown_checks_do_not_appear_passed():
    import io
    output = io.StringIO()
    console = Console(file=output, force_terminal=False, width=110)
    scan = {
        "domain": "example.com",
        "https": {"success": False, "message": "unavailable"},
        "tls": {"valid": False, "expires": None, "message": "unavailable"},
        "redirects": {"status": "unknown", "message": "not checked"},
        "dns": {"records": {}, "spf": {"status": "error"}, "dmarc": {"status": "missing"}},
        "headers": {"status": "unknown", "checks": {}}
    }
    show_report(scan, console)
    assert "UNKNOWN" in output.getvalue()
    assert "VERIFIED" not in output.getvalue()
