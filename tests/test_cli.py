import importlib
import json
import pytest
import sys
from unittest.mock import patch

def test_import_does_not_run_checks():
    with patch("domain_guard.assessment.scan_domain", side_effect=AssertionError("scan started")):
        importlib.import_module("main")

def test_cli_escapes_dns_output(capsys):
    import main
    result = {
        "status": "incomplete", "addresses": ["93.184.215.14"],
        "checks": {"https": {"status": "pass", "status_code": 200, "message": "OK"}, "tls": {"status": "unavailable", "message": "unavailable"}},
        "records": {"A": {"status": "found", "values": ["ok\x1b[31m"]}},
        "spf": {"status": "found", "values": ["v=spf1\x1b[31m"]},
        "dmarc": {"status": "missing", "values": []}
    }
    with patch.object(sys, "argv", ["main.py", "EXAMPLE.COM"]), patch.object(main, "require_runtime"), patch.object(main, "run_scan", return_value=result) as scan:
        main.main()
    assert scan.call_count == 1
    assert scan.call_args.args[0] == "example.com"
    output = capsys.readouterr().out
    assert "Target: example.com" in output
    assert "\x1b" not in output
    assert "ok?[31m" in output
    assert "Assessment: incomplete" in output

@pytest.mark.parametrize("status,exit_code", [("complete", 0), ("incomplete", 1), ("rejected", 2)])
def test_cli_json_report(monkeypatch, capsys, status, exit_code):
    import main
    monkeypatch.setattr(sys, "argv", ["main.py", "--json", "example.com"])
    result = {"domain": "example.com", "status": status, "addresses": [], "checks": {}, "records": {}}
    with patch.object(main, "require_runtime"), patch.object(main, "run_scan", return_value=result):
        if(exit_code):
            with pytest.raises(SystemExit) as error:
                main.main()
            assert error.value.code == exit_code
        else:
            main.main()
    assert json.loads(capsys.readouterr().out) == result
