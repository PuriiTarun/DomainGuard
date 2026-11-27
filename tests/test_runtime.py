import sys
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch
import pytest
from domain_guard.runtime import RuntimeNotReady, require_runtime, runtime_issues
from domain_guard.web_api import make_server
from domain_guard.worker import main as worker_main

@pytest.mark.parametrize("installed", ["2.9.0", "2.9.2rc1", "3.0.0", "2.9.2.dev1", "bad"])
def test_runtime_rejects_unsupported_release(installed):
    with patch("domain_guard.runtime.version", side_effect=lambda name: installed if name == "dnspython" else "2.8.0"):
        with pytest.raises(RuntimeNotReady, match="dnspython"):
            require_runtime()

@pytest.mark.parametrize("installed", ["2.9.2", "2.9.2.post1", "2.10.0"])
def test_runtime_accepts_supported_stable_release(installed):
    with patch("domain_guard.runtime.version", side_effect=lambda name: installed if name == "dnspython" else "2.8.0"):
        assert runtime_issues() == []
        require_runtime()

def test_runtime_rejects_missing_and_old_dependency():
    def installed(name):
        if(name == "dnspython"):
            raise PackageNotFoundError(name)
        return "2.7.0"
    with patch("domain_guard.runtime.version", side_effect=installed):
        assert len(runtime_issues()) == 2

def test_real_scanner_refuses_old_dependencies(monkeypatch):
    monkeypatch.setenv("DOMAIN_GUARD_MODE", "local")
    with patch("domain_guard.runtime.version", return_value="2.7.0"):
        with pytest.raises(RuntimeNotReady):
            make_server(port=0, live=True)
        with make_server(port=0, live=False) as server:
            assert not server.RequestHandlerClass.live_enabled

def test_worker_entry_rejects_before_assessment(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["worker", "example.com"])
    with patch("domain_guard.runtime.version", return_value="2.7.0"), patch("domain_guard.assessment.scan_domain") as scan:
        with pytest.raises(SystemExit) as error:
            worker_main()
        assert error.value.code == 3
        scan.assert_not_called()

def test_cli_rejects_before_worker(monkeypatch):
    import main
    monkeypatch.setattr(sys, "argv", ["main.py", "example.com"])
    with patch("domain_guard.runtime.version", return_value="2.7.0"), patch.object(main, "run_scan") as scan:
        with pytest.raises(SystemExit) as error:
            main.main()
        assert error.value.code == 1
        scan.assert_not_called()

@pytest.mark.parametrize("failure", [TimeoutError(), OSError(), ValueError()])
def test_cli_reports_worker_failure(monkeypatch, capsys, failure):
    import main
    monkeypatch.setattr(sys, "argv", ["main.py", "example.com"])
    with patch.object(main, "require_runtime"), patch.object(main, "run_scan", side_effect=failure):
        with pytest.raises(SystemExit) as error:
            main.main()
        assert error.value.code == 1
    assert "Traceback" not in capsys.readouterr().err
