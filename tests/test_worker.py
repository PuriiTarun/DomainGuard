import subprocess
import sys
import time
import threading
from unittest.mock import patch
import pytest
from domain_guard.worker import encode_result, run_scan, worker_environment
from domain_guard.scan_jobs import ScanJobs

def test_worker_rejects_oversized_result():
    with pytest.raises(ValueError):
        encode_result({"text": "x" * 65536})

def test_worker_does_not_inherit_secrets(monkeypatch):
    monkeypatch.setenv("PRIVATE_API_KEY", "test-value")
    monkeypatch.setenv("PYTHONPATH", "untrusted")
    assert "PRIVATE_API_KEY" not in worker_environment()
    assert "PYTHONPATH" not in worker_environment()

def test_worker_pre_cancel_no_process():
    cancel = threading.Event()
    cancel.set()
    with patch("domain_guard.worker.subprocess.Popen") as popen:
        with pytest.raises(TimeoutError):
            run_scan("example.com", cancel)
    popen.assert_not_called()

def controlled_child(monkeypatch, code):
    popen = subprocess.Popen
    children = []
    def spawn(command, **options):
        assert command[-1] == "example.com"
        assert not options.get("shell", False)
        child = popen([sys.executable, "-c", code], **options)
        children.append(child)
        return child
    monkeypatch.setattr("domain_guard.worker.subprocess.Popen", spawn)
    return children

def test_worker_returns_valid_result(monkeypatch):
    result = {"domain": "example.com", "schema_version": 1, "status": "complete", "addresses": [], "checks": {}, "records": {}}
    import json
    children = controlled_child(monkeypatch, f"print({json.dumps(result)!r})")
    assert run_scan("example.com", threading.Event()) == result
    assert children[0].returncode == 0

def test_worker_cancel_kills_process(monkeypatch):
    children = controlled_child(monkeypatch, "import time; time.sleep(10)")
    cancel = threading.Event()
    timer = threading.Timer(0.1, cancel.set)
    timer.start()
    try:
        with pytest.raises(TimeoutError):
            run_scan("example.com", cancel)
        assert children[0].poll() is not None
    finally:
        timer.cancel()

@pytest.mark.parametrize("code", ["import sys; sys.stdout.write('x' * 1000000); sys.stdout.flush()", "import sys; sys.exit(2)", "print('not json')", "print('{\"domain\":\"other.com\"}')"])
def test_invalid_child_output_is_rejected(monkeypatch, code):
    children = controlled_child(monkeypatch, code)
    with pytest.raises(ValueError):
        run_scan("example.com", threading.Event())
    assert children[0].poll() is not None

def test_manager_propagates_cancel_to_worker():
    started = threading.Event()
    done = threading.Event()
    def scanner(domain, cancel):
        started.set()
        if(cancel.wait(1)):
            done.set()
        return {"domain": domain}
    jobs = ScanJobs(scanner, cancellable=True)
    try:
        scan_id, token = jobs.submit("example.com", "local")
        assert started.wait(1)
        assert jobs.cancel(scan_id, token)["status"] == "cancelled"
        assert done.wait(1)
        jobs.pending.join()
        assert jobs.get(scan_id, token)["status"] == "cancelled"
    finally:
        jobs.close()

def test_real_controlled_child_is_killed_on_deadline():
    import sys
    import time
    popen = subprocess.Popen
    children = []
    def spawn(command, **options):
        child = popen([sys.executable, "-c", "import time; time.sleep(10)"], **options)
        children.append(child)
        return child
    start = time.monotonic()
    with patch("domain_guard.worker.WORKER_SECONDS", 0.2), patch("domain_guard.worker.subprocess.Popen", side_effect=spawn):
        with pytest.raises(TimeoutError):
            run_scan("example.com", threading.Event())
    assert children[0].poll() is not None
    assert time.monotonic() - start < 5

@pytest.mark.parametrize("value", [{"domain": "example.com"}, {"domain": "example.com", "schema_version": 2}, {"domain": "example.com", "schema_version": 1, "status": "unknown"}, {"domain": "example.com", "schema_version": 1, "status": "complete", "addresses": [], "checks": {}, "records": {}, "bad": float("nan")}])
def test_worker_rejects_invalid_report_contract(monkeypatch, value):
    import json
    controlled_child(monkeypatch, f"print({json.dumps(value)!r})")
    with pytest.raises(ValueError):
        run_scan("example.com", threading.Event())
