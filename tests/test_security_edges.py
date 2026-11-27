import json
import threading
from unittest.mock import patch, MagicMock
import pytest
from domain_guard.assessment import scan_domain
from domain_guard.scan_jobs import ScanJobs, ScanError, QUEUE_SIZE
from domain_guard.worker import run_scan
from test_web_api import call

def test_dns_query_restrictions():
    from domain_guard.checks.dns import lookup_records
    with patch("domain_guard.checks.dns.dns.resolver.resolve") as resolve:
        assert lookup_records("app.internal", "A")["status"] == "error"
        assert lookup_records("example.com", "ANY")["status"] == "error"
        assert lookup_records("_dmarc.example.com", "A")["status"] == "error"
        resolve.assert_not_called()

def test_scan_unavailable_dmarc_is_incomplete():
    dns = {"records": {"A": {"status": "found", "values": ["8.8.8.8"]}}, "spf": {"status": "missing", "values": []}, "dmarc": {"status": "error", "values": []}}
    with patch("domain_guard.assessment.check_public_dns", return_value={"safe": True, "addresses": ["8.8.8.8"]}), patch("domain_guard.assessment.check_https", return_value={"success": True, "status_code": 302, "message": "OK", "headers": {}}), patch("domain_guard.assessment.check_tls", return_value={"valid": True, "expires": "2030-01-01", "days_remaining": 30, "message": "OK"}), patch("domain_guard.assessment.check_dns", return_value=dns):
        result = scan_domain("example.com")
    assert result["status"] == "incomplete"
    assert "not followed" in result["checks"]["redirects"]["message"]

def test_scan_failure_is_not_secure():
    dns = {"records": {}, "spf": {"status": "missing", "values": []}, "dmarc": {"status": "nxdomain", "values": []}}
    with patch("domain_guard.assessment.check_public_dns", return_value={"safe": True, "addresses": ["8.8.8.8"]}), patch("domain_guard.assessment.check_https", return_value={"success": False, "status_code": None, "message": "SSL certificate verification failed"}), patch("domain_guard.assessment.check_tls", return_value={"valid": False, "expires": None, "days_remaining": None, "message": "TLS certificate verification failed"}), patch("domain_guard.assessment.check_dns", return_value=dns):
        result = scan_domain("example.com")
    assert result["checks"]["https"]["status"] == "fail"
    assert result["checks"]["tls"]["status"] == "fail"
    assert result["checks"]["headers"]["status"] == "unavailable"
    assert result["status"] == "incomplete"

@pytest.mark.parametrize("path", ["/api/scans/not-a-token", "/api/scans/" + "a" * 24, "/not-found"])
def test_disabled_routes_return_not_found(path):
    assert call("GET", path, live=False)["status"] == 404

@pytest.mark.parametrize("headers,expected", [({"Content-Type": "application/json", "Transfer-Encoding": "chunked"}, 415), ({"Content-Type": "application/json", "Content-Length": "99"}, 400), ({"Content-Type": "application/json", "Content-Length": "٠١"}, 413)])
def test_invalid_http_framing(headers, expected):
    assert call("POST", "/api/scans", headers=headers, body=b'{"domain":"example.com"}')["status"] == expected

def test_result_access_and_cancel_routes():
    jobs = ScanJobs(lambda domain: {"domain": domain})
    try:
        start = call("POST", "/api/scans", body=b'{"domain":"example.com"}', headers={"Content-Type": "application/json"}, jobs=jobs)
        path = "/api/scans/" + start["body"]["id"]
        assert call("DELETE", path, jobs=jobs)["status"] == 404
        assert call("DELETE", path, headers={"Authorization": "Bearer " + start["body"]["access_token"]}, jobs=jobs)["status"] == 200
        assert call("DELETE", "/wrong", jobs=jobs)["status"] == 404
        jobs.pending.join()
    finally:
        jobs.close()

def test_queue_capacity_and_shutdown():
    started = threading.Event()
    release = threading.Event()
    def scanner(domain, cancel):
        started.set()
        release.wait(1)
        return {"domain": domain}
    jobs = ScanJobs(scanner, cancellable=True)
    try:
        jobs.submit("first.com", "first")
        assert started.wait(1)
        for index in range(QUEUE_SIZE):
            jobs.submit(f"queued{index}.com", str(index))
        with pytest.raises(ScanError) as error:
            jobs.submit("overflow.com", "new")
        assert error.value.status == 503
    finally:
        release.set()
        jobs.close()
    with pytest.raises(ScanError):
        jobs.submit("example.com", "new")

def test_failed_worker_never_exposes_error():
    def scanner(domain):
        raise RuntimeError("private internal detail")
    jobs = ScanJobs(scanner)
    try:
        scan_id, token = jobs.submit("example.com", "local")
        jobs.pending.join()
        result = jobs.get(scan_id, token)
        assert result["status"] == "failed"
        assert "private" not in json.dumps(result)
    finally:
        jobs.close()

@pytest.mark.parametrize("returncode,output", [(1, b"error"), (0, b'{"domain":"other.com"}'), (0, b"x" * 65537)], ids=["process-error", "wrong-domain", "oversized-output"])
def test_invalid_worker_output_rejected(returncode, output):
    process = MagicMock()
    process.returncode = returncode
    process.poll.return_value = returncode
    process.stdout.read.return_value = output[:65537]
    with patch("domain_guard.worker.subprocess.Popen") as popen:
        popen.return_value.__enter__.return_value = process
        with pytest.raises(ValueError):
            run_scan("example.com", threading.Event())
