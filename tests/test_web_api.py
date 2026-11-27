import io
import json
import threading
from email.message import Message

import pytest

from domain_guard.scan_jobs import ScanError, ScanJobs
from domain_guard.web_api import ApiHandler, make_server

def call(method, path, *, body=b"", headers=None, jobs=None, live=True):
    handler = ApiHandler.__new__(ApiHandler)
    handler.path = path
    handler.headers = Message()
    if("Host" not in (headers or {})):
        handler.headers["Host"] = handler.allowed_host
    for key, value in (headers or {}).items():
        handler.headers[key] = value
    if(method == "POST" and "Content-Length" not in handler.headers):
        handler.headers["Content-Length"] = str(len(body))
    handler.rfile = io.BytesIO(body)
    handler.wfile = io.BytesIO()
    handler.jobs = jobs
    handler.live_enabled = live
    handler.client_address = ("127.0.0.1", 1234)
    response = {"headers": {}}
    handler.send_response = lambda status: response.update(status=status)
    handler.send_header = lambda key, value: response["headers"].update({key: value})
    handler.end_headers = lambda: None
    getattr(handler, "do_" + method)()
    response["body"] = json.loads(handler.wfile.getvalue())
    return response

def test_live_scan_requires_bearer_token():
    jobs = ScanJobs(lambda domain: {"domain": domain})
    start = call("POST", "/api/scans", body=b'{"domain":"EXAMPLE.COM"}',
                 headers={"Content-Type": "application/json"}, jobs=jobs)
    assert start["status"] == 202
    scan_id = start["body"]["id"]
    token = start["body"]["access_token"]
    path = "/api/scans/" + scan_id
    assert call("GET", path, jobs=jobs)["status"] == 404
    assert call("GET", path, headers={"Authorization": "Bearer wrong"}, jobs=jobs)["status"] == 404
    jobs.pending.join()
    result = call("GET", path, headers={"Authorization": "Bearer " + token}, jobs=jobs)
    assert result["status"] == 200
    assert result["body"]["domain"] == "example.com"
    assert result["body"]["result"] == {"domain": "example.com"}
    assert "access_token" not in result["body"]
    assert result["headers"]["Cache-Control"] == "no-store"
    assert result["headers"]["X-Content-Type-Options"] == "nosniff"

@pytest.mark.parametrize("body,content_type,expected", [
    (b'{"domain":"localhost"}', "application/json", 400),
    (b'{"domain":"example.com","extra":1}', "application/json", 400),
    (b'{"domain":"example.com","domain":"other.com"}', "application/json", 400),
    (b'not-json', "application/json", 400),
    (b'{"domain":"example.com"}', "text/plain", 415),
    (b'x' * 513, "application/json", 413)
])
def test_strict_input(body, content_type, expected):
    result = call("POST", "/api/scans", body=body, headers={"Content-Type": content_type},
                  jobs=ScanJobs(lambda _: pytest.fail("scanner ran")))
    assert result["status"] == expected
    assert set(result["body"]) == {"error"}

def test_disabled_scan_and_capabilities():
    assert call("GET", "/api/capabilities", live=False)["body"]["live_scans"] is False
    result = call("POST", "/api/scans", body=b'{"domain":"example.com"}', live=False)
    assert result["status"] == 503

def test_production_and_non_loopback_fail_closed(monkeypatch):
    with pytest.raises(ValueError):
        make_server(host="0.0.0.0", scanner=lambda _: None)
    class FakeServer:
        def __init__(self, address, handler):
            self.RequestHandlerClass = handler
            self.server_port = address[1]
    monkeypatch.setattr("domain_guard.web_api.LocalServer", FakeServer)
    monkeypatch.setenv("DOMAIN_GUARD_MODE", "production")
    server = make_server(scanner=lambda _: None, live=True)
    assert server.RequestHandlerClass.live_enabled is False

def test_manager_limits_and_cancel():
    release = threading.Event()
    jobs = ScanJobs(lambda domain: release.wait(2) or {"domain": domain})
    scan_id, token = jobs.submit("example.com", "client")
    with pytest.raises(ScanError) as error:
        jobs.submit("example.com", "client")
    assert error.value.status == 429
    assert jobs.cancel(scan_id, token)["status"] == "cancelled"
    release.set()
    jobs.pending.join()
    assert jobs.get(scan_id, token)["status"] == "cancelled"

def test_manager_rate_limit():
    jobs = ScanJobs(lambda domain: {"domain": domain})
    for index in range(5):
        jobs.submit(f"domain{index}.com", "same-client")
        jobs.pending.join()
    with pytest.raises(ScanError) as error:
        jobs.submit("sixth.com", "same-client")
    assert error.value.status == 429

def test_json_requires_utf8():
    result = call("POST", "/api/scans", body='{"domain":"example.com"}'.encode("utf-16"), headers={"Content-Type": "application/json"})
    assert result["status"] == 400
