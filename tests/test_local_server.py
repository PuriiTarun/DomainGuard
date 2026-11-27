import http.client
import json
import socket
import threading
import time
import pytest
from domain_guard.web_api import make_server
from domain_guard.scan_jobs import ScanJobs, ScanError, RESULT_TTL

@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv("DOMAIN_GUARD_MODE", "local")
    with make_server(port=0, scanner=lambda domain: {"domain": domain}, live=True) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=2)

def request(server, method, path, body=None, headers=None):
    with_client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        with_client.request(method, path, body=body, headers=headers or {})
        response = with_client.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        with_client.close()

def test_real_loopback_api_and_assets(server):
    status, headers, body = request(server, "GET", "/index.html")
    assert status == 200 and b"DomainGuard" in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["Connection"] == "close"
    for path in ("/styles.css", "/app.mjs", "/render.mjs", "/demo.mjs", "/input.mjs", "/report.mjs", "/advice.mjs"):
        assert request(server, "GET", path)[0] == 200
    assert request(server, "GET", "/AGENTS.md")[0] == 404
    status, _, body = request(server, "POST", "/api/scans", b'{"domain":"example.com"}', {"Content-Type": "application/json"})
    assert status == 202
    start = json.loads(body)
    path = "/api/scans/" + start["id"]
    server.RequestHandlerClass.jobs.pending.join()
    assert request(server, "GET", path)[0] == 404
    status, _, body = request(server, "GET", path, headers={"Authorization": "Bearer " + start["access_token"]})
    assert status == 200 and json.loads(body)["result"] == {"domain": "example.com"}

def test_rebinding_and_cross_origin_rejected(server):
    assert request(server, "GET", "/api/health", headers={"Host": "attacker.example"})[0] == 403
    assert request(server, "POST", "/api/scans", b'{"domain":"example.com"}', {"Origin": "https://outside.example", "Content-Type": "application/json"})[0] == 403
    assert request(server, "GET", "/api/health", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
    assert request(server, "GET", "http://example.com/api/health", headers={"Host": f"127.0.0.1:{server.server_port}"})[0] == 400

def test_production_and_demo_disabled(monkeypatch):
    for mode in ("production", "demo"):
        monkeypatch.setenv("DOMAIN_GUARD_MODE", mode)
        with make_server(port=0, live=True) as server:
            assert not server.RequestHandlerClass.live_enabled
            assert server.RequestHandlerClass.jobs is None

def test_expired_result_and_non_ascii_token():
    now = [0]
    jobs = ScanJobs(lambda domain: {"domain": domain}, clock=lambda: now[0])
    try:
        scan_id, token = jobs.submit("example.com", "local")
        jobs.pending.join()
        with pytest.raises(ScanError):
            jobs.get(scan_id, "é" * 43)
        now[0] = RESULT_TTL
        with pytest.raises(ScanError):
            jobs.get(scan_id, token)
    finally:
        jobs.close()

def test_guard_blocks_external_network():
    with socket.socket() as sock:
        with pytest.raises(AssertionError, match="External"):
            sock.connect(("8.8.8.8", 443))
    with pytest.raises(AssertionError, match="External"):
        socket.getaddrinfo("example.com", 443)

def test_total_request_deadline(monkeypatch):
    monkeypatch.setattr("domain_guard.web_api.REQUEST_SECONDS", 0.25)
    with make_server(port=0, live=False) as local:
        thread = threading.Thread(target=local.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", local.server_port), timeout=2) as conn:
                conn.sendall(b"GET /api/health HTTP/1.1\r\nHost: ")
                start = time.monotonic()
                assert conn.recv(1) == b""
                assert time.monotonic() - start < 1.5
            assert request(local, "GET", "/api/health")[0] == 200
        finally:
            local.shutdown()
            thread.join(timeout=2)

def test_request_headers_have_total_size_limit(server):
    headers = {"X-Long": "a" * 17000}
    assert request(server, "GET", "/api/health", headers=headers)[0] == 431

def test_oversized_request_line_closes_connection(server):
    with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as conn:
        conn.sendall(b"GET /" + b"x" * 17000 + b" HTTP/1.1\r\n\r\n")
        try:
            assert conn.recv(1) == b""
        except ConnectionResetError:
            pass
    assert request(server, "GET", "/api/health")[0] == 200

def test_self_hosted_font_is_allowed_without_external_font_access(server, monkeypatch, tmp_path):
    from domain_guard import web_api
    (tmp_path / "Geist-Variable.woff2").write_bytes(b"wOF2 fixture")
    monkeypatch.setattr(web_api, "STATIC", tmp_path)
    status, headers, body = request(server, "GET", "/Geist-Variable.woff2")
    assert status == 200 and body == b"wOF2 fixture"
    assert headers["Content-Type"] == "font/woff2"
    assert "font-src 'self'" in headers["Content-Security-Policy"]
    assert request(server, "GET", "/Geist-Variable.woff2", headers={"Sec-Fetch-Site": "cross-site"})[0] == 403
