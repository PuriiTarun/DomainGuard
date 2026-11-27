"""Hostile input tests against the real local HTTP interface, with a fake scanner."""
import json
import threading
import http.client
import socket
import pytest
from domain_guard.web_api import make_server

@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setenv("DOMAIN_GUARD_MODE", "local")
    calls = []
    def scanner(domain):
        calls.append(domain)
        return {"domain": domain, "status": "complete"}
    with make_server(port=0, scanner=scanner, live=True) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server, calls
        finally:
            server.shutdown()
            thread.join(timeout=2)

def request(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()

@pytest.mark.parametrize("payload", ["example.com' OR '1'='1", "example.com;whoami", "example.com|echo injected", "<script>alert(1)</script>", "example.com\r\nX-Test: injected", "http://127.0.0.1/", "169.254.169.254", "[::1]", "example.com@localhost", "example.com:22", "../example.com", "host.internal", "example.com\x00"])
def test_malicious_domain_never_reaches_scanner(endpoint, payload):
    server, calls = endpoint
    status, headers, body = request(server, "POST", "/api/scans", json.dumps({"domain": payload}), {"Content-Type": "application/json"})
    assert status == 400
    assert json.loads(body) == {"error": "Invalid domain"}
    assert headers["Cache-Control"] == "no-store"
    assert calls == []

@pytest.mark.parametrize("path", ["/../../README.md", "/%2e%2e/README.md", "/.git/config", "/AGENTS.md", "/requirements.txt", "/domain_guard/worker.py", "/%2Fprivacy.html"])
def test_private_files_not_served(endpoint, path):
    server, _ = endpoint
    assert request(server, "GET", path)[0] == 404

@pytest.mark.parametrize("headers", [{"Origin": "null"}, {"Origin": "https://attacker.invalid"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}, {"Host": "attacker.invalid"}])
def test_browser_origin_and_host_boundaries(endpoint, headers):
    server, calls = endpoint
    status, _, _ = request(server, "POST", "/api/scans", '{"domain":"example.com"}', {"Content-Type": "application/json", **headers})
    assert status == 403
    assert calls == []

def test_private_results_and_wrong_token_cannot_cancel(endpoint):
    server, calls = endpoint
    status, _, body = request(server, "POST", "/api/scans", '{"domain":"example.com"}', {"Content-Type": "application/json"})
    assert status == 202
    start = json.loads(body)
    path = "/api/scans/" + start["id"]
    for method in ("GET", "DELETE"):
        assert request(server, method, path, headers={"Authorization": "Bearer " + "a" * 43})[0] == 404
    server.RequestHandlerClass.jobs.pending.join()
    status, headers, body = request(server, "GET", path, headers={"Authorization": "Bearer " + start["access_token"]})
    assert status == 200 and calls == ["example.com"]
    assert start["access_token"].encode() not in body
    assert headers["Cache-Control"] == "no-store"

def test_duplicate_fetch_metadata_rejected(endpoint):
    server, calls = endpoint
    body = b'{"domain":"example.com"}'
    with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as conn:
        header = f"POST /api/scans HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-Site: cross-site\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        conn.sendall(header + body)
        assert b"403" in conn.recv(1024).split(b"\r\n", 1)[0]
    assert calls == []

@pytest.mark.parametrize("path", ["/", "/privacy.html", "/terms.html", "/action-plan.mjs"])
def test_new_public_assets_security_headers(endpoint, path):
    server, _ = endpoint
    status, headers, body = request(server, "GET", path)
    assert status == 200 and body
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "noindex" in headers["X-Robots-Tag"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert "Set-Cookie" not in headers

def test_rejected_body_can_arrive_after_response_headers(endpoint):
    server, calls = endpoint
    body = b'{"domain":"example.com"}'
    with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as conn:
        header = f"POST /api/scans HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nOrigin: https://attacker.invalid\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n".encode()
        conn.sendall(header + body[:1])
        response = http.client.HTTPResponse(conn)
        response.begin()
        assert response.status == 403
        assert json.loads(response.read()) == {"error": "Invalid request origin"}
        conn.sendall(body[1:])
        assert conn.recv(1) == b""
    assert calls == []
    assert request(server, "GET", "/api/health")[0] == 200

def test_rejected_body_drain_obeys_absolute_deadline(monkeypatch):
    monkeypatch.setenv("DOMAIN_GUARD_MODE", "local")
    monkeypatch.setattr("domain_guard.web_api.REQUEST_SECONDS", 0.4)
    with make_server(port=0, live=False) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", server.server_port), timeout=2) as conn:
                header = f"POST /api/scans HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nOrigin: https://attacker.invalid\r\nContent-Length: 20\r\n\r\n".encode()
                conn.sendall(header)
                response = http.client.HTTPResponse(conn)
                response.begin()
                assert response.status == 403
                assert response.read()
                assert conn.recv(1) == b""
            assert request(server, "GET", "/api/health")[0] == 200
        finally:
            server.shutdown()
            thread.join(timeout=2)
