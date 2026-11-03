from unittest.mock import patch
from fastapi.testclient import TestClient
from api.app import app, RateLimiter

client = TestClient(app)


def fake_scan(domain):
    return {
        "domain": domain,
        "scanned_at": "2026-11-03T08:00:00+00:00",
        "network": {"safe": True, "addresses": ["8.8.8.8"], "message": "Public"},
        "https": {"success": True, "status_code": 200, "message": "Connected", "headers": {}},
        "tls": {"valid": True, "expires": "2026-12-03", "days_remaining": 30, "message": "Verified"},
        "dns": {"records": {"A": {"status": "found", "values": ["8.8.8.8"]}},
                "spf": {"status": "missing", "values": []},
                "dmarc": {"status": "error", "values": []}},
        "headers": {"status": "checked", "checks": {}, "message": "Reviewed"},
        "redirects": {"status": "unknown", "http_status": None,
                      "location": None, "message": "Unknown"}
    }


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_scan_response_is_typed_and_uses_scanner():
    with patch("api.app.scan_domain", side_effect=fake_scan) as scanner:
        response = client.post("/api/v1/scans", json={"domain": "EXAMPLE.COM"})
    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert response.json()["dns"]["dmarc"]["status"] == "error"
    scanner.assert_called_once_with("example.com")


def test_invalid_target_never_calls_scanner():
    with patch("api.app.scan_domain") as scanner:
        response = client.post("/api/v1/scans", json={"domain": "127.0.0.1"})
    assert response.status_code == 422
    scanner.assert_not_called()


def test_unknown_fields_are_rejected():
    response = client.post("/api/v1/scans", json={
        "domain": "example.com", "url": "http://127.0.0.1/"
    })
    assert response.status_code == 422


def test_rate_limit_is_bounded():
    limiter = RateLimiter(max_requests=2, window_seconds=60)
    assert limiter.allow("local")
    assert limiter.allow("local")
    assert limiter.allow("local") is False


def test_untrusted_host_is_rejected():
    response = client.get("/health", headers={"host": "other.example"})
    assert response.status_code == 400


def test_cors_is_not_wildcard():
    result = client.options("/api/v1/scans", headers={
        "origin": "https://attacker.example",
        "access-control-request-method": "POST"
    })
    assert result.headers.get("access-control-allow-origin") is None
