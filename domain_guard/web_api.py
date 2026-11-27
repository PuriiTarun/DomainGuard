"""Loopback-only HTTP API and static frontend for local use."""
import json
import http.client
import os
from http.server import BaseHTTPRequestHandler
import re
import threading
from urllib.parse import urlsplit

from domain_guard.scan_jobs import ScanError, ScanJobs
from domain_guard.local_server import LocalServer, BoundedInput, expire_connection, REQUEST_SECONDS
from domain_guard.worker import run_scan
from domain_guard.web_request import scan_request
from domain_guard.runtime import RuntimeNotReady, require_runtime

from domain_guard.web_assets import STATIC, ASSETS

class ApiHandler(BaseHTTPRequestHandler):
    jobs = None
    live_enabled = False
    protocol_version = "HTTP/1.1"
    allowed_host = "127.0.0.1:8000"
    server_version = "DomainGuard"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        self.rfile = BoundedInput(self.rfile)
        self.deadline = threading.Timer(REQUEST_SECONDS, expire_connection, args=(self.connection,))
        self.deadline.daemon = True
        self.deadline.start()

    def finish(self):
        try:
            super().finish()
        finally:
            self.deadline.cancel()

    def handle_one_request(self):
        try:
            super().handle_one_request()
            if(getattr(self, "headers", None) is not None):
                self.rfile.discard_body(self.headers)
        except (http.client.LineTooLong, OSError):
            self.close_connection = True

    def log_message(self, format, *args):
        # Avoid recording scan identifiers, bearer tokens, or submitted domains.
        return

    def _send(self, status, payload, content_type="application/json; charset=utf-8"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Robots-Tag", "noindex, nofollow, noarchive")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        try:
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            self.close_connection = True

    def _error(self, status, message):
        self.close_connection = True
        self._send(status, {"error": message})

    def send_error(self, code, message=None, explain=None):
        self._error(code, "Request could not be completed")

    def handle_expect_100(self):
        self._error(417, "Unsupported request expectation")
        return False

    def _route(self):
        if(self.headers.defects):
            raise ScanError(400, "Malformed request headers")
        if(self.headers.get_all("Host") != [self.allowed_host]):
            raise ScanError(403, "Invalid request host")
        origins = self.headers.get_all("Origin", [])
        if(origins and origins != [f"http://{self.allowed_host}"]):
            raise ScanError(403, "Invalid request origin")
        fetch_sites = self.headers.get_all("Sec-Fetch-Site", [])
        if(len(fetch_sites) > 1 or (fetch_sites and fetch_sites[0] not in ("same-origin", "none"))):
            raise ScanError(403, "Cross-origin request rejected")
        if(not self.path.startswith("/") or self.path.startswith("//") or len(self.path) > 256):
            raise ScanError(400, "Invalid request path")
        try:
            target = urlsplit(self.path)
        except ValueError:
            raise ScanError(400, "Invalid request path") from None
        if(target.scheme or target.netloc or "?" in self.path or "#" in self.path):
            raise ScanError(400, "Invalid request path")
        return target.path

    def _scan_id(self, path):
        scan_id = path.removeprefix("/api/scans/")
        if(self.jobs is None or not re.fullmatch(r"[A-Za-z0-9_-]{24}", scan_id)):
            raise ScanError(404, "Scan not found")
        return scan_id

    def _token(self):
        values = self.headers.get_all("Authorization", [])
        if(len(values) != 1 or not re.fullmatch(r"Bearer [A-Za-z0-9_-]{43}", values[0])):
            return ""
        return values[0][7:]

    def do_GET(self):
        try:
            path = self._route()
            if(path == "/api/health"):
                self._send(200, {"status": "ok"})
            elif(path == "/api/capabilities"):
                self._send(200, {"live_scans": self.live_enabled, "demo": True, "retention_seconds": 900})
            elif(path.startswith("/api/scans/")):
                scan_id = self._scan_id(path)
                self._send(200, self.jobs.get(scan_id, self._token()))
            elif(path in ASSETS):
                name, content_type = ASSETS[path]
                file = STATIC / name
                if(not file.is_file()):
                    raise ScanError(404, "Page not found")
                self._send(200, file.read_bytes(), content_type)
            else:
                raise ScanError(404, "Page not found")
        except ScanError as error:
            self._error(error.status, str(error))
        except (OSError, ValueError):
            self._error(500, "Request could not be completed")

    def do_POST(self):
        try:
            if(self._route() != "/api/scans"):
                raise ScanError(404, "Page not found")
            if(not self.live_enabled):
                raise ScanError(503, "Live scans are disabled")
            domain = scan_request(self.headers, self.rfile)
            scan_id, token = self.jobs.submit(domain, self.client_address[0])
            self._send(202, {"id": scan_id, "status": "queued", "access_token": token})
        except ScanError as error:
            self._error(error.status, str(error))

    def do_DELETE(self):
        try:
            path = self._route()
            if(not path.startswith("/api/scans/")):
                raise ScanError(404, "Page not found")
            scan_id = self._scan_id(path)
            self._send(200, self.jobs.cancel(scan_id, self._token()))
        except ScanError as error:
            self._error(error.status, str(error))

def make_server(*, scanner=None, host="127.0.0.1", port=8000, live=None):
    if(host != "127.0.0.1"):
        raise ValueError("DomainGuard local server must bind to loopback")
    mode = os.environ.get("DOMAIN_GUARD_MODE", "local")
    if(mode not in ("local", "demo", "production")):
        raise ValueError("Invalid mode")
    enabled = (os.environ.get("DOMAIN_GUARD_LOCAL_SCANS") == "1" if live is None else live)
    enabled = bool(enabled and mode == "local")
    default_scanner = scanner is None
    if(enabled and default_scanner):
        require_runtime()
    class Handler(ApiHandler):
        live_enabled = enabled
    server = LocalServer((host, port), Handler)
    Handler.allowed_host = f"{host}:{server.server_port}"
    Handler.jobs = ScanJobs(run_scan if default_scanner else scanner, cancellable=default_scanner) if enabled else None
    return server

def main():
    try:
        server = make_server()
    except RuntimeNotReady as error:
        raise SystemExit(str(error)) from None
    with server:
        print(f"DomainGuard local site: http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

if(__name__ == "__main__"):
    main()
