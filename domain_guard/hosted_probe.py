import io
import ipaddress
import json
import re
import signal
import socket
import ssl
import sys
from datetime import datetime, timezone
from http.client import parse_headers

from domain_guard.checks.headers import collect_headers, check_headers
from domain_guard.checks.redirects import observe_redirect
from domain_guard.validation import normalize_domain

MAX_HEADERS = 16384
SCAN_SECONDS = 8
SPECIAL = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "192.0.0.0/24", "192.88.99.0/24", "198.18.0.0/15"
))

def screened_ipv4(value):
    # IPv6 is deferred until the cloud firewall supports a verified /128 policy.
    if(not isinstance(value, str)):
        raise ValueError("Invalid destination")
    address = ipaddress.IPv4Address(value)
    if(not address.is_global or address.is_multicast or address.is_reserved or
       any(address in network for network in SPECIAL)):
        raise ValueError("Non-public destination")
    return str(address)

class HeaderValues:
    def __init__(self, headers):
        self.headers = headers

    def getlist(self, name):
        return self.headers.get_all(name, [])

def parse_response(raw):
    if(len(raw) > MAX_HEADERS or not raw.endswith(b"\r\n\r\n")):
        raise ValueError("Invalid or oversized response headers")
    first, fields = raw.split(b"\r\n", 1)
    status = re.fullmatch(rb"HTTP/1\.[01] ([2-5][0-9]{2})(?: [\x20-\x7e]*)?", first)
    if(not status):
        raise ValueError("Unsupported HTTP response")
    for line in fields[:-4].split(b"\r\n") if fields != b"\r\n" else []:
        if(not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x09\x20-\x7e\x80-\xff]*", line)):
            raise ValueError("Malformed HTTP header")
    headers = parse_headers(io.BytesIO(fields))
    if(headers.defects):
        raise ValueError("Malformed HTTP response")
    return int(status.group(1)), HeaderValues(headers)

def read_headers(connection):
    raw = bytearray()
    while(len(raw) < MAX_HEADERS):
        value = connection.recv(1)
        if(not value):
            break
        raw.extend(value)
        if(raw.endswith(b"\r\n\r\n")):
            return parse_response(bytes(raw))
    raise ValueError("Response headers incomplete or oversized")

def deadline(signum, frame):
    raise TimeoutError("Probe deadline reached")

def probe(domain, address):
    domain = normalize_domain(domain)
    address = screened_ipv4(address)
    skipped = {"status": "unavailable", "message": "Check could not be completed"}
    checks = {key: skipped.copy() for key in ("https", "tls", "headers", "redirects")}
    # This Linux worker runs once per sandbox; an absolute deadline covers slow trickles.
    previous = signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, SCAN_SECONDS)
    try:
        context = ssl.create_default_context()
        context.hostname_checks_common_name = False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(4)
            connection.connect((address, 443))
            with context.wrap_socket(connection, server_hostname=domain) as tls:
                certificate = tls.getpeercert()
                expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc)
                now = datetime.now(timezone.utc)
                checks["tls"] = {"status": "pass", "message": "TLS certificate and hostname verified", "expires": expiry.strftime("%Y-%m-%d"), "days_remaining": (expiry - now).days}
                # HEAD only, no body download, credentials, redirects or additional paths.
                request = f"HEAD / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: DomainGuard/0.2\r\nConnection: close\r\n\r\n"
                tls.sendall(request.encode("ascii"))
                status, headers = read_headers(tls)
                checks["https"] = {"status": "pass", "message": "Verified HTTPS HEAD response received", "status_code": status}
                checks["headers"] = check_headers(collect_headers(headers))
                checks["headers"]["message"] = "Security header observations from one HTTPS HEAD response; GET responses can differ"
                checks["redirects"] = observe_redirect(domain, status, headers)
    except ssl.SSLCertVerificationError:
        checks["tls"] = {"status": "fail", "message": "TLS certificate verification failed"}
        checks["https"] = {"status": "fail", "message": "HTTPS certificate verification failed"}
    except (OSError, ValueError, KeyError):
        pass
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    status = "incomplete" if any(item["status"] in ("unavailable", "incomplete") for item in checks.values()) else "complete"
    return {"domain": domain, "schema_version": 1, "scope": "hosted-web-probe", "status": status, "addresses": [address], "checks": checks, "records": {}}

def main():
    if(len(sys.argv) != 3):
        raise SystemExit(2)
    try:
        result = probe(sys.argv[1], sys.argv[2])
    except ValueError:
        raise SystemExit(2) from None
    payload = json.dumps(result, ensure_ascii=True, allow_nan=False)
    if(len(payload) > 16384):
        raise SystemExit(3)
    print(payload)

if(__name__ == "__main__"):
    main()
