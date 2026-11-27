import socket
import ssl
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from domain_guard.checks.https import check_https
from domain_guard.checks.tls import check_tls

HOST = "example.com"
APPROVED_IP = "8.8.8.8"
START = datetime(2020, 1, 1, tzinfo=timezone.utc)
END = datetime(2050, 1, 1, tzinfo=timezone.utc)

def name(value):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])

def certificate(subject, issuer, key, signer, ca=False, end=END, san=True):
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(START).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                            data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                                            crl_sign=ca, encipher_only=None, decipher_only=None), critical=True))
    if(not ca):
        if(san):
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return builder.sign(signer, hashes.SHA256())

@pytest.fixture
def endpoint(tmp_path, request):
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = certificate(name("Controlled test CA"), name("Controlled test CA"), root_key, root_key, ca=True)
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate(name(HOST), root.subject, key, root_key, san=getattr(request, "param", True))
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    sni = []
    hosts = []
    server_context.set_servername_callback(lambda sock, server_name, ctx: sni.append(server_name))
    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                pass
        def do_GET(self):
            hosts.append(self.headers.get("Host"))
            self.send_response(200)
            self.send_header("Strict-Transport-Security", "max-age=31536000")
            self.send_header("Content-Length", "0")
            self.end_headers()
        def log_message(self, *args):
            pass
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        trusted = ssl.create_default_context(cadata=root.public_bytes(serialization.Encoding.PEM).decode("ascii"))
        untrusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        try:
            yield server.server_port, trusted, untrusted, sni, hosts
        finally:
            server.shutdown()
            thread.join(timeout=2)

def connect_local(port):
    connect = socket.create_connection
    def controlled(address, timeout=None, *args, **kwargs):
        assert address == (APPROVED_IP, 443)
        return connect(("127.0.0.1", port), timeout=timeout)
    return controlled

@pytest.mark.parametrize("domain,trust,expected", [(HOST, True, True), ("other.com", True, False), (HOST, False, False)])
def test_real_tls_verification(endpoint, domain, trust, expected):
    port, trusted, untrusted, sni, _ = endpoint
    with patch("domain_guard.checks.tls.socket.create_connection", side_effect=connect_local(port)), patch("domain_guard.checks.tls.ssl.create_default_context", return_value=trusted if trust else untrusted):
        result = check_tls(domain, [APPROVED_IP], timeout=2)
    assert result["valid"] is expected
    assert sni == [domain]
    if(expected):
        assert result["expires"] == "2050-01-01"
    else:
        assert result["message"] == "TLS certificate verification failed"

@pytest.mark.parametrize("domain,trust,expected", [(HOST, True, True), ("other.com", True, False), (HOST, False, False)])
def test_real_https_verification(endpoint, domain, trust, expected):
    port, trusted, untrusted, sni, hosts = endpoint
    with patch("urllib3.util.connection.create_connection", side_effect=connect_local(port)), patch("domain_guard.checks.https.ssl.create_default_context", return_value=trusted if trust else untrusted):
        result = check_https(domain, [APPROVED_IP], timeout=2)
    assert result["success"] is expected
    assert sni == [domain]
    if(expected):
        assert hosts == [HOST]
        assert result["status_code"] == 200
        assert result["headers"]["Strict-Transport-Security"] == ["max-age=31536000"]
    else:
        assert hosts == []

@pytest.mark.parametrize("endpoint", [False], indirect=True)
@pytest.mark.parametrize("check", [check_tls, check_https])
def test_common_name_only_certificate_is_rejected(endpoint, check):
    port, trusted, _, _, _ = endpoint
    target = "domain_guard.checks.tls.socket.create_connection" if check == check_tls else "urllib3.util.connection.create_connection"
    with patch(target, side_effect=connect_local(port)), patch("ssl.create_default_context", return_value=trusted):
        result = check(HOST, [APPROVED_IP], timeout=2)
    assert not result.get("valid", result.get("success"))
    assert "certificate verification failed" in result["message"].lower()
