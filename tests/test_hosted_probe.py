import unittest
from unittest.mock import patch

from domain_guard.hosted_probe import MAX_HEADERS, parse_response, read_headers, screened_ipv4, probe

class HostedProbeTests(unittest.TestCase):
    def test_public_ipv4_only(self):
        self.assertEqual(screened_ipv4("8.8.8.8"), "8.8.8.8")
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "0.0.0.0", "::1", "::ffff:8.8.8.8", "8.8.8.8%eth0", "example.com"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                screened_ipv4(address)

    def test_parse_headers_and_duplicates(self):
        status, headers = parse_response(b"HTTP/1.1 302 Found\r\nLocation: /home\r\nLocation: /other\r\n\r\n")
        self.assertEqual(status, 302)
        self.assertEqual(headers.getlist("Location"), ["/home", "/other"])
        self.assertEqual(headers.getlist("Absent"), [])

    def test_reject_malformed_and_oversized(self):
        for raw in (b"HTTP/1.1 100 Continue\r\n\r\n", b"HTTP/1.1 200 OK\r\nBroken\r\n\r\n", b"HTTP/1.1 200 OK\r\nX-Test: value\r\n continued\r\n\r\n", b"HTTP/1.1 200 OK\r\nX: \x00\r\n\r\n", b"x" * (MAX_HEADERS + 1)):
            with self.subTest(raw=raw[:60]), self.assertRaises(ValueError):
                parse_response(raw)

    def test_read_only_headers(self):
        class Stream:
            def __init__(self):
                self.data = bytearray(b"HTTP/1.1 200 OK\r\nX-Test: value\r\n\r\nBODY")
            def recv(self, length):
                part = self.data[:length]
                del self.data[:length]
                return bytes(part)
        stream = Stream()
        self.assertEqual(read_headers(stream)[0], 200)
        self.assertEqual(stream.data, b"BODY")

    def test_invalid_input_does_not_open_socket(self):
        with patch("domain_guard.hosted_probe.socket.socket") as connect:
            for domain, address in (("https://example.com", "8.8.8.8"), ("example.com", "127.0.0.1")):
                with self.assertRaises(ValueError):
                    probe(domain, address)
            connect.assert_not_called()

    def test_connection_failure_is_incomplete(self):
        with patch("domain_guard.hosted_probe.socket.socket", side_effect=OSError):
            result = probe("example.com", "8.8.8.8")
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(all(value["status"] == "unavailable" for value in result["checks"].values()))

if(__name__ == "__main__"):
    unittest.main()
