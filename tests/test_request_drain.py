import io
from email.message import Message
import pytest
from domain_guard.local_server import BoundedInput, MAX_BODY_BYTES

def headers(*pairs):
    result = Message()
    for name, value in pairs:
        result[name] = value
    return result

def test_discard_consumes_only_unread_body():
    stream = io.BytesIO(b"header\nabcNEXT")
    bounded = BoundedInput(stream)
    assert bounded.readline() == b"header\n"
    assert bounded.read(1) == b"a"
    bounded.discard_body(headers(("Content-Length", "3")))
    assert bounded.body_read == 3
    bounded.discard_body(headers(("Content-Length", "3")))
    assert stream.read() == b"NEXT"

@pytest.mark.parametrize("pairs", [[], [("Content-Length", "0")], [("Content-Length", str(MAX_BODY_BYTES + 1))], [("Content-Length", "-1")], [("Content-Length", "3"), ("Content-Length", "3")], [("Content-Length", "3"), ("Transfer-Encoding", "chunked")], [("Content-Length", "3"), ("Expect", "100-continue")]])
def test_discard_rejects_unbounded_or_ambiguous_framing(pairs):
    stream = io.BytesIO(b"abc")
    bounded = BoundedInput(stream)
    bounded.discard_body(headers(*pairs))
    assert stream.tell() == 0

def test_discard_respects_remaining_request_budget():
    stream = io.BytesIO(b"abc")
    bounded = BoundedInput(stream)
    bounded.remaining = 2
    bounded.discard_body(headers(("Content-Length", "3")))
    assert stream.tell() == 0

def test_discard_skips_malformed_headers():
    stream = io.BytesIO(b"abc")
    bounded = BoundedInput(stream)
    fields = headers(("Content-Length", "3"))
    fields.defects.append(ValueError("invalid header"))
    bounded.discard_body(fields)
    assert stream.tell() == 0
