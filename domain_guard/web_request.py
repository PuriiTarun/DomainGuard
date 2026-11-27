import json
import re
from domain_guard.local_server import MAX_BODY_BYTES
from domain_guard.scan_jobs import ScanError
from domain_guard.validation import normalize_domain

def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if(key in value):
            raise ValueError("Duplicate key")
        value[key] = item
    return value

def scan_request(headers, stream):
    if(headers.get_all("Transfer-Encoding") or len(headers.get_all("Content-Type", [])) != 1 or headers.get("Content-Type", "").split(";", 1)[0].lower() != "application/json"):
        raise ScanError(415, "Expected a JSON request")
    length = headers.get("Content-Length", "")
    if(len(headers.get_all("Content-Length", [])) != 1 or not re.fullmatch(r"[0-9]{1,3}", length) or not 1 <= int(length) <= MAX_BODY_BYTES):
        raise ScanError(413, "Request is too large or missing")
    try:
        body = stream.read(int(length))
    except OSError:
        raise ScanError(400, "Incomplete request body") from None
    if(len(body) != int(length)):
        raise ScanError(400, "Incomplete request body")
    try:
        data = json.loads(body.decode("utf-8"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise ScanError(400, "Invalid JSON request") from None
    if(type(data) is not dict or set(data) != {"domain"} or type(data["domain"]) is not str):
        raise ScanError(400, "Expected one domain")
    try:
        return normalize_domain(data["domain"])
    except ValueError:
        raise ScanError(400, "Invalid domain") from None
