from urllib.parse import urlsplit
from domain_guard.validation import is_valid_domain

REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_LOCATION = 2048

def observe_redirect(domain, status, headers):
    # Inspect only the response's Location; do not resolve or follow it.
    if(status not in REDIRECT_CODES):
        return {"status": "info", "message": "No redirect observed on the HTTPS root response"}
    locations = headers.getlist("Location")
    if(len(locations) != 1):
        return {"status": "warning", "message": "Redirect has missing or repeated Location header; destination not followed"}
    location = locations[0]
    if(not isinstance(location, str) or not location or len(location) > MAX_LOCATION or not location.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in location) or "\\" in location):
        return {"status": "warning", "message": "Redirect target is malformed or unsupported; destination not followed"}
    try:
        target = urlsplit(location)
        host = target.hostname
        port = target.port
    except ValueError:
        return {"status": "warning", "message": "Redirect target could not be parsed; destination not followed"}
    if(target.scheme == "http"):
        return {"status": "warning", "message": "HTTPS response redirects to HTTP; destination not followed"}
    if(target.scheme not in ("", "https") or target.username is not None or target.password is not None or (port is not None and port != 443)):
        return {"status": "warning", "message": "Redirect target has an unsupported scheme, credentials or port; destination not followed"}
    if(target.netloc and (not host or not is_valid_domain(host)) or target.scheme and not target.netloc or location.startswith("///")):
        return {"status": "warning", "message": "Redirect target is outside the supported hostname format; destination not followed"}
    if(host and host != domain):
        return {"status": "info", "message": "Redirect points to another hostname; destination not followed or verified"}
    return {"status": "info", "message": "Redirect stays on the requested hostname or uses a relative reference; destination not followed"}
