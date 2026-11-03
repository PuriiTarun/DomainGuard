"""Inspect an HTTP-to-HTTPS redirect without following it."""

import ipaddress
from urllib.parse import urlsplit

import urllib3

from domain_guard.validation import is_valid_domain

REDIRECT_CODES = (301, 302, 303, 307, 308)


def check_http_redirect(domain, addresses):
    """
    Connect to port 80 on a screened IP and inspect its response.
    Never follow the Location header or request an arbitrary URL.
    """
    result = {
        "status": "unknown",
        "http_status": None,
        "location": None,
        "message": "Redirect check was not completed"
    }
    if not is_valid_domain(domain):
        result["message"] = "Invalid domain format"
        return result
    if not addresses:
        result["message"] = "No IP addresses available"
        return result
    try:
        if any(not ipaddress.ip_address(ip).is_global for ip in addresses):
            result["message"] = "Non-public IP address detected"
            return result
    except ValueError:
        result["message"] = "Invalid IP address"
        return result

    pool = None
    response = None
    try:
        # This pool receives a numeric IP, not a hostname or redirect target.
        pool = urllib3.HTTPConnectionPool(addresses[0], port=80)
        response = pool.urlopen(
            "GET",
            "/",
            headers={"Host": domain, "User-Agent": "DomainGuard/0.2"},
            timeout=urllib3.Timeout(connect=5, read=5),
            retries=False,
            redirect=False,
            preload_content=False,
            assert_same_host=False
        )
        result["http_status"] = response.status
        location = response.headers.get("Location")
        result["location"] = location if isinstance(location, str) else None

        if response.status not in REDIRECT_CODES or not result["location"]:
            result["status"] = "review"
            result["message"] = "HTTP did not return a redirect to HTTPS"
            return result

        try:
            target = urlsplit(result["location"])
            valid_port = target.port in (None, 443)
        except ValueError:
            target = None
            valid_port = False

        if (target and target.scheme.lower() == "https"
                and target.hostname == domain and valid_port
                and not target.username and not target.password):
            result["status"] = "pass"
            result["message"] = "HTTP redirects directly to HTTPS on the same domain"
        else:
            result["status"] = "review"
            result["message"] = "Redirect does not directly upgrade to HTTPS on the same domain"

    except (urllib3.exceptions.HTTPError, OSError, TimeoutError):
        result["message"] = "Could not complete the HTTP redirect check"
    finally:
        if response is not None:
            response.close()
            response.release_conn()
        if pool is not None:
            pool.close()
    return result
