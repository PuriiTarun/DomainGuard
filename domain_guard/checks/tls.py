import socket
import ssl
from datetime import datetime, timezone
from domain_guard.network import validate_addresses
from domain_guard.validation import is_valid_domain

def check_tls(domain, addresses, timeout=5, now=None):
    """
    Check a website's TLS certificate and expiration date.
    Connect to a screened public IP and verify the original hostname.
    """
    result = {
        "valid": False,
        "expires": None,
        "days_remaining": None,
        "message": ""
    }

    if(not is_valid_domain(domain)):
        result["message"] = "Invalid domain"
        return result
    if(timeout <= 0):
        result["message"] = "Scan deadline exceeded"
        return result

    # Only allow connections to public IP addresses
    if(not addresses):
        result["message"] = "No IP addresses available"
        return result

    if(not validate_addresses(addresses)):
        result["message"] = "Invalid or non-public IP address"
        return result
    try:
        context = ssl.create_default_context()
        context.hostname_checks_common_name = False

        # Connect to an approved IP without resolving the hostname again
        with socket.create_connection((addresses[0], 443), timeout=min(timeout, 5)) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as tls_socket:
                certificate = tls_socket.getpeercert()

                if(not certificate):
                    result["message"] = "Certificate information unavailable"
                    return result

                expiration = certificate["notAfter"]
                timestamp = ssl.cert_time_to_seconds(expiration)
                expiry_date = datetime.fromtimestamp(timestamp, timezone.utc)
                current_date = now if now is not None else datetime.now(timezone.utc)
                if("notBefore" in certificate):
                    start = datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notBefore"]), timezone.utc)
                    if(start > current_date):
                        result["message"] = "TLS certificate not yet valid"
                        return result
                if(expiry_date <= current_date):
                    result["message"] = "TLS certificate expired"
                    return result
                result["valid"] = True
                result["expires"] = expiry_date.strftime("%Y-%m-%d")
                result["days_remaining"] = (expiry_date - current_date).days
                result["message"] = "TLS certificate verified"

    except ssl.SSLCertVerificationError:
        result["message"] = "TLS certificate verification failed"

    except ssl.SSLError:
        result["message"] = "TLS handshake failed"

    except TimeoutError:
        result["message"] = "TLS connection timed out"

    except (OSError, KeyError, ValueError):
        result["message"] = "Could not inspect the TLS certificate"

    return result
