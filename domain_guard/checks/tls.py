import ipaddress
import socket
import ssl
from datetime import datetime, timezone

def check_tls(domain, addresses):
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

    # Only allow connections to public IP addresses
    if(not addresses):
        result["message"] = "No IP addresses available"
        return result

    for address in addresses:
        try:
            if(not ipaddress.ip_address(address).is_global):
                result["message"] = "Non-public IP address detected"
                return result
        except ValueError:
            result["message"] = "Invalid IP address"
            return result
    try:
        context = ssl.create_default_context()

        # Connect to an approved IP without resolving the hostname again
        with socket.create_connection((addresses[0], 443), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=domain) as tls_socket:
                certificate = tls_socket.getpeercert()

                if(not certificate):
                    result["message"] = "Certificate information unavailable"
                    return result

                expiration = certificate["notAfter"]
                timestamp = ssl.cert_time_to_seconds(expiration)
                expiry_date = datetime.fromtimestamp(timestamp, timezone.utc)
                current_date = datetime.now(timezone.utc)
                result["valid"] = True
                result["expires"] = expiry_date.strftime("%Y-%m-%d")
                result["days_remaining"] = (expiry_date - current_date).days
                result["message"] = "TLS certificate verified"

    except ssl.SSLError:
        result["message"] = "TLS certificate verification failed"

    except TimeoutError:
        result["message"] = "TLS connection timed out"

    except (OSError, KeyError, ValueError):
        result["message"] = "Could not inspect the TLS certificate"

    return result