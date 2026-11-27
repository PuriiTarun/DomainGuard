import ssl
import urllib3
from domain_guard.network import validate_addresses
from domain_guard.checks.headers import collect_headers
from domain_guard.checks.redirects import observe_redirect
from domain_guard.validation import is_valid_domain

def check_https(domain, addresses, timeout=5):
    """
    Check if a website has a valid HTTPS connection.

    The connection uses a verified public IP address while checking
    the SSL certificate against the original domain name.
    Returns the connection status, HTTP status code, and a message.
    """

    if(not is_valid_domain(domain)):
        return {"success": False, "status_code": None, "message": "Invalid domain"}
    if(timeout <= 0):
        return {"success": False, "status_code": None, "message": "Scan deadline exceeded"}

    # Check that the provided IP addresses are public
    if(not addresses):
        return {
            "success": False,
            "status_code": None,
            "message": "No IP addresses available"
        }

    if(not validate_addresses(addresses)):
        return {"success": False, "status_code": None, "message": "Invalid or non-public IP address"}

    pool = None
    response = None

    try:
        # Verify the original hostname using the TLS context, not the pinned IP.
        context = ssl.create_default_context()
        context.hostname_checks_common_name = False
        pool = urllib3.HTTPSConnectionPool(
            addresses[0],
            port=443,
            server_hostname=domain,
            ssl_context=context
        )

        # Check HTTPS without following redirects or downloading the page
        response = pool.urlopen(
            "GET",
            "/",
            headers={
                "Host": domain,
                "User-Agent": "DomainGuard/0.1"
            },
            timeout=urllib3.Timeout(total=min(timeout, 5), connect=min(timeout, 5), read=min(timeout, 5)),
            retries=False,
            redirect=False,
            preload_content=False,
            assert_same_host=False
        )

        return {
            "success": True,
            "status_code": response.status,
            "message": "HTTPS connection successful",
            "headers": collect_headers(response.headers),
            "redirect": observe_redirect(domain, response.status, response.headers)
        }

    except ssl.SSLCertVerificationError:
        message = "SSL certificate verification failed"

    except urllib3.exceptions.SSLError as error:
        message = "SSL certificate verification failed" if any(isinstance(reason, ssl.SSLCertVerificationError) for reason in error.args) else "TLS handshake failed"

    except ssl.SSLError:
        message = "TLS handshake failed"

    except urllib3.exceptions.NewConnectionError:
        message = "Could not connect to the website"

    except (urllib3.exceptions.TimeoutError, TimeoutError):
        message = "Connection timed out"

    except (urllib3.exceptions.HTTPError, OSError):
        message = "An HTTP request error occurred"

    finally:
        # Close the connection once the check is finished
        if(response is not None):
            response.close()
            response.release_conn()

        if(pool is not None):
            pool.close()

    return {
        "success": False,
        "status_code": None,
        "message": message
    }
