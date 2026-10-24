import ipaddress
import ssl
import urllib3

def check_https(domain, addresses):
    """
    Check if a website has a valid HTTPS connection.

    The connection uses a verified public IP address while checking
    the SSL certificate against the original domain name.
    Returns the connection status, HTTP status code, and a message.
    """

    # Check that the provided IP addresses are public
    if(not addresses):
        return {
            "success": False,
            "status_code": None,
            "message": "No IP addresses available"
        }

    for address in addresses:
        try:
            if(not ipaddress.ip_address(address).is_global):
                return {
                    "success": False,
                    "status_code": None,
                    "message": "Non-public IP address detected"
                }

        except ValueError:
            return {
                "success": False,
                "status_code": None,
                "message": "Invalid IP address"
            }

    pool = None
    response = None

    try:
        # Connect to the verified IP while checking the original hostname
        pool = urllib3.HTTPSConnectionPool(
            addresses[0],
            port=443,
            server_hostname=domain,
            assert_hostname=domain,
            ssl_context=ssl.create_default_context()
        )

        # Check HTTPS without following redirects or downloading the page
        response = pool.urlopen(
            "GET",
            "/",
            headers={
                "Host": domain,
                "User-Agent": "DomainGuard/0.1"
            },
            timeout=urllib3.Timeout(connect=5, read=5),
            retries=False,
            redirect=False,
            preload_content=False,
            assert_same_host=False
        )

        return {
            "success": True,
            "status_code": response.status,
            "message": "HTTPS connection successful"
        }

    except (urllib3.exceptions.SSLError, ssl.SSLError):
        message = "SSL certificate verification failed"

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