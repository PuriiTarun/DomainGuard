import requests

def check_https(domain):
    """
    Check if a website has a working HTTPS connection.
    Return the connection status or an error message if it fails.
    """
    url = f"https://{domain}"

    try:
        # Check HTTPS without following redirects or downloading the page
        with requests.get(url, timeout=(5, 5), verify=True, allow_redirects=False, stream=True) as response:
            return {
                "success": True,
                "status_code": response.status_code,
                "message": "HTTPS connection successful"
            }

    except requests.exceptions.SSLError:
        message = "SSL certificate verification failed"

    except requests.exceptions.Timeout:
        message = "Connection timed out"

    except requests.exceptions.ConnectionError:
        message = "Could not connect to the website"

    except requests.exceptions.RequestException:
        message = "An HTTP request error occurred"

    return {
        "success": False,
        "status_code": None,
        "message": message
    }