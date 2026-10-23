import ipaddress
import socket

def check_public_dns(domain):
    """
    Resolve a domain and check its IP addresses.
    Reject domains that resolve to non-public addresses.
    """
    try:
        # Look up the addresses used for an HTTPS connection
        results = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)

    except socket.gaierror:
        return {
            "safe": False,
            "addresses": [],
            "message": "Could not resolve the domain"
        }

    addresses = sorted({result[4][0] for result in results})

    if(not addresses):
        return {
            "safe": False,
            "addresses": [],
            "message": "No IP addresses were found"
        }

    # Reject the domain if any resolved address is not public
    for address in addresses:
        if(not ipaddress.ip_address(address).is_global):
            return {
                "safe": False,
                "addresses": addresses,
                "message": "Domain resolves to a non-public IP address"
            }

    return {
        "safe": True,
        "addresses": addresses,
        "message": "Domain resolves to public IP addresses"
    }