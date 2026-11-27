import ipaddress
import time
from domain_guard.checks.dns import lookup_records
from domain_guard.validation import is_valid_domain

MAX_ADDRESSES = 32
PUBLIC_V6 = ipaddress.ip_network("2000::/3")
SPECIAL_V4 = tuple(ipaddress.ip_network(value) for value in ("192.0.0.0/24", "192.88.99.0/24", "198.18.0.0/15"))
SPECIAL_V6 = (ipaddress.ip_network("2001::/23"), ipaddress.ip_network("3fff::/20"))

def is_public_address(value):
    if(not isinstance(value, str) or "%" in value):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if(not address.is_global or address.is_multicast or address.is_reserved or address.is_loopback or address.is_link_local or address.is_unspecified):
        return False
    if(isinstance(address, ipaddress.IPv6Address)):
        if(address.ipv4_mapped or address.sixtofour or address.teredo or address not in PUBLIC_V6):
            return False
        if(any(address in network for network in SPECIAL_V6)):
            return False
    elif(any(address in network for network in SPECIAL_V4)):
        return False
    return True

def validate_addresses(addresses):
    if(not isinstance(addresses, (list, tuple)) or not 0 < len(addresses) <= MAX_ADDRESSES):
        return False
    return all(is_public_address(address) for address in addresses)

def rejected(message, status="rejected"):
    return {"safe": False, "addresses": [], "message": message, "status": status}

def check_public_dns(domain, deadline=None):
    if(not is_valid_domain(domain)):
        return rejected("Invalid domain")
    if(deadline is None):
        deadline = time.monotonic() + 5
    addresses = []
    records = {}
    for kind in ("A", "AAAA"):
        remaining = deadline - time.monotonic()
        if(remaining <= 0):
            return rejected("Address resolution deadline exceeded", "incomplete")
        lookup = lookup_records(domain, kind, remaining)
        if(not isinstance(lookup, dict) or not isinstance(lookup.get("values"), list)):
            return rejected("Invalid DNS address response")
        if(lookup.get("status") == "nxdomain"):
            return rejected("Domain does not exist")
        if(lookup.get("status") not in ("found", "missing")):
            return rejected("Could not resolve both address families", "incomplete")
        if(bool(lookup["values"]) != (lookup["status"] == "found")):
            return rejected("Inconsistent DNS address response")
        screened = []
        for value in lookup["values"]:
            if(not is_public_address(value)):
                return rejected("Domain resolves to a non-public or invalid address")
            try:
                address = ipaddress.ip_address(value)
            except (TypeError, ValueError):
                return rejected("Invalid DNS address response")
            if(address.version != (4 if kind == "A" else 6)):
                return rejected("Domain resolves to a non-public or invalid address")
            screened.append(str(address))
            addresses.append(str(address))
            if(len(addresses) > MAX_ADDRESSES):
                return rejected("Too many DNS addresses")
        records[kind] = {"status": lookup["status"], "values": screened}
    if(not addresses):
        return rejected("No IP addresses were found")
    if(time.monotonic() >= deadline):
        return rejected("Address resolution deadline exceeded", "incomplete")
    return {"safe": True, "addresses": sorted(set(addresses)), "message": "Domain resolves to public IP addresses", "status": "pass", "records": records}
