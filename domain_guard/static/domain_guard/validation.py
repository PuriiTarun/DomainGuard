import re

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\Z")
TOP_LEVEL = re.compile(r"[a-z]{2,63}\Z")
LOCAL_SUFFIXES = {"localhost", "local", "internal", "invalid", "test", "onion", "home", "lan", "example", "arpa", "alt", "localdomain", "corp", "intranet", "private"}

def normalize_domain(value):
    """Return a canonical ASCII hostname or raise ValueError."""
    if(not isinstance(value, str) or len(value) > 512 or not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Invalid domain")
    domain = value.strip(" ").lower()
    if(not is_valid_domain(domain)):
        raise ValueError("Invalid domain")
    return domain

def is_valid_domain(domain):
    """
    Check if the domain has a valid hostname format.
    Return True if the format is valid, otherwise False.
    """
    if(not isinstance(domain, str) or not domain or len(domain) > 253 or not domain.isascii()):
        return False

    labels = domain.split(".")

    if(len(labels) < 2):
        return False

    for label in labels:
        if((len(label) < 1) or (len(label) > 63)):
            return False

        # IDNA labels are deferred until a Unicode policy is defined.
        if(label.startswith("xn--") or not LABEL.fullmatch(label)):
            return False

    return bool(TOP_LEVEL.fullmatch(labels[-1])) and labels[-1] not in LOCAL_SUFFIXES
