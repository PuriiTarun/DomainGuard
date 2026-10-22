import re

def is_valid_domain(domain):
    """
    Check if the domain has a valid hostname format.
    Return True if the format is valid, otherwise False.
    """
    if(len(domain) > 253):
        return False

    labels = domain.split(".")

    if(len(labels) < 2):
        return False

    for label in labels:
        if((len(label) < 1) or (len(label) > 63)):
            return False

        # Domain labels can contain letters, numbers, and middle hyphens
        pattern = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"

        if(not re.fullmatch(pattern, label)):
            return False

    # Only accept standard alphabetic top-level domains for now
    return bool(re.fullmatch(r"[a-z]{2,63}", labels[-1]))