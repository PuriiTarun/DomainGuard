"""Command-line entry point for DomainGuard."""

import argparse

from domain_guard.scanner import scan_domain


def main():
    """Accept a domain and print its diagnostic results."""
    parser = argparse.ArgumentParser(
        description="DomainGuard: Website Security Diagnostic Tool"
    )
    parser.add_argument("domain", help="Website domain to check (example.com)")
    args = parser.parse_args()

    try:
        result = scan_domain(args.domain)
    except ValueError as error:
        parser.error(str(error))

    print("\n=== DomainGuard ===")
    print(f"Target: {result['domain']}")
    print("-------------------------")

    https = result["https"]
    print(f"HTTPS: {'CONNECTED' if https['success'] else 'FAILED'}")
    if https["status_code"] is not None:
        print(f"Status Code: {https['status_code']}")
    print(f"Details: {https['message']}")

    tls = result["tls"]
    print("\n--- TLS Certificate ---")
    print(f"TLS: {'VERIFIED' if tls['valid'] else 'CHECK FAILED'}")
    if tls["valid"]:
        print(f"Expires: {tls['expires']}")
        print(f"Days Remaining: {tls['days_remaining']}")
        if tls["days_remaining"] < 30:
            print("Warning: Certificate expires within 30 days")
    print(f"Details: {tls['message']}")

    print("\n--- DNS Records ---")
    for record_type, lookup in result["dns"]["records"].items():
        if lookup["status"] == "found":
            print(f"{record_type}: {len(lookup['values'])} record(s)")
            if record_type != "TXT":
                for value in lookup["values"]:
                    print(f"  {value}")
        else:
            print(f"{record_type}: {lookup['status'].upper()}")

    print("\n--- Email Authentication ---")
    for name in ("spf", "dmarc"):
        item = result["dns"][name]
        print(f"{name.upper()}: {item['status'].upper()} (presence only)")

    print("\n--- Security Headers ---")
    headers = result["headers"]
    if headers["status"] != "checked":
        print(headers["message"])
    else:
        for name, finding in headers["checks"].items():
            print(f"{name}: {finding['status'].upper()}")

    print("\n--- HTTP Redirect ---")
    redirect = result["redirects"]
    print(f"Status: {redirect['status'].upper()}")
    print(f"Details: {redirect['message']}")
    if redirect["location"]:
        print(f"Location: {redirect['location']}")


if __name__ == "__main__":
    main()
