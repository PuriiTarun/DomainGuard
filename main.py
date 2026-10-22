import argparse
from domain_guard.checks.https import check_https
from domain_guard.validation import is_valid_domain

def main():
    """Accept a domain and display its HTTPS connection status."""

    parser = argparse.ArgumentParser(
        description="DomainGuard: Website Security Diagnostic Tool"
    )

    parser.add_argument(
        "domain",
        help="Website domain to check (example.com)"
    )

    args = parser.parse_args()
    domain = args.domain.strip().lower()

    if(not is_valid_domain(domain)):
        parser.error("Invalid domain. Enter a domain such as example.com")
    
    print("\n=== DomainGuard ===")
    print(f"Target: {domain}")
    print("-------------------------")

    result = check_https(domain)

    if(result["success"]):
        print("HTTPS: CONNECTED")
        print(f"Status Code: {result['status_code']}")
    else:
        print("HTTPS: FAILED")

    print(f"Details: {result['message']}")
    
main()