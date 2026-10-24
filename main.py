import argparse
from domain_guard.checks.https import check_https
from domain_guard.validation import is_valid_domain
from domain_guard.network import check_public_dns
from domain_guard.checks.tls import check_tls

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

    # Check the resolved IP addresses before making an HTTPS request
    network_result = check_public_dns(domain)

    if(not network_result["safe"]):
        parser.error(network_result["message"])

    print("\n=== DomainGuard ===")
    print(f"Target: {domain}")
    print("-------------------------")

    result = check_https(domain, network_result["addresses"])

    if(result["success"]):
        print("HTTPS: CONNECTED")
        print(f"Status Code: {result['status_code']}")
    else:
        print("HTTPS: FAILED")

    print(f"Details: {result['message']}")

    print("\n--- TLS Certificate ---")

    tls_result = check_tls(domain, network_result["addresses"])

    if tls_result["valid"]:
        print("TLS: VERIFIED")
        print(f"Expires: {tls_result['expires']}")
        print(f"Days Remaining: {tls_result['days_remaining']}")

        if tls_result["days_remaining"] < 30:
            print("Warning: Certificate expires within 30 days")
    else:
        print("TLS: CHECK FAILED")

    print(f"Details: {tls_result['message']}")

    
main()