import argparse
import json
import threading
from domain_guard.worker import run_scan
from domain_guard.runtime import RuntimeNotReady, require_runtime
from domain_guard.validation import normalize_domain

def safe_text(value):
    return "".join(char if char.isprintable() and char not in "\x1b\x7f" else "?" for char in str(value))

def show_check(name, check):
    print(f"{name}: {safe_text(check['status']).upper()}")
    print(f"Details: {safe_text(check['message'])}")
    if(check.get("status_code") is not None):
        print(f"Status Code: {check['status_code']}")
    if(check.get("expires") is not None):
        print(f"Expires: {safe_text(check['expires'])}")
        print(f"Days Remaining: {check['days_remaining']}")
        if(check["days_remaining"] < 30):
            print("Warning: Certificate expires within 30 days")
    for finding in check.get("findings", []):
        print(f"  {safe_text(finding['name'])}: {safe_text(finding['message'])}")

def show_records(result):
    labels = {"found": "Found", "missing": "Not found", "multiple": "Multiple records detected",
              "error": "DNS lookup failed", "nxdomain": "Name does not exist", "incomplete": "Incomplete"}
    print("\n--- DNS Records ---")
    for kind, lookup in result["records"].items():
        print(f"{safe_text(kind)}: {labels.get(lookup['status'], 'Unavailable')}")
        if(lookup.get("message")):
            print(f"  {safe_text(lookup['message'])}")
        if(kind == "TXT"):
            print(f"  {len(lookup['values'])} record(s)")
        else:
            for value in lookup["values"]:
                print(f"  {safe_text(value)}")
    print("\n--- Email Authentication ---")
    for kind, name in (("spf", "SPF"), ("dmarc", "DMARC"), ("mta_sts", "MTA-STS"), ("tlsrpt", "SMTP TLS reporting")):
        if(kind not in result):
            continue
        lookup = result[kind]
        label = "Detected (not validated)" if lookup["status"] == "found" else labels.get(lookup["status"], "Unavailable")
        print(f"{name}: {label}")
        if(lookup.get("message")):
            print(f"  {safe_text(lookup['message'])}")
        for value in lookup["values"]:
            print(f"  {safe_text(value)}")
        for finding in lookup.get("findings", []):
            print(f"  {safe_text(finding['name'])}: {safe_text(finding['message'])}")

def main():
    parser = argparse.ArgumentParser(description="DomainGuard: domain configuration assessment")
    parser.add_argument("domain", help="Website domain to check (example.com)")
    parser.add_argument("--json", action="store_true", help="Write the structured report as JSON")
    args = parser.parse_args()
    try:
        domain = normalize_domain(args.domain)
    except ValueError:
        parser.error("Invalid domain. Enter a domain such as example.com")
    try:
        require_runtime()
        result = run_scan(domain, threading.Event())
    except RuntimeNotReady as error:
        parser.exit(1, f"{error}\n")
    except TimeoutError:
        parser.exit(1, "Scan deadline exceeded; no complete result available.\n")
    except (OSError, ValueError):
        parser.exit(1, "Scan could not be completed.\n")
    if(args.json):
        print(json.dumps(result, ensure_ascii=True, allow_nan=False))
        if(result["status"] != "complete"):
            raise SystemExit(2 if result["status"] == "rejected" else 1)
        return
    if(not result["addresses"]):
        parser.error(safe_text(result["checks"]["address"]["message"]))
    print("\n=== DomainGuard ===")
    print(f"Target: {domain}")
    for key, name in (("https", "HTTPS"), ("tls", "TLS"), ("headers", "HTTP security headers"), ("redirects", "Redirects"), ("output", "Output budget")):
        if(key in result["checks"]):
            show_check(name, result["checks"][key])
    show_records(result)
    print(f"\nAssessment: {safe_text(result['status'])}")

if(__name__ == "__main__"):
    main()
