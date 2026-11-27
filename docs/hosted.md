# Hosted DNS mode

The hosted static website can perform real public DNS and email configuration checks from the visitor's browser. It does not run a Python API or connect to the submitted website. The full scanner remains local-only.

## Scope

- A, AAAA, MX, NS, TXT, CAA and SOA queries.
- SPF, DMARC, MTA-STS and SMTP TLS reporting record observations.
- Up to ten requests to Google Public DNS per assessment, two at a time. Per-request and overall deadlines, bounded response sizes, no redirects, no automatic retries, and a client-side cooldown.
- Explicitly skipped website connection, certificate, header and redirect checks. The browser must not mark these as verified. Reports and exports identify their source and scope.

The visitor's browser sends domain names to Google's fixed DNS-over-HTTPS endpoint only after submission. Requests omit credentials and referrers and request no EDNS client subnet disclosure. The provider can see the visitor's network address and queried names. Do not submit private or unauthorized names. See the privacy notice for details. Client-side limits govern the application, not a global or adversary-proof provider rate limit.

## Deployment and acceptance

Use the Vercel Hobby project with `domain_guard/static` as the root, the Other preset, no build or install command, and `.` as output. The deployment CSP permits connections only to the DNS resolver and blocks form navigation. There is no server-side scan endpoint.

Before promotion, inspect the hosted CSP and test successful DNS queries for an authorized domain, resolver failures, report exports, sample data labeling, skipped website checks, cancellation and desktop/mobile rendering. Run the offline JavaScript tests with `node --test tests/test_*.mjs`. The broader local Python scanner must remain unchanged. No hosted full scanner should be enabled until independently enforced network isolation, bounded admission and abuse controls, privacy disclosures, costs and deployment security are verified.
