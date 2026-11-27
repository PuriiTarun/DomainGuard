# Hosted DNS mode

The production website performs real public DNS and email configuration checks from the visitor's browser. It does not connect to the submitted website. The full scanner remains local-only. A separately gated, protected preview can also perform a bounded website probe for DomainGuard's own fixed production domain; it is not a general public scanner.

## Scope

- A, AAAA, MX, NS, TXT, CAA and SOA queries.
- SPF, DMARC, MTA-STS and SMTP TLS reporting record observations.
- Up to ten requests to Google Public DNS per assessment, two at a time. Per-request and overall deadlines, bounded response sizes, no redirects, no automatic retries, and a client-side cooldown.
- Website connection, certificate, header and redirect checks are skipped in production. In the protected preview, the fixed owner-domain probe is attempted only after explicit submission. A denied or unavailable probe leaves the DNS report and its skipped website states intact. Reports and exports identify each source and scope.

The visitor's browser sends domain names to Google's fixed DNS-over-HTTPS endpoint only after submission. Requests omit credentials and referrers and request no EDNS client subnet disclosure. The provider can see the visitor's network address and queried names. Do not submit private or unauthorized names. See the privacy notice for details. Client-side limits govern the application, not a global or adversary-proof provider rate limit.

## Deployment and acceptance

Use the Vercel Hobby project with `domain_guard/static` as the root, the Other preset, no build or install command, and `.` as output. Production keeps server-side scanning disabled. A protected preview has a gated endpoint for the fixed DomainGuard hostname only.

Before promotion, inspect the hosted CSP and test successful DNS queries for an authorized domain, resolver failures, report exports, sample data labeling, skipped website checks, cancellation and desktop/mobile rendering. Run the offline JavaScript tests with `node --test tests/test_*.mjs`. Verify the protected pilot separately; a mocked browser test does not prove a real sandbox scan. No hosted full scanner should be enabled until independently enforced network isolation, bounded admission and abuse controls, privacy disclosures, costs and deployment security are verified.
