# Hosted DNS mode

The production website performs real public DNS and email configuration checks from the visitor's browser. It does not connect to the submitted website. The full scanner remains local-only. A separately gated, protected preview has code for a bounded website probe of validated public domains. This route remains disabled until live security and quota checks pass.

## Scope

- A, AAAA, MX, NS, TXT, CAA and SOA queries.
- SPF, DMARC, MTA-STS and SMTP TLS reporting record observations.
- Up to ten requests to Google Public DNS per assessment, two at a time. Per-request and overall deadlines, bounded response sizes, no redirects, no automatic retries, and a client-side cooldown.
- Website connection, certificate, header and redirect checks are skipped in production. In a protected preview, the gated probe is attempted only after explicit submission. A denied or unavailable probe leaves the DNS report and its skipped website states intact. Reports and exports identify each source and scope.

The visitor's browser sends domain names to Google's fixed DNS-over-HTTPS endpoint only after submission. Requests omit credentials and referrers and request no EDNS client subnet disclosure. The provider can see the visitor's network address and queried names. Do not submit private or unauthorized names. See the privacy notice for details. Client-side limits govern the application, not a global or adversary-proof provider rate limit.

## Deployment and acceptance

The repository contains root and `domain_guard/static` Vercel packaging. The root JavaScript route and controller re-export the static-root implementation, while `scripts/check-hosted-packaging.mjs` verifies the Python worker mirrors and browser asset manifests. Production keeps server-side scanning disabled. The preview route requires `VERCEL_ENV=preview`, `DOMAIN_GUARD_PILOT=1`, `DOMAIN_GUARD_QUOTA_ACL_VERIFIED=1`, and a restricted `DOMAIN_GUARD_QUOTA_TOKEN`; do not set the ACL flag before live permission tests.

For the shared Upstash Free database, create a separate ACL user in the Upstash console with only the exact key pattern `~domainguard:scan-quota:v1` and commands `+eval +get +set +time`; do not grant `+@all`, wildcard key patterns, or ACL administration. Generate that user's REST token and store it only as the preview server environment variable `DOMAIN_GUARD_QUOTA_TOKEN`. Preserve the initialized counter and all job-radar keys and credentials. Run `node scripts/verify-quota-acl.mjs` with that token and the existing Upstash REST URL. The script reads the quota key and confirms that direct GET and Lua GET of an unrelated key are denied. Then, with `DOMAIN_GUARD_LIVE_QUOTA_TEST=1`, run `node scripts/verify-quota-live.mjs` to consume one reservation and test five concurrent requests plus cooldown. Both scripts fail closed and print no token. Verify provider-side network isolation and sandbox cleanup separately before setting either activation flag.

Before promotion, inspect the hosted CSP and test successful DNS queries for an authorized domain, resolver failures, report exports, sample data labeling, skipped website checks, cancellation and desktop/mobile rendering. Run the offline JavaScript tests with `node --test tests/test_*.mjs`. Verify the protected pilot separately; a mocked browser test does not prove a real sandbox scan. No hosted full scanner should be enabled until independently enforced network isolation, bounded admission and abuse controls, privacy disclosures, costs and deployment security are verified.
