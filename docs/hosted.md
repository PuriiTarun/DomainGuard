# Hosted DNS mode

The production website performs real public DNS and email configuration checks from the visitor's browser. It does not connect to the submitted website. The full scanner remains local-only. A separately gated, protected preview has code for a bounded website probe of domainguard-check.vercel.app only. The pilot route remains disabled by default.

## Scope

- A, AAAA, MX, NS, TXT, CAA and SOA queries.
- SPF, DMARC, MTA-STS and SMTP TLS reporting record observations.
- Up to ten requests to Google Public DNS per assessment, two at a time. Per-request and overall deadlines, bounded response sizes, no redirects, no automatic retries, and a client-side cooldown.
- Website connection, certificate, header and redirect checks are skipped in production. In a protected preview, the gated probe is attempted only for domainguard-check.vercel.app after explicit submission. Other domains receive DNS-only results. A denied or unavailable probe leaves the DNS report and its skipped website states intact. Reports and exports identify each source and scope.

The visitor's browser sends domain names to Google's fixed DNS-over-HTTPS endpoint only after submission. Requests omit credentials and referrers and request no EDNS client subnet disclosure. The provider can see the visitor's network address and queried names. Do not submit private or unauthorized names. See the privacy notice for details. Client-side limits govern the application, not a global or adversary-proof provider rate limit.

## Deployment and acceptance

The repository contains root and `domain_guard/static` Vercel packaging. The root JavaScript route and controller re-export the static-root implementation, while `scripts/check-hosted-packaging.mjs` verifies the Python worker mirrors and browser asset manifests. Production always disables the route, including if activation flags are present. The pilot requires Vercel Preview Authentication as the caller-access boundary, `VERCEL_ENV=preview`, `DOMAIN_GUARD_PILOT=1`, `DOMAIN_GUARD_PILOT_ALLOWLIST=domainguard-check.vercel.app`, `DOMAIN_GUARD_QUOTA_ACL_VERIFIED=1`, and a restricted `DOMAIN_GUARD_QUOTA_TOKEN`. The exact allowlist value is a server-side configuration gate, not a browser secret. Origin, Fetch Metadata and Host checks reject unexpected routing; they do not authenticate callers. The restricted token is the only quota credential supplied to the adapter.

The restricted Upstash ACL, live concurrency, and Sandbox network/worker checks were reported as passed before this hardening change; their credentials and live evidence are not stored in this repository. Keep the existing Secret scoped to Preview and this development branch. Preserve the initialized counter, default Redis integration, and all job-radar keys. The read-only `node scripts/verify-quota-acl.mjs` checks direct and Lua denial on an unrelated key; the opt-in `node scripts/verify-quota-live.mjs` consumes one reservation. Do not repeat live cloud tests without an explicit review plan.

Before promotion, inspect the hosted CSP and test successful DNS queries for an authorized domain, resolver failures, report exports, sample data labeling, skipped website checks, cancellation and desktop/mobile rendering. Run the offline JavaScript tests with `node --test tests/test_*.mjs`. Verify the protected pilot separately; a mocked browser test does not prove a real sandbox scan. No hosted full scanner should be enabled until independently enforced network isolation, bounded admission and abuse controls, privacy disclosures, costs and deployment security are verified.
