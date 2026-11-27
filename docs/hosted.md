# Hosted scanning modes

Production always supports browser-side DNS and email observations. A separate, disabled-by-default server feature may add one bounded HTTPS HEAD response and TLS/header observations, retaining DNS results if unavailable. The full local scanner provides more coverage.

## What the hosted website probe does

- The browser explicitly submits a validated ASCII hostname; no URLs, IP literals, or special-use suffixes are accepted.
- DNS and email lookups go directly to Google Public DNS from the visitor's browser.
- For admitted website checks, the Vercel function re-validates the hostname, resolves both A and AAAA records through the fixed public resolver, refuses all responses containing a non-public or malformed address, and selects one public IPv4.
- The function atomically reserves one scan using a restricted Upstash Redis credential. A single counter limits the entire hosted service to **10 scans per UTC day, 100 per UTC month, and one admission per 35 seconds**, including failed scans. This is a global limit, not a per-user allowance; users may encounter exhausted capacity.
- A short-lived Vercel Sandbox receives only four pinned Python worker modules and a deny-by-default network policy allowing one screened IPv4 /32. The worker verifies TLS for the supplied hostname and sends a single HTTPS HEAD / request. It does not follow redirects, fetch response bodies, or send authentication credentials.
- CPU, runtime, HTTP request/response and report sizes are bounded; the Sandbox is stopped in the success and worker-error paths. The returned report has a strict schema.
- If admission, DNS, provider capacity, or the worker fails, the public DNS-only report remains usable. The website scan is not a certification or security audit.

## Deployment gates

**Production:** `VERCEL_ENV=production` and `DOMAIN_GUARD_PUBLIC=1` are both required. The production host must be `domainguard-check.vercel.app`, with matching Host and Origin and same-origin Fetch Metadata. Browser-controlled headers are request-shape checks, not authentication. Production access is public; server-enforced quota plus Sandbox isolation bound admitted work. A dedicated restricted `DOMAIN_GUARD_QUOTA_TOKEN` and `DOMAIN_GUARD_QUOTA_ACL_VERIFIED=1` are required in Production. The scanner never uses the unrestricted shared Upstash token. This public mode must not be activated until its production credential and monitoring are ready.

**Protected Preview:** `VERCEL_ENV=preview`, `DOMAIN_GUARD_PILOT=1` and `DOMAIN_GUARD_PILOT_ALLOWLIST=domainguard-check.vercel.app` are required. Vercel Preview Authentication is the caller boundary; the same quota credential and ACL verification gates apply. Only the pilot hostname is accepted. Use a branch-restricted Preview Secret for the restricted token.

The credential may access only `domainguard:scan-quota:v1` and Redis `TIME`, `GET`, `SET` and `EVAL` as verified by the ACL test. Preserve all other Redis keys and the existing integrations. Production and Preview use the same counter only if supplied with credentials for the same restricted quota user.

## Release and rollback

1. Run Python tests, JavaScript tests, packaging parity, Bandit, dependency audits, Gitleaks, and `git diff --check`.
2. Confirm Production has the restricted quota secret and ACL verification flag without modifying the unrestricted job-radar integration. Keep `DOMAIN_GUARD_PUBLIC` absent for the first Production staging deployment.
3. Deploy a staged production build **without assigning the production hostname**, validate the disabled endpoint and authentication/routing, then activate `DOMAIN_GUARD_PUBLIC=1` in a new staged production build and test the exact deployment before promoting it. Environment variable updates do not retroactively change old deployment snapshots.
4. Verify an authorized public-domain scan, an unauthorized/special-use hostname rejection, a quota-exhaustion response, DNS-only fallback, browser report/export and successful Sandbox cleanup; inspect function runtime errors and quotas.
5. Promote only the accepted staged Production deployment. Monitor errors, resource usage and quota. If compromised or abused, remove the activation flag, deploy an updated disabled Production build, and restore/rollback production traffic. Retire older enabled deployment URLs as needed. Do not rely on deleting an environment variable to disable already-built deployments.
6. Keep Preview protected. Do not promote a Preview deployment directly as evidence for the Production build.

## Privacy and permissions

Only assess domains you own, administer or have permission to check. The external destination sees a limited HTTPS HEAD request from the Vercel Sandbox, the hostname via SNI and HTTP Host, and the scan's timing and user agent. Google Public DNS sees browser queries. Vercel and Upstash process scanner requests and aggregate quota counts. DomainGuard does not request passwords or intentionally persist per-domain scan history, but platform infrastructure may retain access metadata. Read the published Privacy notice and Terms.

The existing production DNS-only experience remains available even when the hosted website feature is disabled or the shared quota is exhausted.
