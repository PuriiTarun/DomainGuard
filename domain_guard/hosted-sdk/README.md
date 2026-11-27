# Hosted web probe pilot

This directory contains compatibility re-exports and offline tests. The deployed controller, quota adapter, DNS resolver and route live under `domain_guard/static`; the root route re-exports that route. Both package lockfiles pin the audited Sandbox SDK version.

The route is disabled by default and restricted to protected previews. The gateway requires server-controlled authorization, a durable atomic quota reservation, a trusted DNS screening decision, and reviewed worker source files. It fails closed if authorization or quota admission fails. The probe uses IPv4 only, a single pinned address, no exposed ports, no persistence and a 30-second sandbox timeout. The worker separately verifies TLS and bounds its execution and output.

Before enabling the route, verify the restricted Redis ACL user and token, atomic quota behavior, network isolation, and the Vercel SDK adapter with the project's OIDC identity. Validate cleanup and provider quota behavior. Do not rely on an in-memory counter or regional firewall rules for a global quota. Run `node scripts/verify-quota-acl.mjs` with server-side credentials; it only reads keys. `node scripts/verify-quota-live.mjs` consumes one quota reservation and requires `DOMAIN_GUARD_LIVE_QUOTA_TEST=1`.

Run the offline controller tests with `node --test domain_guard/hosted-sdk/*.test.mjs tests/*.mjs`. Install dependencies with `npm ci --ignore-scripts` and review `npm audit --omit=dev`.
