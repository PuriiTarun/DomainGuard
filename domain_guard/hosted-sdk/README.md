# Hosted web probe pilot

This directory is not the deployed static site root. It contains the isolated worker controller and a pinned Sandbox SDK dependency set for a future hosted pilot.

The gateway has no public route. It requires server-controlled authorization, a durable atomic quota reservation, a trusted DNS screening decision, and reviewed worker source files. It fails closed if authorization or quota admission fails. The pilot uses IPv4 only, a single pinned address, no exposed ports, no persistence and a 30-second sandbox timeout. The worker separately verifies TLS and bounds its execution and output.

Before enabling any endpoint, supply and test actual authentication, an atomic shared quota store, DNS screening of both address families, and the Vercel SDK adapter with the project's OIDC identity. Validate cleanup and provider quota behavior. Do not rely on an in-memory counter or regional firewall rules for a global quota. No credentials or runtime services are configured by these files.

Run the offline controller tests with `node --test gateway.test.mjs`. Install dependencies with `npm ci --ignore-scripts` and review `npm audit --omit=dev`. The targeted Zod override addresses a transitive advisory; re-evaluate it whenever upgrading the SDK.
