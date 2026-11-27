# Hosted quota and restricted Redis access

The hosted gateway uses a server-side atomic Upstash Redis quota. Credentials must never be sent to the browser or committed to Git. Use a dedicated restricted ACL user whose key pattern permits only `domainguard:scan-quota:v1` and whose allowed commands are `EVAL`, `GET`, `SET` and `TIME`. The underlying Redis database may be shared with other applications; **never** broaden this user's ACL or modify another application's keys or credentials.

Initialize the quota key once using the provider's trusted administration console before activation:

```text
SET domainguard:scan-quota:v1 v1:0:0:0:0:0 NX
```

Do not reset the key as part of deployment, restart or recovery. The gate atomically uses provider time and UTC windows to cap accepted scans at **10 per UTC day, 100 per UTC month and a 35-second cooldown**. All visitors share this limit, which can be exhausted by other users; this is not a per-user quota. A reservation is consumed even if DNS, Sandbox creation or the probe fails. Missing, malformed, unavailable or exhausted quota state fails closed.

The gateway requires `DOMAIN_GUARD_QUOTA_TOKEN` and `DOMAIN_GUARD_QUOTA_ACL_VERIFIED=1` in its trusted Vercel environment. It must not use the application's unrestricted Upstash token. The restricted token's ACL and atomic reservation behavior need independent testing with `scripts/verify-quota-acl.mjs` and `scripts/verify-quota-live.mjs`; the live check consumes a reservation and requires an explicit test flag.

These limits reduce abuse and resource usage, but do **not** guarantee zero cost or prevent quota exhaustion by another visitor. Monitor Vercel Sandbox usage, quotas and provider billing. Provider outages and exhausted quotas disable hosted website checks rather than permit unmetered scans; the browser-side DNS/email report remains available. See [hosted release and rollback guidance](../../docs/hosted.md).
