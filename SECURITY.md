# Security

DomainGuard checks public domain configuration. It does not test application vulnerabilities or provide a security certification.

## Supported operation

Use DomainGuard only for domains you own, administer or have permission to assess. The full local Python scanner and its web API bind to loopback and must not be exposed through a proxy, tunnel or public interface.

The public website performs DNS and email observations through Google Public DNS from the visitor's browser. When the production feature gate is enabled and quota permits, the hosted backend separately validates and resolves a submitted public hostname, reserves an atomic quota slot using a restricted credential, and runs one bounded HTTPS HEAD observation inside an isolated Vercel Sandbox with tightly restricted network egress. It verifies TLS and observes selected headers and redirects without following redirects or downloading response bodies. Hosted checks may be skipped or unavailable; the DNS report remains usable. This is not the full local scanner, a penetration test or a security certification.

## Reporting a vulnerability

Please contact the maintainer privately through the contact options on [GitHub](https://github.com/PuriiTarun). If private vulnerability reporting is enabled for the repository, use that channel. Do not post sensitive information, credentials or exploitable findings in public issues. Describe the affected version, impact and a safe reproduction using a controlled local environment. Do not test unrelated infrastructure.

## Security updates

Keep runtime dependencies up to date and review current advisories before enabling scans. The documented verification commands run offline tests, security scans and separate dependency auditing. Passing tests do not guarantee that the application is free of vulnerabilities.
