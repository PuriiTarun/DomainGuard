# Security

DomainGuard checks public domain configuration. It does not test application vulnerabilities or provide a security certification.

## Supported operation

Use the local scanner only for authorized domains. The server binds to loopback and must not be exposed through a proxy, tunnel or public interface. The hosted DNS mode performs public DNS queries directly from the visitor's browser through a fixed external resolver; it does not contact the submitted website or expose a scanning backend. Full public live scanning is not supported by this version.

## Reporting a vulnerability

Please contact the maintainer privately through the contact options on [GitHub](https://github.com/PuriiTarun). If private vulnerability reporting is enabled for the repository, use that channel. Do not post sensitive information, credentials or exploitable findings in public issues. Describe the affected version, impact and a safe reproduction using a controlled local environment. Do not test unrelated infrastructure.

## Security updates

Keep runtime dependencies up to date and review current advisories before enabling scans. The documented verification commands run offline tests, security scans and separate dependency auditing. Passing tests do not guarantee that the application is free of vulnerabilities.
