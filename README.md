# DomainGuard

DomainGuard checks public domain configuration using Python. It inspects DNS records, HTTPS connectivity, TLS certificates, HTTP response security headers and published email security records. It provides observations rather than a security score or a complete vulnerability assessment.

## Setup

Python 3.12 or newer is required. Create a virtual environment with `python -m venv .venv`. On Windows, activate it with `.venv\Scripts\Activate.ps1`; on Linux or macOS, use `source .venv/bin/activate`. Then run `python -m pip install .`. Alternatively, run the Python executable from that environment directly.

## CLI

```sh
domainguard example.com
domainguard --json example.com
python main.py --help
```

Use an ASCII hostname, not a URL, IP address or port. Uppercase and surrounding ordinary spaces are normalized. Internationalized names, trailing dots, control characters and local-use suffixes are not accepted.

Both entry points use a supervised scan process with a 25-second wall-clock limit. Live scanning refuses to start with missing or unsupported runtime dependency versions. The JSON option returns exit code 0 for a completed assessment, 1 for incomplete or failed work, and 2 for rejected input or destinations. A completed assessment can still contain negative findings.

The engine checks both IPv4 and IPv6 DNS answers before connecting. It rejects prohibited or uncertain destinations, pins connections to an approved address and verifies the requested TLS hostname. HTTP connections are limited to HTTPS on port 443. Certificate names must match a subject alternative name. Redirect targets are described without being followed or resolved, and response bodies are not downloaded.

## Local website

To use the Geist typeface, run `python scripts/install_geist.py` once from the source directory. This downloads the pinned official Geist package from the npm registry, verifies its published integrity and copies only the variable sans font and its license. The browser serves the font locally; it does not contact an external font provider. If the font is absent, the site uses a system font. Include both files when packaging or deploying the site.

```sh
python -m domain_guard.web_api
```

Open `http://127.0.0.1:8000` for the demonstration. To enable local scans, set `DOMAIN_GUARD_LOCAL_SCANS=1` before starting the server. In PowerShell:

```powershell
$env:DOMAIN_GUARD_MODE = "local"
$env:DOMAIN_GUARD_LOCAL_SCANS = "1"
python -m domain_guard.web_api
```

The server binds only to IPv4 loopback, requires its exact host, and rejects cross-origin requests. Live scans are disabled by default and in production mode. Results expire after 15 minutes; the local queue limits concurrent work and the scan subprocess has a cancellation/deadline mechanism and a bounded output pipe. Local HTTP connections have an absolute deadline and a total request-size budget. On Linux the worker also limits its address space, CPU time, open file descriptors and core dumps. Other platforms retain the wall-clock and output limits; process resource limits are not claimed there. Process separation is not a network sandbox. Do not expose this development server through a proxy, tunnel or public interface.

The report includes plain-language findings, optional technical details, a warnings and failures filter, a printable, downloadable action plan with domain-specific filename, responsible provider and verification steps, and JSON export. Example reports are always labelled as sample data.

The `domain_guard/static/` directory also supports a static-only demonstration. Its Vercel configuration does not include a scanning backend. Set the hosting project root to that directory when deploying an approved demo.

## Tests

```sh
python -m pip install -e ".[dev]"
python scripts/check_security.py --offline-only
python scripts/check_security.py
```

Python tests block external socket connections and DNS lookups in-process, allowing controlled loopback integration tests. The JavaScript tests require Node.js. TLS integration tests use an ephemeral test CA and controlled loopback TLS endpoint; cryptography is a development-only dependency. The full security command requires Bandit and Gitleaks; missing tools cause it to fail. Run `python scripts/check_security.py --dependency-audit` separately when current advisory access is available.

## Scope

DNS checks cover A, AAAA, MX, NS, TXT, CAA and SOA. SPF/DMARC checks identify candidate records, duplicates and limited published policy observations; MTA-STS and SMTP TLS reporting checks discover DNS announcements only. None establishes full policy validity or mail delivery effectiveness. A scan makes at most ten application-level DNS lookups (resolver wire retries may vary) and two TLS connections; A/AAAA observations reuse the addresses screened before connection. Oversized reports preserve bounded data and mark omitted records incomplete. Header observations describe one HTTPS response, not a site's overall security. Only assess domains you are authorized to check. Results may be incomplete when network requests fail or scan limits are reached.

Public live scanning is not supported until separate worker isolation, enforced network egress restrictions, abuse controls and deployment security have been verified.

## Privacy and permitted use

The website includes a privacy notice and terms for the local application and static demonstration. Before public live scanning, verify hosting disclosures, private contact channels, legal requirements and production security. Local scans are limited to authorized domains.
