# Using DomainGuard

[Back to the project](../README.md)

## Installation

Python 3.12 or newer is required. From the repository root, create a virtual environment with `python -m venv .venv`. Activate it with `.venv\Scripts\Activate.ps1` in PowerShell or `source .venv/bin/activate` on Linux/macOS. Alternatively, invoke the Python executable inside the environment directly.

Run `python -m pip install .` to install the application and its runtime dependencies.

The official Geist variable sans font and its license are included in the V2 release. The browser serves the font locally, without contacting an external font provider. If these files are absent, run `python scripts/install_geist.py` from the repository root to retrieve the pinned official package, verify its published integrity and restore the font and license. If the font is unavailable, the site falls back to system typography.

## Web interface

Start the local server:

```sh
python -m domain_guard.web_api
```

Open http://127.0.0.1:8000/ to view the demonstration. Example reports are labelled as sample data and do not perform live scanning.

To enable local scanning for domains you own or have permission to assess:

Windows PowerShell:

```powershell
$env:DOMAIN_GUARD_MODE = "local"
$env:DOMAIN_GUARD_LOCAL_SCANS = "1"
python -m domain_guard.web_api
```

Linux/macOS:

```sh
DOMAIN_GUARD_MODE=local DOMAIN_GUARD_LOCAL_SCANS=1 python -m domain_guard.web_api
```

Do not expose this development server through a proxy, tunnel or public interface.

### Reading the report

Start with the plain-language findings. Use the warnings and failures filter to focus on issues that need review, and expand technical details to inspect the evidence. Missing optional records are not automatically security failures.

The downloadable action plan identifies recommended changes, the relevant provider or developer and how to verify the change. It can be opened offline or printed to PDF. JSON export is available for technical use. Downloads use domain-specific filenames.

## Command-line interface

```sh
domainguard example.com
domainguard --json example.com
python main.py --help
```

Enter an ASCII hostname, not a URL, IP address or port. Uppercase and surrounding ordinary spaces are normalized. Internationalized names, trailing dots, control characters and local-use suffixes are not accepted.

Both CLI entry points use a supervised scan process with a 25-second wall-clock limit. Live scanning refuses to start with missing or unsupported runtime dependency versions.

| JSON exit code | Meaning |
| --- | --- |
| 0 | Completed assessment; negative findings may still be present |
| 1 | Incomplete or failed assessment |
| 2 | Rejected input or destination |

## Assessment scope

- DNS: A, AAAA, MX, NS, TXT, CAA and SOA.
- SPF and DMARC: candidate records, duplicate records and limited published policy observations. These checks do not establish full policy validity or mail delivery effectiveness.
- MTA-STS and SMTP TLS reporting: DNS announcements only.
- HTTPS: verified connection on port 443 and observations from a single root response. Redirect targets are described without being followed or resolved, and response bodies are not downloaded.
- TLS: hostname and certificate validity and expiration. Certificate names must match a subject alternative name.
- HTTP security headers: configuration observations from one response, not a site's overall security.

A scan makes at most ten application-level DNS lookups (resolver wire retries may vary) and two TLS connections. A/AAAA observations reuse the addresses screened before connection. Oversized reports preserve bounded data and mark omitted records incomplete. Network failures and scan limits may produce incomplete results.

## Privacy and deployment

Local results expire after 15 minutes. Read the [privacy notice](../domain_guard/static/privacy.html), [terms of use](../domain_guard/static/terms.html) and [security policy](../SECURITY.md) for details.

The `domain_guard/static/` directory supports the [public hosted mode](hosted.md): browser-based DNS/email observations and, when the production feature gate and shared quota allow, a limited HTTPS/TLS/header/redirect probe through an isolated Vercel Sandbox. Root and `domain_guard/static/` build layouts are kept compatible.

Hosted website scans inspect one HTTPS HEAD response without following redirects or downloading page bodies. Global capacity is limited to 10 admitted scans per UTC day, 100 per UTC month and one scan every 35 seconds. If a hosted check is unavailable, the DNS and email report remains usable. Deeper assessment is available through the local Python scanner only; keep its server bound to loopback.
