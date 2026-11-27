<h1 align="center">DomainGuard</h1>
<p align="center">Understand your domain. Know what needs attention.</p>
<p align="center"><strong>DNS · HTTPS · TLS · Email security</strong></p>
<p align="center">
  <a href="#quick-start">Get started</a> ·
  <a href="#what-it-checks">Features</a> ·
  <a href="docs/usage.md">User guide</a> ·
  <a href="docs/development.md">Development</a>
</p>

---

### The project

I started DomainGuard as a Python command-line tool for checking domain configuration. It has since grown into a local web application that helps both technical users and website owners understand their DNS, certificate, website and email settings.

The aim is to explain what was observed, why it matters and what to do next, without treating a missing optional record as a confirmed vulnerability.

### What it checks

| Area | Checks |
| --- | --- |
| DNS | A, AAAA, MX, NS, TXT, CAA and SOA records |
| Website | Verified HTTPS connection, response status and redirect observations |
| Certificates | TLS hostname verification, expiry date and days remaining |
| Browser protection | HSTS, CSP, content type, framing, referrer and permissions policies |
| Email | SPF, DMARC, MTA-STS and SMTP TLS reporting DNS observations |

The web interface includes understandable findings, expandable technical evidence, a findings filter, JSON exports and a printable action plan with recommended changes, responsible providers and retesting instructions.

### How it has progressed

| Original CLI | V2 review release |
| --- | --- |
| 56 passing Python tests | 317 passing Python tests on Windows |
| Command-line reports | CLI and responsive web interface |
| DNS, HTTPS and certificate checks | Expanded website and email observations |
| Basic output | Structured JSON and domain-specific action plans |

| Python tests | JavaScript tests | Python coverage |
| :---: | :---: | :---: |
| **317 passed** | **18 passed** | **92%** |

<sub>Local verification on November 27, 2026: two Linux-specific Python tests skipped on Windows. Coverage is rounded and combines statement and branch coverage. Bandit reported no medium/high findings, Gitleaks reported no leaks, and dependency audits reported no known vulnerabilities at the time of testing. See [development and testing](docs/development.md) for reproduction steps.</sub>

### Quick start

Requires Python 3.12 or newer. Run from the repository root:

```sh
python -m venv .venv
```

Activate the environment using `.venv\Scripts\Activate.ps1` in Windows PowerShell or `source .venv/bin/activate` on Linux/macOS. Then:

```sh
python -m pip install .
python -m domain_guard.web_api
```

Open **http://127.0.0.1:8000/** in your browser to explore the sample report. Live scans are disabled by default. See the [user guide](docs/usage.md) to enable authorized local scans.

Prefer the terminal?

```sh
domainguard example.com
domainguard --json example.com
```

Only check domains you own or have permission to assess.

### Repository guide

| File or directory | Purpose |
| --- | --- |
| [`domain_guard/`](domain_guard/) | Assessment engine, network validation, local API and scan workers |
| [`domain_guard/static/`](domain_guard/static/) | Website, styles, client-side reports, exports and policy pages |
| [`main.py`](main.py) | Command-line entry point |
| [`tests/`](tests/) | Offline Python and JavaScript regression and security tests |
| [`scripts/`](scripts/) | Verification tools and optional Geist font installer |
| [`requirements.txt`](requirements.txt) | Libraries required to run the application |
| [`requirements-dev.txt`](requirements-dev.txt) | Runtime libraries plus testing, coverage and security tools |
| [`pyproject.toml`](pyproject.toml) | Package metadata, dependencies, entry points and test settings |
| [`SECURITY.md`](SECURITY.md) | Supported operation and private vulnerability reporting |
| [`.gitignore`](.gitignore) | Excludes environments, caches and generated local files |
| [`.gitattributes`](.gitattributes) | Consistent text line endings and binary font handling |
| [`docs/`](docs/) | Usage and developer documentation |

### Security and release status

DomainGuard is a configuration assessment tool, not a penetration test or security certification. The local scanner is restricted to loopback, and live public scanning is not supported. The static website demonstration does not send scanning requests.

The V2 application is under review. Public live scanning requires separate deployment security and abuse-control verification.

**[Security policy](SECURITY.md)** · [Privacy notice](domain_guard/static/privacy.html) · [Terms of use](domain_guard/static/terms.html) · [Detailed scope](docs/usage.md#assessment-scope)

---

Developed by [Tarun Puri](https://github.com/PuriiTarun).
