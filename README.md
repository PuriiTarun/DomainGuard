<div align="center">

# DomainGuard

**Website security configuration and DNS diagnostics**

Python · FastAPI · React · TypeScript · pytest · Vite

**In active development · Local use only**

</div>

---

DomainGuard checks common website configuration signals including verified HTTPS connectivity, TLS certificate expiration, DNS records, SPF/DMARC presence, HTTP security headers, and HTTP-to-HTTPS redirects. The Python diagnostic modules power both the command-line tool and a local FastAPI API. The React UI renders only responses from that API.

DomainGuard is **not a vulnerability scanner**. A missing header or email authentication declaration is not proof of an exploitable weakness.

## Features

| Check | Current implementation |
| --- | --- |
| Target validation | Reject malformed domain names and DNS results containing non-public IPs |
| HTTPS | Connect to a screened numeric IP and verify TLS for the original hostname |
| TLS | Verify certificates, report expiration date and days remaining |
| DNS | A, AAAA, MX, NS and TXT lookups |
| SPF/DMARC | Detect records and duplicate declarations, not full policy evaluation |
| Security headers | Inspect HSTS, CSP, nosniff, Referrer-Policy, Permissions-Policy and frame settings |
| HTTP redirect | Inspect port 80 responses without following redirect destinations |
| Local API | FastAPI POST /api/v1/scans, GET /health with Pydantic validation |
| Web dashboard | Responsive dark/light UI, actual scan results, local browser history, JSON/Markdown downloads |

## Windows development setup

Requirements: Python 3.12+, Node.js 22.12+, npm. From the repository root in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

### CLI (still supported)

```powershell
.\.venv\Scripts\python.exe main.py example.com
.\.venv\Scripts\python.exe main.py example.com --format rich
.\.venv\Scripts\python.exe main.py example.com --format json
```

### API

Start the Python backend in one terminal:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8000
```

Check health using `Invoke-RestMethod http://127.0.0.1:8000/health`.

The scan endpoint accepts JSON `{"domain":"example.com"}`. API documentation is available at `http://127.0.0.1:8000/docs` while the local server is running.

### Frontend

In a second PowerShell terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. Vite proxies API requests to port 8000. In `frontend/`, run `npm test` and `npm run build` to verify the UI.

Frontend installation and the production build were **not verified in the local authoring environment** because it could not download packages. Do not assume the dashboard is fully working until the GitHub CI checks and local tests succeed.

## Architecture

```text
frontend/            React, TypeScript, Vite, Tailwind
api/                 FastAPI routes and Pydantic response models
domain_guard/        Reusable Python diagnostics and scanner orchestration
domain_guard/checks/ HTTPS, TLS, DNS, security headers and redirects
main.py              CLI, including optional Rich and JSON formats
tests/               Mocked Python tests
```

The CLI and REST API use `domain_guard.scanner.scan_domain`. Individual failures remain separate and do not automatically count as successful findings. Scan history is stored only in the browser, with a maximum of 10 entries and a clear control. SQLite server-side history has not yet been implemented.

## Security restrictions

- **Use locally only.** Do not expose the scanning API publicly until independent SSRF and abuse-resistance testing is complete.
- Do not run against sites without authorization.
- The HTTP and HTTPS checkers connect to screened numeric IPs. Redirect targets are inspected as text, not followed.
- DNS resolution and request budgets still need a comprehensive security audit, including worst-case resolution delays and concurrency behaviour.
- API rate limiting is process-local and not suitable for public multi-instance deployment.
- API responses do not disclose cookies or arbitrary HTTP response headers.
- SPF and DMARC checks identify declarations but do not fully validate policy or inheritance.
- An unreachable or untested check is reported as unknown, never as a pass.

## Testing

The audited repository baseline contained 56 pytest cases. This branch adds tests for headers, redirects, API validation, orchestration and CLI presentation. GitHub Actions runs the full Python suite and attempts the frontend tests and build on pull requests. Use CI output, not the README, to determine the current passing test total.

An optional local Docker API configuration is provided; the Compose host port is pinned to `127.0.0.1:8000`.

## Roadmap

Remaining work includes strengthening DNS resolver time budgets, reviewing IP controls across all network paths, SQLite persistence if needed, deeper policy evaluation, and end-to-end frontend verification. No public deployment is planned until security review.
