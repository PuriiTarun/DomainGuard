# Development and testing

[Back to the project](../README.md)

## Dependencies

| Dependency | Purpose |
| --- | --- |
| urllib3 | HTTPS connections and HTTP response handling |
| dnspython | DNS record resolution |
| pytest | Python test runner |
| coverage | Statement and branch coverage |
| Bandit | Static Python security analysis |
| pip-audit | Known Python dependency vulnerabilities |
| cryptography | Test certificate and CA generation |

The first two are runtime libraries. The remaining five are development-only dependencies. Node.js runs the JavaScript tests; Gitleaks is required for the full secret scan.

[`requirements.txt`](../requirements.txt) lists runtime dependencies. [`requirements-dev.txt`](../requirements-dev.txt) includes the runtime list and developer tools. [`pyproject.toml`](../pyproject.toml) defines package metadata, installation extras, command entry points and pytest settings.

## Local development

Create and activate a Python 3.12+ virtual environment as described in the [user guide](usage.md), then run:

```sh
python -m pip install -e ".[dev]"
```

Keep pip and dependencies up to date before running the separate advisory audit.

## Verification

Run from the repository root:

```sh
python scripts/check_security.py --offline-only
```

This compiles Python, runs pytest with branch coverage, checks JavaScript syntax and runs the Node.js test suite. Python tests block external socket connections and DNS lookups in-process, allowing controlled loopback integration tests. TLS integration tests use an ephemeral test CA and controlled loopback endpoint.

For the additional runtime dependency, Bandit, Gitleaks and Git whitespace checks:

```sh
python scripts/check_security.py
```

Missing required tools cause verification to fail. When current advisory access is available, run the separate network-dependent audit:

```sh
python scripts/check_security.py --dependency-audit
```

This checks installed packages, declared development requirements and dependency compatibility.

## Security architecture

The assessment engine checks both IPv4 and IPv6 DNS answers before connecting. It rejects prohibited or uncertain destinations, pins connections to an approved address and verifies the requested TLS hostname.

The local server binds only to IPv4 loopback, requires its exact host and rejects unauthorized browser origins. The local queue bounds concurrent work, result access uses private credentials, and jobs expire after 15 minutes. The scan subprocess supports cancellation and has a wall-clock deadline and bounded output pipe.

Local HTTP connections have an absolute deadline and total request-size budget. On Linux, workers additionally limit address space, CPU time, open file descriptors and core dumps. Other platforms retain wall-clock and output limits; process resource limits are not claimed there.

Process separation is not a network sandbox. Local Python scans are disabled by default and in production mode. The separate browser-based [hosted DNS mode](hosted.md) does not run the Python scanner. See [SECURITY.md](../SECURITY.md) for supported operation and vulnerability reporting.

## Source layout

- `domain_guard/checks/`: DNS, HTTPS, TLS, headers, redirects and email observations.
- `domain_guard/assessment.py`: coordinates one bounded domain assessment.
- `domain_guard/network.py` and `validation.py`: screen destinations and normalize input.
- `domain_guard/web_api.py`, `local_server.py`, `web_request.py`: local HTTP boundary.
- `domain_guard/scan_jobs.py`, `worker.py`, `worker_limits.py`: job lifecycle and worker limits.
- `domain_guard/static/`: browser interface, report rendering and exports.
- `tests/`: deterministic regression tests and controlled local integration tests.

Passing tests and security scans are evidence of the checks performed, not a guarantee that the application is free of vulnerabilities.
