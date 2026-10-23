
<div align="center">

# DomainGuard

**Automated Website Security & Diagnostic Tool**

A Python command-line application for checking website connectivity and common security configuration issues.

![Python](https://img.shields.io/badge/Python-171717?style=flat-square&logo=python&logoColor=white)
![Requests](https://img.shields.io/badge/Requests-171717?style=flat-square)
![pytest](https://img.shields.io/badge/pytest-171717?style=flat-square&logo=pytest&logoColor=white)
![Status](https://img.shields.io/badge/Status-In_Development-555555?style=flat-square)

</div>

---

## Overview

DomainGuard is a Python-based diagnostic tool designed to make routine website security and connectivity checks easier to perform.

The project focuses on identifying common configuration issues, handling network errors, and presenting useful information about a website's technical setup.

DomainGuard is being developed as a practical command-line utility, with an emphasis on readable code, modular design, and automated testing.

## Current Features

| Feature | Description |
|---------|-------------|
| HTTPS connectivity | Establishes a verified HTTPS connection |
| Certificate verification | Uses TLS certificate verification during HTTPS requests |
| Domain validation | Rejects domains with invalid formats |
| DNS address screening | Checks resolved IP addresses and rejects non-public results |
| Error handling | Handles certificate failures, timeouts, and connection errors |
| Automated testing | Uses pytest to verify expected results and failure cases |

## Getting Started

### Requirements

- Python 3.12 or newer
- Git
- Internet access for live website checks

### Installation

Clone the repository:

```bash
git clone https://github.com/PuriiTarun/DomainGuard.git
cd DomainGuard
```

Create a virtual environment:

```bash
python -m venv .venv
```

Install dependencies on Windows:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Usage

Run DomainGuard from the project directory:

```powershell
.\.venv\Scripts\python.exe main.py example.com
```

Example output:

```text
=== DomainGuard ===
Target: example.com
-------------------------
HTTPS: CONNECTED
Status Code: 200
Details: HTTPS connection successful
```

Actual results depend on the website and network conditions.

## Automated Testing

DomainGuard uses pytest to test its diagnostic functions without relying on live website connections.

Install development dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Run the test suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

The current test suite contains 28 passing test cases covering:

- Successful HTTPS connections
- TLS certificate verification errors
- Connection timeouts and failures
- Valid and invalid domain formats
- Public and non-public IP address screening
- DNS resolution failures

Network responses are mocked so tests can run consistently without contacting external websites.

## Project Structure

```text
DomainGuard/
├── main.py
├── domain_guard/
│   ├── __init__.py
│   ├── validation.py
│   ├── network.py
│   └── checks/
│       ├── __init__.py
│       └── https.py
├── tests/
│   ├── test_https.py
│   ├── test_validation.py
│   └── test_network.py
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

Each module has a specific responsibility, making individual checks easier to maintain, improve, and test.

## Planned Development

- TLS certificate details and expiration checks
- DNS record inspection
- SPF and DMARC analysis
- HTTP security header checks
- HTTP-to-HTTPS redirect analysis
- Structured diagnostic reports
- Improved terminal output
- Additional automated tests

## Security Considerations

DomainGuard is intended for authorized website diagnostics and educational development.

The current DNS screening is a preliminary safeguard. It does not fully protect against DNS rebinding or address changes between validation and connection.

Until connection-time protections are implemented and verified, the application should only be used against controlled or explicitly authorized public targets.

DomainGuard is not a comprehensive vulnerability scanner and does not establish that a website is secure.

---

<div align="center">

**Built with Python. Developed and tested incrementally.**

</div>
