import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(name, command):
    print(f"{name}: {' '.join(command)}", flush=True)
    return subprocess.run(command, cwd=ROOT, check=False).returncode

def module(name, args):
    if(importlib.util.find_spec(name) is None):
        print(f"{name}: required tool unavailable", flush=True)
        return 1
    return run(name, [sys.executable, "-m", name, *args])

def executable(name, args):
    if(not shutil.which(name)):
        print(f"{name}: required tool unavailable", flush=True)
        return 1
    return run(name, [name, *args])

def tracked_local_secrets():
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=False)
    if(result.returncode):
        print("Tracked local secrets: Git inventory unavailable", flush=True)
        return 1
    names = [name.decode("utf-8", "replace") for name in result.stdout.split(b"\0") if name]
    exposed = [name for name in names if any(part.startswith(".env") or part in (".vercel", ".venv", "node_modules") for part in Path(name).parts)]
    if(exposed):
        print("Tracked local secrets or installed dependencies: " + ", ".join(exposed), flush=True)
        return 1
    print("Tracked local secrets: none", flush=True)
    return 0

def main():
    parser = argparse.ArgumentParser(description="Run DomainGuard verification")
    parser.add_argument("--offline-only", action="store_true", help="Run tests and coverage without security scanners")
    parser.add_argument("--dependency-audit", action="store_true", help="Run the separate network-dependent advisory audit")
    args = parser.parse_args()
    if(args.dependency_audit):
        status = module("pip_audit", ["--local"])
        status |= module("pip_audit", ["-r", "requirements-dev.txt"])
        status |= module("pip", ["check"])
        raise SystemExit(1 if status else 0)
    status = run("Python syntax", [sys.executable, "-m", "compileall", "-q", "main.py", "domain_guard", "tests", "scripts"])
    status |= module("coverage", ["run", "--branch", "--source=domain_guard,main", "-m", "pytest", "-q"])
    if(not status):
        status |= module("coverage", ["report", "-m"])
    javascript = [ROOT / "api/hosted-pilot.js"]
    for directory in ("domain_guard/static", "domain_guard/static/api", "domain_guard/static/hosted-backend", "scripts"):
        javascript.extend((ROOT / directory).glob("*.mjs"))
        javascript.extend((ROOT / directory).glob("*.js"))
    for path in sorted(javascript):
        status |= executable("node", ["--check", str(path)])
    status |= executable("node", ["scripts/check-hosted-packaging.mjs"])
    node_tests = sorted((ROOT / "tests").glob("test_*.mjs")) + sorted((ROOT / "domain_guard/hosted-sdk").glob("*.test.mjs"))
    status |= executable("node", ["--test", *[str(path) for path in node_tests]])
    if(not args.offline_only):
        status |= run("Runtime dependencies", [sys.executable, "-c", "from domain_guard.runtime import require_runtime; require_runtime()"])
        status |= module("bandit", ["-q", "-r", "domain_guard", "main.py", "scripts", "-ll"])
        status |= tracked_local_secrets()
        status |= executable("gitleaks", ["git", "--redact", "--no-banner", "."])
        status |= executable("gitleaks", ["dir", "--redact", "--no-banner", "."])
        status |= executable("git", ["-c", "core.whitespace=cr-at-eol", "diff", "--check"])
        status |= executable("git", ["-c", "core.whitespace=cr-at-eol", "diff", "--cached", "--check"])
    raise SystemExit(1 if status else 0)

if(__name__ == "__main__"):
    main()
