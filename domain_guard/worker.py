import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from domain_guard.results import MAX_RESULT_BYTES, serialize
WORKER_SECONDS = 25
ROOT = Path(__file__).resolve().parent.parent
ENV_KEYS = ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE", "TZ")

def encode_result(result):
    payload = serialize(result)
    if(len(payload) > MAX_RESULT_BYTES):
        raise ValueError("Result too large")
    return payload

def worker_environment():
    return {key: os.environ[key] for key in ENV_KEYS if key in os.environ}

def read_output(stream, result, done):
    try:
        # Read at most the limit plus one byte; never accumulate unlimited stdout.
        result.append(stream.read(MAX_RESULT_BYTES + 1))
    except (OSError, ValueError):
        result.append(None)
    finally:
        done.set()

def collect_output(process, deadline, cancel):
    output = []
    done = threading.Event()
    reader = threading.Thread(target=read_output, args=(process.stdout, output, done), daemon=True)
    reader.start()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if(cancel.is_set() or remaining <= 0):
                raise TimeoutError("Scan interrupted")
            if(done.wait(min(remaining, 0.1))):
                if(not output or output[0] is None or len(output[0]) > MAX_RESULT_BYTES):
                    raise ValueError("Worker output limit exceeded or unavailable")
                if(process.poll() is not None):
                    return output[0]
                cancel.wait(min(remaining, 0.05))
    finally:
        if(process.poll() is None):
            process.kill()
        process.wait()
        reader.join(timeout=1)

def run_scan(domain, cancel):
    from domain_guard.validation import normalize_domain
    domain = normalize_domain(domain)
    deadline = time.monotonic() + WORKER_SECONDS
    if(cancel.is_set()):
        raise TimeoutError("Scan cancelled")
    command = [sys.executable, "-m", "domain_guard.worker", domain]
    with subprocess.Popen(command, cwd=ROOT, env=worker_environment(), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
        output = collect_output(process, deadline, cancel)
        if(process.returncode != 0):
            raise ValueError("Worker failed")
        try:
            result = json.loads(output)
            if(not isinstance(result, dict) or result.get("domain") != domain or result.get("schema_version") != 1):
                raise ValueError("Invalid worker response")
            if(result.get("status") not in ("complete", "incomplete", "rejected") or not isinstance(result.get("addresses"), list) or not all(isinstance(result.get(key), dict) for key in ("checks", "records"))):
                raise ValueError("Invalid worker response")
            encode_result(result)
        except (RecursionError, TypeError, UnicodeError) as error:
            raise ValueError("Invalid worker response") from error
        return result

def main():
    from domain_guard.runtime import RuntimeNotReady, require_runtime
    if(len(sys.argv) != 2):
        raise SystemExit(2)
    try:
        require_runtime()
    except RuntimeNotReady:
        raise SystemExit(3) from None
    from domain_guard.worker_limits import apply_limits
    apply_limits()
    from domain_guard.assessment import scan_domain
    sys.stdout.buffer.write(encode_result(scan_domain(sys.argv[1])))

if(__name__ == "__main__"):
    main()
