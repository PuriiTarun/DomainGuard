import json
import subprocess
import sys
from unittest.mock import patch
import pytest
from domain_guard.worker_limits import apply_limits, MEMORY_BYTES, CPU_SECONDS, MAX_FILES

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux resource controls")
def test_limits_enforced_in_real_child():
    code = """
import json, resource
from domain_guard.worker_limits import apply_limits
assert apply_limits()
keys = (resource.RLIMIT_AS, resource.RLIMIT_CPU, resource.RLIMIT_NOFILE, resource.RLIMIT_CORE)
print(json.dumps([resource.getrlimit(key) for key in keys]))
"""
    child = subprocess.run([sys.executable, "-c", code], capture_output=True, check=True, timeout=5)
    limits = json.loads(child.stdout)
    for actual, maximum in zip(limits, (MEMORY_BYTES, CPU_SECONDS, MAX_FILES, 0)):
        assert 0 <= actual[0] == actual[1] <= maximum

@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux resource controls")
def test_worker_memory_cap_rejects_large_allocation():
    code = """
from domain_guard.worker_limits import apply_limits, MEMORY_BYTES
assert apply_limits()
try:
    data = bytearray(MEMORY_BYTES + 1)
except MemoryError:
    print('allocation rejected')
else:
    raise SystemExit(1)
"""
    child = subprocess.run([sys.executable, "-c", code], capture_output=True, check=True, timeout=5)
    assert b"allocation rejected" in child.stdout

def test_unsupported_platform_does_not_claim_limits():
    with patch("domain_guard.worker_limits.sys.platform", "win32"):
        assert apply_limits() is False
