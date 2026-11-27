import re
from importlib.metadata import PackageNotFoundError, version

MINIMUMS = {"dnspython": (2, 9, 2), "urllib3": (2, 8, 0)}

class RuntimeNotReady(RuntimeError):
    pass

def runtime_issues():
    issues = []
    for name, minimum in MINIMUMS.items():
        required = ".".join(map(str, minimum))
        try:
            installed = version(name)
        except PackageNotFoundError:
            issues.append(f"{name} is not installed; require >={required},<3")
            continue
        match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:\.post[0-9]+)?", installed)
        if(not match or not minimum <= tuple(map(int, match.groups())) < (3, 0, 0)):
            issues.append(f"{name} must be a supported stable release (>={required},<3)")
    return issues

def require_runtime():
    issues = runtime_issues()
    if(issues):
        raise RuntimeNotReady("Live scanning unavailable: " + "; ".join(issues) + ". Install the project in an isolated environment.")
