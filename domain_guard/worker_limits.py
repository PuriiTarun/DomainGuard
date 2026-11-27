import sys

MEMORY_BYTES = 512 * 1024 * 1024
CPU_SECONDS = 20
MAX_FILES = 64

def apply_limits():
    # Linux process limits are additional controls, not network isolation.
    if(not sys.platform.startswith("linux")):
        return False
    import resource
    def cap(kind, maximum):
        soft, hard = resource.getrlimit(kind)
        limit = min(value for value in (soft, hard, maximum) if value != resource.RLIM_INFINITY)
        resource.setrlimit(kind, (limit, limit))
    cap(resource.RLIMIT_CORE, 0)
    cap(resource.RLIMIT_CPU, CPU_SECONDS)
    cap(resource.RLIMIT_AS, MEMORY_BYTES)
    cap(resource.RLIMIT_NOFILE, MAX_FILES)
    return True
