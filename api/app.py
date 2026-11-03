"""Local-only FastAPI application. Do not expose publicly without a security review."""

from collections import defaultdict, deque
from threading import BoundedSemaphore, Lock
from time import monotonic

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

from api.schemas import ScanRequest, ScanResponse
from domain_guard.scanner import UnsafeTargetError, scan_domain


class RateLimiter:
    """Basic in-process request limit, intended only for local development."""

    def __init__(self, max_requests=5, window_seconds=60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)
        self._lock = Lock()

    def allow(self, client):
        now = monotonic()
        with self._lock:
            timestamps = self._events[client]
            while timestamps and now - timestamps[0] >= self.window_seconds:
                timestamps.popleft()
            if len(timestamps) >= self.max_requests:
                return False
            timestamps.append(now)
            return True


app = FastAPI(title="DomainGuard API", version="0.2.0")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["localhost", "127.0.0.1", "testserver"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"]
)

limiter = RateLimiter()
scan_slots = BoundedSemaphore(value=2)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/scans", response_model=ScanResponse)
def create_scan(payload: ScanRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    if not limiter.allow(client):
        raise HTTPException(status_code=429, detail="Too many scans. Try again later.")
    if not scan_slots.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Scanner is busy. Try again later.")
    try:
        return scan_domain(payload.domain)
    except UnsafeTargetError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    finally:
        scan_slots.release()
