"""Bounded, short-lived local scan jobs."""
import queue
import secrets
import threading
import time
from domain_guard.validation import normalize_domain
from domain_guard.worker import encode_result

MAX_JOBS = 32
QUEUE_SIZE = 4
RESULT_TTL = 900
RATE_WINDOW = 60

class ScanError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status

class ScanJobs:
    def __init__(self, scanner, *, clock=time.monotonic, cancellable=False):
        self.scanner = scanner
        self.clock = clock
        self.cancellable = cancellable
        self.closed = threading.Event()
        self.jobs = {}
        self.events = []
        self.pending = queue.Queue(maxsize=QUEUE_SIZE)
        self.lock = threading.Lock()
        self.worker = threading.Thread(target=self._work, daemon=True)
        self.worker.start()

    def _clean(self, now):
        for scan_id, job in list(self.jobs.items()):
            if(now - job["created"] >= RESULT_TTL):
                job["cancel"].set()
                del self.jobs[scan_id]
        self.events = [event for event in self.events if now - event[0] < RATE_WINDOW]

    def submit(self, domain, client):
        domain = normalize_domain(domain)
        now = self.clock()
        with self.lock:
            self._clean(now)
            if(self.closed.is_set()):
                raise ScanError(503, "Scanner is closed")
            if(len(self.jobs) >= MAX_JOBS or self.pending.full()):
                raise ScanError(503, "Scanner is busy")
            if(sum(1 for _, source, _ in self.events if source == client) >= 5):
                raise ScanError(429, "Request limit reached")
            if(sum(1 for _, _, name in self.events if name == domain) >= 3):
                raise ScanError(429, "Domain request limit reached")
            if(len(self.events) >= 20):
                raise ScanError(429, "Request limit reached")
            if(any(job["domain"] == domain and job["status"] in ("queued", "running") for job in self.jobs.values())):
                raise ScanError(429, "Domain scan already in progress")
            scan_id = secrets.token_urlsafe(18)
            token = secrets.token_urlsafe(32)
            self.jobs[scan_id] = {"id": scan_id, "token": token, "domain": domain, "created": now,
                                  "status": "queued", "result": None, "error": None, "cancel": threading.Event()}
            self.events.append((now, client, domain))
            self.pending.put_nowait(scan_id)
        return scan_id, token

    def get(self, scan_id, token):
        now = self.clock()
        with self.lock:
            self._clean(now)
            job = self.jobs.get(scan_id)
            if(job is None or not isinstance(token, str) or not token.isascii() or not secrets.compare_digest(job["token"], token)):
                raise ScanError(404, "Scan not found")
            return {key: job[key] for key in ("id", "domain", "status", "result", "error")}

    def cancel(self, scan_id, token):
        with self.lock:
            self._clean(self.clock())
            job = self.jobs.get(scan_id)
            if(job is None or not isinstance(token, str) or not token.isascii() or not secrets.compare_digest(job["token"], token)):
                raise ScanError(404, "Scan not found")
            if(job["status"] in ("queued", "running")):
                job["status"] = "cancelled"
                job["cancel"].set()
            return {key: job[key] for key in ("id", "domain", "status", "result", "error")}

    def close(self):
        with self.lock:
            self.closed.set()
            for job in self.jobs.values():
                job["cancel"].set()
                if(job["status"] in ("queued", "running")):
                    job["status"] = "cancelled"
        self.worker.join(timeout=2)

    def _work(self):
        while not self.closed.is_set():
            try:
                scan_id = self.pending.get(timeout=0.25)
            except queue.Empty:
                with self.lock:
                    self._clean(self.clock())
                continue
            try:
                with self.lock:
                    job = self.jobs.get(scan_id)
                    if(job is None or job["status"] != "queued"):
                        continue
                    job["status"] = "running"
                    domain = job["domain"]
                    cancel = job["cancel"]
                try:
                    result = self.scanner(domain, cancel) if self.cancellable else self.scanner(domain)
                    encode_result(result)
                except Exception:
                    with self.lock:
                        job = self.jobs.get(scan_id)
                        if(job is not None and job["status"] == "running"):
                            job["status"] = "failed"
                            job["error"] = "Scan could not be completed"
                else:
                    with self.lock:
                        job = self.jobs.get(scan_id)
                        if(job is not None and job["status"] == "running"):
                            job["status"] = "complete"
                            job["result"] = result
            finally:
                self.pending.task_done()
