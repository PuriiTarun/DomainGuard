from http.server import ThreadingHTTPServer
import threading
import socket
import http.client
import re

MAX_CONNECTIONS = 8
REQUEST_SECONDS = 10
MAX_REQUEST_BYTES = 16384
MAX_BODY_BYTES = 512

class BoundedInput:
    def __init__(self, stream):
        self.stream = stream
        self.remaining = MAX_REQUEST_BYTES
        self.body_read = 0

    def readline(self, size=-1):
        limit = self.remaining + 1
        data = self.stream.readline(limit if size < 0 else min(size, limit))
        self.remaining -= len(data)
        if(self.remaining < 0):
            raise http.client.LineTooLong("request")
        return data

    def read(self, size):
        if(size > self.remaining):
            raise OSError("Request budget exceeded")
        data = self.stream.read(size)
        self.remaining -= len(data)
        self.body_read += len(data)
        return data

    def discard_body(self, headers):
        # Drain only a small, unambiguous body after the response is sent.
        if(headers.defects or headers.get_all("Transfer-Encoding") or headers.get_all("Expect")):
            return
        lengths = headers.get_all("Content-Length", [])
        if(len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,3}", lengths[0])):
            return
        length = int(lengths[0])
        remaining = length - self.body_read
        if(length <= MAX_BODY_BYTES and 0 < remaining <= self.remaining):
            self.read(remaining)

    def close(self):
        self.stream.close()

    @property
    def closed(self):
        return self.stream.closed

def expire_connection(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass

class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, handler):
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if(not self.slots.acquire(blocking=False)):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def server_close(self):
        jobs = getattr(self.RequestHandlerClass, "jobs", None)
        if(jobs is not None):
            jobs.close()
        super().server_close()
