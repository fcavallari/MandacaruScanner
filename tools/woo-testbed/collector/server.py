"""Test collector: appends every request it receives to requests.jsonl.

Stands in for a skimmer's drop server. Standard library only.

Hardening (it listens on 127.0.0.1 only, but any web page the dev browser opens
can reach it):
  - Content-Length is parsed defensively: missing means no body; non-numeric or
    negative gets 400 and the connection is closed.
  - A body over MAX_BODY gets 413 and the connection is closed (nothing is read,
    so no leftover bytes can be parsed as the next request).
  - Transfer-Encoding (chunked) gets 411 and the connection is closed.
  - Slow clients are dropped after READ_TIMEOUT seconds.
  - requests.jsonl stops growing at MAX_LOG_BYTES; later requests are counted
    (GET /__stats) but not written.
  - CORS headers are sent only to the testbed store's own origins.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LOG = os.environ.get("COLLECTOR_LOG", "requests.jsonl")
MAX_BODY = 1_000_000
MAX_LOG_BYTES = int(os.environ.get("COLLECTOR_MAX_LOG_BYTES", 50 * 1024 * 1024))
READ_TIMEOUT = 10
_woo_port = os.environ.get("WOO_PORT", "8188")
ALLOWED_ORIGINS = {f"http://localhost:{_woo_port}", f"http://127.0.0.1:{_woo_port}"}

_lock = threading.Lock()
_stats = {"logged": 0, "skipped_log_full": 0, "rejected": 0}


def _append(record: dict) -> None:
    line = json.dumps(record) + "\n"
    with _lock:
        try:
            size = os.path.getsize(LOG)
        except OSError:
            size = 0
        if size + len(line.encode("utf-8")) > MAX_LOG_BYTES:
            _stats["skipped_log_full"] += 1
            if _stats["skipped_log_full"] in (1, 100, 10_000):
                print(f"log full ({size} bytes): skipping requests, {_stats['skipped_log_full']} so far", flush=True)
            return
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
        _stats["logged"] += 1


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = READ_TIMEOUT

    def _reply(self, status: int, body: bytes = b"", close: bool = False, content_type: str = "") -> None:
        self.send_response(status)
        origin = self.headers.get("Origin")
        if origin in ALLOWED_ORIGINS:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Vary", "Origin")
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if close:
            self.close_connection = True
            self.send_header("Connection", "close")
        self.end_headers()
        if body and self.command != "HEAD":
            self.wfile.write(body)

    def _reject(self, status: int) -> None:
        with _lock:
            _stats["rejected"] += 1
        self._reply(status, close=True)

    def _handle(self):
        parts = urlsplit(self.path)

        if self.headers.get("Transfer-Encoding"):
            return self._reject(411)

        raw_len = self.headers.get("Content-Length")
        length = 0
        if raw_len is not None:
            raw_len = raw_len.strip()
            if not raw_len.isascii() or not raw_len.isdigit():
                return self._reject(400)
            length = int(raw_len)
            if length > MAX_BODY:
                return self._reject(413)

        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""

        if parts.path == "/__health":
            return self._reply(204)
        if parts.path == "/__stats":
            with _lock:
                payload = dict(_stats)
            try:
                payload["log_bytes"] = os.path.getsize(LOG)
            except OSError:
                payload["log_bytes"] = 0
            payload["max_log_bytes"] = MAX_LOG_BYTES
            return self._reply(200, json.dumps(payload).encode(), content_type="application/json")

        _append({
            "ts": time.time(),
            "method": self.command,
            "path": parts.path,
            "query": parts.query,
            "body": body,
            "origin": self.headers.get("Origin") or self.headers.get("Referer") or "",
            "content_type": self.headers.get("Content-Type") or "",
        })
        self._reply(204)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8199), Handler).serve_forever()
