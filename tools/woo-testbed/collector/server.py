"""Test collector: appends every request it receives to requests.jsonl.

Stands in for a skimmer's drop server. Answers every method with 204 and
permissive CORS headers, so no browser-side failure hides a request.
Standard library only.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

LOG = os.environ.get("COLLECTOR_LOG", "requests.jsonl")
MAX_BODY = 1_000_000
_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        parts = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, MAX_BODY)).decode("utf-8", "replace") if length else ""
        if parts.path != "/__health":
            record = {
                "ts": time.time(),
                "method": self.command,
                "path": parts.path,
                "query": parts.query,
                "body": body,
                "origin": self.headers.get("Origin") or self.headers.get("Referer") or "",
                "content_type": self.headers.get("Content-Type") or "",
            }
            with _lock, open(LOG, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8199), Handler).serve_forever()
