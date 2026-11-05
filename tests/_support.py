"""Helpers shared by the browser and YARA test modules.

Test modules import from here as ``from _support import ...`` (pytest's default import
mode puts ``tests/`` on ``sys.path``). A fixture is made available to a module with
``from _support import <fixture>  # noqa: F401``.
"""
import pytest


def _browser_available() -> bool:
    """Skip live-browser tests when Chromium isn't installed (e.g. CI without `playwright install`)."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


requires_browser = pytest.mark.skipif(
    not _browser_available(),
    reason="Chromium not installed (run: playwright install chromium)",
)


# ---------- YARA: synthetic rules only (the real rule sets are private) ----------

def _yara_available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


requires_yara = pytest.mark.skipif(not _yara_available(), reason="yara-python not installed")

_RULE = """rule {name} : {tag} {{
  meta:
    signatureId = {sid}
    production = {production}
    severity = {severity}
    description = "{description}"
    targetLanguage = "raw"
  strings:
    $a = "{marker}"
  condition:
    $a and filename != "ignore-me"
}}
"""


def _rules_dir(tmp_path):
    """A rules tree split by target: html/ and raw/js_* are used, raw/php_* and php/ are not."""
    root = tmp_path / "YARA"
    for sub in ("html", "raw", "php"):
        (root / sub).mkdir(parents=True)

    def rule(path, name, marker, severity, production=True):
        tag = "production" if production else "exploratory"
        path.write_text(_RULE.format(name=name, tag=tag, sid=42000000 + len(name), severity=severity,
                                     production=str(production).lower(), marker=marker,
                                     description=f"Synthetic {name}"))

    rule(root / "raw" / "js_skimmer_test_001.yara", "js_skimmer_test_001", "PNAKOTIC_TEST_SKIMMER", 5)
    rule(root / "html" / "html_adframe_test_001.yara", "html_adframe_test_001", "PNAKOTIC_TEST_ADFRAME", 4,
         production=False)
    rule(root / "raw" / "php_ignored_test_001.yara", "php_ignored_test_001", "shop", 5)
    rule(root / "php" / "php_backdoor_test_001.yara", "php_backdoor_test_001", "news", 5)
    (root / "raw" / "js_broken_test_001.yara").write_text("rule js_broken_test_001 { condition: nope(")
    return root


@pytest.fixture
def yara_rules_dir(tmp_path, monkeypatch):
    root = _rules_dir(tmp_path)
    monkeypatch.setenv("YARA_RULES_DIR", str(root))
    return root


# ---------- site-mode loads against a local server ----------

def _site_engine(tmp_path):
    """Engine whose egress policy allows only 127.0.0.1 and localhost (two hosts, so a
    script on `localhost` is on another site than a page on `127.0.0.1`)."""
    from pnakotic.src.scanner.artifacts import ArtifactManager
    from pnakotic.src.scanner.engine import PnakoticEngine

    async def loopback_names(host):
        return host in ("127.0.0.1", "localhost")

    engine = PnakoticEngine(task_id="site-job", timeout_ms=10000, host_allowed=loopback_names)
    engine.artifacts = ArtifactManager(base_dir=str(tmp_path))
    return engine


@pytest.fixture(scope="module")
def site_server():
    """127.0.0.1 server for site-mode loads. Yields its base URL."""
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Server(ThreadingHTTPServer):
        daemon_threads = True

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # chunked /stream needs it

        def log_message(self, *args):
            pass

        def _send(self, status, content_type, body):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            port = self.server.server_address[1]
            if self.path == "/":  # the Task 5 loader shape, injecting a script from another site
                self._send(200, "text/html", (
                    "<html><head><title>Shop</title></head><body><a href='/about'>About</a><script>"
                    ";;(function(f,i,u,w,s){w=f.createElement(i);s=f.getElementsByTagName(i)[0];"
                    "w.async=1;w.src=u;s.parentNode.insertBefore(w,s);})"
                    f"(document,'script','http://localhost:{port}/payload.js');"
                    "</script></body></html>").encode())
            elif self.path == "/payload.js":
                self._send(200, "text/javascript", b"var PNAKOTIC_TEST_SKIMMER = 1;")
            elif self.path == "/challenge":
                self._send(403, "text/html", b"<html><head><title>One more step</title></head><body>"
                                             b"<script src=\"/cdn-cgi/challenge-platform/h/b\"></script>"
                                             b"</body></html>")
            elif self.path == "/stream":  # a main document that never finishes (chunked, no length)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                chunk = b"<html><body><p>still loading</p>"
                try:
                    for _ in range(300):  # 30 s at most, then the thread gives up
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass  # the browser went away
            elif self.path == "/clean.js":
                self._send(200, "text/javascript", b"var clean = 1;")
            else:
                self._send(404, "text/html", b"<html><body>Not found</body></html>")

    srv = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


# ---------- site-check loads built by hand (no browser) ----------

def _yara_hop(source, url, rule, sev, production, offset, text):
    """A per-buffer `yara_match` hop as a site-mode load records it."""
    import json

    from pnakotic.src.scanner.models import RedirectHop
    from pnakotic.src.scanner.yara_scan import YARA_MECHANISM

    return RedirectHop(url=url, mechanism=YARA_MECHANISM, evidence=json.dumps({
        "id": "yara_match", "rule": rule, "signature_id": 1, "severity": sev, "production": production,
        "description": f"Synthetic {rule}", "source": source, "url": url, "offset": offset,
        "buffer_index": 0, "hits": 1,
        "context": {"text": text, "match_start": 0, "match_end": len(text), "line": 1},
    }))


def _load(page_index, page_url, profile, hops=(), injections=(), state="checked", reason=None, final_url=None,
          script_requests=(), score=0.0):
    """A site-check Load around a hand-built ScanResult."""
    from pnakotic.src.scanner.models import ScanResult
    from pnakotic.src.scanner.site_findings import Load

    result = ScanResult(target_url=page_url, final_url=final_url or page_url, hops=list(hops), malicious_score=score)
    result.metadata = {
        "injections": list(injections), "script_requests": list(script_requests),
        "scoring_findings": [], "decisive_findings": [], "cloaking": None,
    }
    return Load(page_index=page_index, page_url=page_url, profile=profile, state=state, reason=reason,
                result=result, shot=None)


def _result(**metadata):
    """A ScanResult carrying just the given metadata (plus a page title, default "x")."""
    from pnakotic.src.scanner.models import ScanResult

    signals = {"title": metadata.pop("title", "x")}
    return ScanResult(target_url="https://s.com/", final_url="https://s.com/",
                      metadata={"page_signals": signals, **metadata})
