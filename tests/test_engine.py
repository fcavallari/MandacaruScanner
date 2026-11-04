import os
import asyncio
import base64

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


@requires_browser
@pytest.mark.asyncio
async def test_benign_scan():
    from pnakotic.src.scanner.engine import PnakoticEngine

    engine = PnakoticEngine(task_id="test-job")
    result = await engine.scan("https://www.google.com")
    assert result.target_url == "https://www.google.com"
    # google.com's inline scripts may trip the js_location heuristic (0.4); a direct,
    # unredirected visit must never read as "malicious" (> 0.6).
    assert result.malicious_score < 0.6
    assert result.is_redirect_chain_detected is False


@requires_browser
@pytest.mark.asyncio
async def test_redirect_detection():
    from pnakotic.src.scanner.engine import PnakoticEngine

    engine = PnakoticEngine(task_id="test-job")
    # http://google.com redirects to https://www.google.com/
    result = await engine.scan("http://google.com")
    assert result.is_redirect_chain_detected is True
    assert len(result.hops) >= 1


def test_artifact_safety(tmp_path):
    from pnakotic.src.scanner.artifacts import ArtifactManager

    am = ArtifactManager(base_dir=str(tmp_path / "vault"))
    with pytest.raises(ValueError):
        am.create_task_folder("../../../etc/passwd")
    with pytest.raises(ValueError):
        am.create_task_folder("!@#$%^&*")


def test_artifact_manifest_recurses(tmp_path):
    from pnakotic.src.scanner.artifacts import ArtifactManager

    am = ArtifactManager(base_dir=str(tmp_path / "vault"))
    folder = am.create_task_folder("job-1")
    (tmp_path / "vault" / "job-1" / "screenshots").mkdir()
    (tmp_path / "vault" / "job-1" / "screenshots" / "landing.png").write_bytes(b"x")

    manifest = am.get_task_manifest("job-1")
    rel_paths = [a["rel_path"] for a in manifest["artifacts"]]
    assert "screenshots/landing.png" in rel_paths


def test_scoring_ip_landing():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    result = ScanResult(target_url="http://1.2.3.4/", final_url="http://1.2.3.4/")
    result.hops = [RedirectHop(url="http://1.2.3.4/", status_code=302, mechanism="http_3xx")]
    score = PnakoticScorer().score(result)
    assert score >= 0.5  # ip_landing weight


def test_scoring_meta_refresh_and_high_value():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    result = ScanResult(target_url="http://junk.tk/", final_url="https://www.google.com/")
    result.hops = [RedirectHop(url="http://junk.tk/", mechanism="meta_refresh")]
    score = PnakoticScorer().score(result)
    # meta_refresh (0.25) + high_value_landing after a redirect (0.2); final TLD is .com
    assert abs(score - 0.45) < 1e-9


def test_scoring_suspicious_tld():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    result = ScanResult(target_url="http://x.tk/", final_url="http://x.tk/")
    assert PnakoticScorer().score(result) == pytest.approx(0.3)


def test_static_analyzer_b64_filter():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    analyst = StaticAnalyst()
    # 64-char hex hash: long alnum run, no +/= -> filtered out (no findings)
    html = "<script>var h='a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1';</script>"
    assert analyst.analyze_content(html) == []

    # Real base64 payload (>= 60 chars, contains '/') -> detected
    payload = base64.b64encode(b"\xff" * 60).decode()  # '////' * 20
    findings = analyst.analyze_content(f"<script>var p='{payload}';</script>")
    assert any(f["id"] == "b64_payload" for f in findings)


def test_static_analyzer_meta_refresh_order_independent():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    analyst = StaticAnalyst()
    content_first = '<meta content="0; url=https://x.example" http-equiv="refresh">'
    equiv_first = '<meta http-equiv="refresh" content="0; url=https://x.example">'
    assert any(f["id"] == "meta_refresh" for f in analyst.analyze_content(content_first))
    assert any(f["id"] == "meta_refresh" for f in analyst.analyze_content(equiv_first))


def test_static_analyzer_js_location_variants():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    analyst = StaticAnalyst()
    for html in (
        "<script>window.location='https://x.example';</script>",
        "<script>document.location.href = \"https://x.example\";</script>",
        "<script>location.replace('https://x.example');</script>",
    ):
        assert any(f["id"] == "js_location_assignment" for f in analyst.analyze_content(html)), html


# ---------- fixes from review: timestamps, obfuscation, deep_chain ----------

def test_hop_and_result_timestamps_are_per_instance():
    import time
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    a = RedirectHop(url="http://a.example/", mechanism="http_3xx")
    r1 = ScanResult(target_url="http://a.example/")
    time.sleep(0.01)
    b = RedirectHop(url="http://b.example/", mechanism="http_3xx")
    r2 = ScanResult(target_url="http://b.example/")
    assert b.timestamp > a.timestamp
    assert r2.start_time > r1.start_time


def test_obfuscation_signatures_are_not_redirects():
    from pnakotic.src.scanner.models import REDIRECT_MECHANISMS
    from pnakotic.src.scanner.static_analyzer import SIGNATURE_MECHANISMS

    for sig in ("js_atob", "js_fromCharCode"):
        assert SIGNATURE_MECHANISMS[sig] not in REDIRECT_MECHANISMS
    # Regex hits only show redirect code is present; a redirect that fires is observed via CDP.
    for sig in ("js_location_assignment", "meta_refresh"):
        assert SIGNATURE_MECHANISMS[sig] not in REDIRECT_MECHANISMS
    assert SIGNATURE_MECHANISMS["js_location_assignment"] == "js_location_code"
    assert SIGNATURE_MECHANISMS["meta_refresh"] == "meta_refresh_code"


def test_scoring_obfuscation_counted_once():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    result = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    result.hops = [
        RedirectHop(url="https://x.example/", mechanism="js_obfuscation"),  # atob
        RedirectHop(url="https://x.example/", mechanism="js_obfuscation"),  # fromCharCode
    ]
    assert PnakoticScorer().score(result) == pytest.approx(0.4)


def test_scoring_deep_chain_ignores_static_hops():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    passive = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    passive.hops = [RedirectHop(url="https://x.example/", mechanism="static_analysis") for _ in range(6)]
    assert PnakoticScorer().score(passive) == 0.0

    deep = ScanResult(target_url="https://x.example/", final_url="https://y.example/")
    deep.hops = [RedirectHop(url=f"https://h{i}.example/", status_code=302, mechanism="http_3xx") for i in range(6)]
    assert PnakoticScorer().score(deep) == pytest.approx(0.2)


def test_scoring_redirect_code_present_counted_once():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    result = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    result.hops = [
        RedirectHop(url="https://x.example/", mechanism="meta_refresh_code"),
        RedirectHop(url="https://x.example/", mechanism="meta_refresh_code"),
        RedirectHop(url="https://x.example/", mechanism="js_location_code"),
        RedirectHop(url="https://x.example/", mechanism="js_location_code"),
        RedirectHop(url="https://x.example/", mechanism="js_location_code"),
    ]
    assert PnakoticScorer().score(result) == pytest.approx(0.25)  # 0.1 + 0.15, once each
    findings = result.metadata["scoring_findings"]
    assert findings.count("Meta refresh code present (did not fire)") == 1
    assert findings.count("JS location code present (did not fire)") == 1


def test_launch_options_channel(monkeypatch):
    from pnakotic.src.scanner.engine import launch_options

    monkeypatch.delenv("BROWSER_CHANNEL", raising=False)
    opts = launch_options(4321)
    assert "channel" not in opts
    assert opts["chromium_sandbox"] is True
    assert opts["proxy"] == {"server": "socks5://127.0.0.1:4321"}

    monkeypatch.setenv("BROWSER_CHANNEL", " chrome ")
    assert launch_options(1)["channel"] == "chrome"


# ---------- engine against a local server (offline) ----------

@pytest.fixture(scope="module")
def local_site():
    """127.0.0.1 server. Records (Host header, path) for every request it receives."""
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    hits = []

    class Server(ThreadingHTTPServer):
        daemon_threads = True  # /slow sleeps 20 s; don't let it hold up interpreter exit

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            hits.append((self.headers.get("Host", "").split(":")[0], self.path))
            port = self.server.server_address[1]
            redirects = {
                "/r": "/target",
                "/imgr": "/img",
                "/to-internal": f"http://localhost:{port}/target",
            }
            if self.path in redirects:
                self.send_response(302)
                self.send_header("Location", redirects[self.path])
                self.end_headers()
                return
            if self.path == "/slow":  # a response that outlives any test timeout
                time.sleep(20)
                try:
                    self.send_response(200)
                    self.end_headers()
                except OSError:
                    pass
                return
            if self.path == "/ok-ws":  # an allowed WebSocket upgrade: arriving is the point
                self.send_response(400)
                self.end_headers()
                return
            if self.path == "/sw.js":
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript")
                self.end_headers()
                self.wfile.write(f'fetch("http://localhost:{port}/leak-sw");'.encode())
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            if self.path == "/ws-main":
                self.wfile.write(f"<html><body><script>new WebSocket('ws://localhost:{port}/leak-ws');</script></body></html>".encode())
            elif self.path == "/ws-worker":
                src = f"new WebSocket('ws://localhost:{port}/leak-ws-worker');"
                self.wfile.write(
                    f"<html><body><script>new Worker(URL.createObjectURL(new Blob([\"{src}\"])));</script></body></html>".encode())
            elif self.path == "/shared-worker":
                self.wfile.write(b"<html><body><script>new SharedWorker('/sw.js');</script></body></html>")
            elif self.path == "/ws-allowed":
                self.wfile.write(f"<html><body><script>new WebSocket('ws://127.0.0.1:{port}/ok-ws');</script></body></html>".encode())
            elif self.path == "/js":
                self.wfile.write(b"<html><script>window.location='/r'</script></html>")
            elif self.path == "/meta":
                self.wfile.write(b"<html><meta http-equiv='refresh' content='0;url=/target'></html>")
            elif self.path == "/delayed":  # 9 s: must not fire during the scan (10 s page timeout, ~1 s of work after load)
                self.wfile.write(b"<html><body>wait<script>setTimeout(function(){location.replace('/target')},9000)</script></body></html>")
            elif self.path == "/js-loop-a":
                self.wfile.write(b"<html><script>window.location='/js-loop-b'</script></html>")
            elif self.path == "/js-loop-b":
                self.wfile.write(b"<html><script>window.location='/js-loop-a'</script></html>")
            elif self.path == "/never-idle":
                self.wfile.write(b"<html><body>ok<script>atob('aGVsbG8=')</script><img src='/slow'></body></html>")
            elif self.path == "/with-pixel":
                self.wfile.write(b"<html><body>page<img src='/imgr'></body></html>")
            else:
                self.wfile.write(b"<html><body>ok</body></html>")

    srv = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", hits
    srv.shutdown()


def _local_engine(tmp_path):
    """Engine whose egress policy allows only the literal 127.0.0.1 (so `localhost`,
    the same address under another name, stands in for an internal host)."""
    from pnakotic.src.scanner.artifacts import ArtifactManager
    from pnakotic.src.scanner.engine import PnakoticEngine

    async def only_loopback_literal(host):
        return host == "127.0.0.1"

    engine = PnakoticEngine(task_id="local-job", timeout_ms=10000, host_allowed=only_loopback_literal)
    engine.artifacts = ArtifactManager(base_dir=str(tmp_path))
    return engine


@requires_browser
@pytest.mark.asyncio
async def test_subresource_redirect_is_not_a_chain(local_site, tmp_path):
    base, hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/with-pixel")
    assert ("127.0.0.1", "/img") in hits  # the pixel's redirect really happened
    assert result.is_redirect_chain_detected is False
    assert not [h for h in result.hops if h.mechanism == "http_3xx"]
    assert result.final_url == f"{base}/with-pixel"


@requires_browser
@pytest.mark.asyncio
async def test_main_frame_redirect_is_a_chain(local_site, tmp_path):
    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/r")
    http_hops = [h for h in result.hops if h.mechanism == "http_3xx"]
    assert result.is_redirect_chain_detected is True
    assert [h.url for h in http_hops] == [f"{base}/r"]
    assert result.final_url == f"{base}/target"


@requires_browser
@pytest.mark.asyncio
async def test_redirect_to_internal_host_is_blocked(local_site, tmp_path):
    base, hits = local_site
    hits.clear()
    result = await _local_engine(tmp_path).scan(f"{base}/to-internal")
    assert ("127.0.0.1", "/to-internal") in hits
    assert not [h for h in hits if h[0] == "localhost"]  # the redirect hop never left the browser
    blocked = result.metadata.get("blocked_hosts") or []
    assert "localhost" in blocked
    if not os.environ.get("BROWSER_CHANNEL"):
        assert blocked == ["localhost"]
    else:
        # Branded Chrome phones home at startup (accounts/clients2.google.com, update.googleapis.com,
        # www.google.com, www.gstatic.com) regardless of Playwright's quieting flags; the strict
        # loopback-only test policy blocks those too. The production policy allows them.
        assert all(h == "localhost" or h.endswith((".google.com", ".googleapis.com", ".gstatic.com")) for h in blocked), blocked
    assert "ERR_BLOCKED_BY_CLIENT" in (result.metadata.get("raw_error") or "")
    assert any("non-public host" in f for f in result.metadata["scoring_findings"])


@requires_browser
@pytest.mark.asyncio
async def test_internal_target_is_blocked_by_default_policy(local_site, tmp_path):
    from pnakotic.src.scanner.artifacts import ArtifactManager
    from pnakotic.src.scanner.engine import PnakoticEngine

    base, hits = local_site
    hits.clear()
    engine = PnakoticEngine(task_id="local-job", timeout_ms=10000)  # real policy
    engine.artifacts = ArtifactManager(base_dir=str(tmp_path))
    result = await engine.scan(f"{base}/target")
    assert hits == []
    assert result.metadata.get("blocked_hosts") == ["127.0.0.1"]


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("page, leak", [
    ("/ws-main", "/leak-ws"),               # WebSocket from the main frame
    ("/ws-worker", "/leak-ws-worker"),      # WebSocket from a dedicated worker
    ("/shared-worker", "/leak-sw"),         # fetch() from a SharedWorker (separate CDP target)
])
async def test_websocket_and_shared_worker_cannot_reach_internal_host(local_site, tmp_path, page, leak):
    base, hits = local_site
    hits.clear()
    result = await _local_engine(tmp_path).scan(f"{base}{page}")
    await asyncio.sleep(0.5)  # let any stray connection arrive
    assert not [h for h in hits if h[0] == "localhost" or h[1] == leak]
    assert "localhost" in result.metadata.get("blocked_hosts", [])


@requires_browser
@pytest.mark.asyncio
async def test_allowed_websocket_passes_through_proxy(local_site, tmp_path):
    base, hits = local_site
    hits.clear()
    await _local_engine(tmp_path).scan(f"{base}/ws-allowed")
    await asyncio.sleep(0.5)
    assert ("127.0.0.1", "/ok-ws") in hits


@pytest.mark.asyncio
async def test_egress_proxy_socks5(local_site):
    import struct
    from urllib.parse import urlparse
    from pnakotic.src.scanner.egress_proxy import EgressProxy

    async def only_loopback_literal(host):
        return host == "127.0.0.1"

    async def connect(proxy_port, host, port):
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        w.write(b"\x05\x01\x00")
        assert await r.readexactly(2) == b"\x05\x00"
        w.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode() + struct.pack("!H", port))
        reply = await r.readexactly(10)
        return reply[1], r, w

    base, _hits = local_site
    port = urlparse(base).port
    proxy = EgressProxy(only_loopback_literal)
    proxy_port = await proxy.start()
    try:
        rep, _r, w = await connect(proxy_port, "localhost", port)
        assert rep == 0x02
        assert proxy.blocked_hosts == ["localhost"]
        w.close()

        rep, r, w = await connect(proxy_port, "127.0.0.1", port)
        assert rep == 0x00
        w.write(b"GET /via-proxy HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        assert (await r.read(12)).startswith(b"HTTP/1.")
        w.close()
        assert proxy.blocked_hosts == ["localhost"]
    finally:
        await proxy.stop()


def _redirect_hops(result):
    from pnakotic.src.scanner.models import REDIRECT_MECHANISMS

    return [h for h in result.hops if h.mechanism in REDIRECT_MECHANISMS]


@requires_browser
@pytest.mark.asyncio
async def test_js_redirect_is_recorded(local_site, tmp_path):
    import json

    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/js")
    js_hops = [h for h in result.hops if h.mechanism == "js_location"]
    assert len(js_hops) == 1
    assert js_hops[0].url.endswith("/js")
    evidence = json.loads(js_hops[0].evidence)
    assert evidence["id"] == "js_location"
    assert evidence["reason"] == "scriptInitiated"
    assert evidence["to"].endswith("/r")
    assert [h.url for h in result.hops if h.mechanism == "http_3xx"] == [f"{base}/r"]
    assert result.is_redirect_chain_detected is True
    assert result.final_url.endswith("/target")
    assert len(_redirect_hops(result)) == 2


@requires_browser
@pytest.mark.asyncio
async def test_meta_refresh_is_recorded(local_site, tmp_path):
    import json

    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/meta")
    meta_hops = [h for h in result.hops if h.mechanism == "meta_refresh"]
    assert len(meta_hops) == 1
    assert json.loads(meta_hops[0].evidence)["reason"] == "metaTagRefresh"
    assert result.is_redirect_chain_detected is True
    assert result.final_url.endswith("/target")


@requires_browser
@pytest.mark.asyncio
async def test_delayed_redirect_code_is_not_a_redirect(local_site, tmp_path):
    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/delayed")  # timeout_ms=10000
    assert _redirect_hops(result) == []
    assert [h.mechanism for h in result.hops].count("js_location_code") == 1
    assert result.is_redirect_chain_detected is False
    assert result.final_url == f"{base}/delayed"
    # The 127.0.0.1 landing alone is 0.5 (ip_landing), so assert on what code-present adds:
    # 0.15, where the old regex-as-redirect scoring added 0.4 and read "Malicious" for real hosts.
    findings = result.metadata["scoring_findings"]
    assert not any("JS location manipulation" in f for f in findings)
    assert result.malicious_score == pytest.approx(0.5 + 0.15)


@requires_browser
@pytest.mark.asyncio
async def test_js_redirect_loop_stops_at_max_hops(local_site, tmp_path):
    import time
    from pnakotic.src.scanner.artifacts import ArtifactManager
    from pnakotic.src.scanner.engine import PnakoticEngine

    async def only_loopback_literal(host):
        return host == "127.0.0.1"

    base, _hits = local_site
    engine = PnakoticEngine(task_id="local-job", timeout_ms=10000, max_hops=4,
                            host_allowed=only_loopback_literal)
    engine.artifacts = ArtifactManager(base_dir=str(tmp_path))
    started = time.monotonic()
    result = await engine.scan(f"{base}/js-loop-a")
    assert time.monotonic() - started < 8  # stopped by max_hops, not by the 10 s page timeout
    assert result.metadata["redirect_loop"] is True
    assert len([h for h in result.hops if h.mechanism == "js_location"]) <= 4
    assert result.is_redirect_chain_detected is True


@requires_browser
@pytest.mark.asyncio
async def test_slow_subresource_does_not_skip_analysis(local_site, tmp_path):
    from pnakotic.src.scanner.artifacts import ArtifactManager
    from pnakotic.src.scanner.engine import PnakoticEngine

    async def only_loopback_literal(host):
        return host == "127.0.0.1"

    base, _hits = local_site
    engine = PnakoticEngine(task_id="local-job", timeout_ms=3000, host_allowed=only_loopback_literal)
    engine.artifacts = ArtifactManager(base_dir=str(tmp_path))
    result = await engine.scan(f"{base}/never-idle")  # the <img> holds `load` open past the timeout
    assert result.metadata.get("raw_error") or result.metadata.get("settle_timed_out")
    assert any(h.mechanism == "js_obfuscation" for h in result.hops)
    assert list((tmp_path / "local-job" / "screenshots").glob("*.png"))


@requires_browser
@pytest.mark.asyncio
async def test_analyzer_exception_propagates(local_site, tmp_path):
    base, _hits = local_site
    engine = _local_engine(tmp_path)

    def boom(_html):
        raise RuntimeError("boom")

    engine.analyst.analyze_content = boom
    with pytest.raises(RuntimeError, match="boom"):
        await engine.scan(f"{base}/target")
