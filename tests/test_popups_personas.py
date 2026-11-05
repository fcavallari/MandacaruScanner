"""Popup capture, the click probe, and visitor personas (docs/forum-gap-analysis.md §4, items 1-2)."""
import json

import pytest



def _browser_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            p.chromium.launch(headless=True).close()
        return True
    except Exception:
        return False


requires_browser = pytest.mark.skipif(
    not _browser_available(), reason="Chromium not installed (run: playwright install chromium)")


# ---------- offline: personas and scoring ----------

def test_user_agent_follows_the_real_browser():
    from pnakotic.src.scanner.profiles import PROFILES, FALLBACK_CHROME_MAJOR

    assert "Chrome/145.0.0.0 " in PROFILES["default"].user_agent_for("145.0.7632.6")
    assert "Chrome/145.0.0.0 " in PROFILES["googlebot"].user_agent_for("145.0.7632.6")
    assert "Googlebot/2.1" in PROFILES["googlebot"].user_agent_for("145.0.7632.6")
    assert f"Chrome/{FALLBACK_CHROME_MAJOR}.0.0.0" in PROFILES["default"].user_agent_for("")
    for profile in PROFILES.values():
        assert "{chrome}" not in profile.user_agent_for("145.0.1.2")


def test_facebook_persona_looks_like_the_in_app_browser():
    from pnakotic.src.scanner.profiles import PROFILES

    fb = PROFILES["facebook-android"]
    assert "FB_IAB/FB4A" in fb.user_agent and "; wv)" in fb.user_agent
    assert fb.extra_headers["Referer"] == "https://l.facebook.com/"
    assert fb.is_mobile and fb.has_touch


def _hop(mechanism, url, to, trigger="load"):
    from pnakotic.src.scanner.models import RedirectHop

    return RedirectHop(url=url, mechanism=mechanism,
                       evidence=json.dumps({"id": mechanism, "to": to, "trigger": trigger}))


def _score(hops, final_url="https://blog.example.com/"):
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import ScanResult

    result = ScanResult(target_url=final_url, final_url=final_url, hops=hops)
    PnakoticScorer().score(result)
    return result


def test_cross_site_popup_scores_once_and_same_site_does_not():
    page = "https://blog.example.com/post"
    same = _score([_hop("popup_open", page, "https://shop.example.com/share")])
    cross = _score([
        _hop("popup_open", page, "https://ads.prize-wheel.top/r", trigger="click"),
        _hop("popup_open", page, "https://ads.prize-wheel.top/r2"),
    ])
    weight = cross.malicious_score - same.malicious_score
    assert weight == pytest.approx(0.3)  # popup_cross_site, applied once for two popups
    assert "Popup to another site on click: ads.prize-wheel.top" in cross.metadata["scoring_findings"]
    assert not any("Popup" in f for f in same.metadata["scoring_findings"])


def test_relative_popup_is_same_site():
    result = _score([_hop("popup_open", "https://blog.example.com/", "/newsletter")])
    assert not any("Popup" in f for f in result.metadata["scoring_findings"])


def test_click_hijack_scores_and_is_not_a_redirect():
    from pnakotic.src.scanner.models import REDIRECT_MECHANISMS

    assert "click_hijack" not in REDIRECT_MECHANISMS and "popup_open" not in REDIRECT_MECHANISMS
    base = _score([])
    hijack = _score([_hop("click_hijack", "https://blog.example.com/", "https://win.example.xyz/", "click")])
    assert hijack.malicious_score - base.malicious_score == pytest.approx(0.4)
    assert "Click on the page sent it to another site: win.example.xyz" in hijack.metadata["scoring_findings"]


def test_malformed_popup_evidence_is_ignored():
    from pnakotic.src.scanner.models import RedirectHop

    hops = [
        RedirectHop(url="https://a.example.com/", mechanism="popup_open", evidence="not json"),
        RedirectHop(url="https://a.example.com/", mechanism="popup_open", evidence="[1, 2]"),
        _hop("popup_open", "https://a.example.com/", "http://[::1"),
    ]
    result = _score(hops)
    assert not any("Popup" in f for f in result.metadata["scoring_findings"])


# ---------- engine against a local server ----------

PAGES = {
    # Fires on load, without a gesture (real Chrome's popup blocker would stop this one).
    "/pop-load": b"<html><body>x<script>window.open('http://localhost/ad-load')</script></body></html>",
    # Popunder: waits for the visitor's first click anywhere.
    "/pop-click": (b"<html><body style='height:1200px'>x<script>document.addEventListener('click',"
                   b"function(){window.open('http://localhost/ad-click')},{once:true})</script></body></html>"),
    "/pop-storm": b"<html><body><script>for(var i=0;i<40;i++)window.open('/p'+i)</script></body></html>",
    # Click hijack: the first click anywhere sends the tab away.
    "/hijack": (b"<html><body style='height:1200px'>x<script>document.addEventListener('click',"
                b"function(){location.href='/elsewhere'},{once:true})</script></body></html>"),
    "/ua": b"<html><body><script>document.title=navigator.userAgent</script></body></html>",
}


@pytest.fixture(scope="module")
def popup_site():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            seen.append((self.path, dict(self.headers)))
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(PAGES.get(self.path, b"<html><body>plain</body></html>"))

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", seen
    srv.shutdown()


def _engine(tmp_path):
    from pnakotic.src.scanner.artifacts import ArtifactManager
    from pnakotic.src.scanner.engine import PnakoticEngine

    async def only_loopback_literal(host):
        return host == "127.0.0.1"

    engine = PnakoticEngine(task_id="popup-job", timeout_ms=10000, host_allowed=only_loopback_literal)
    engine.artifacts = ArtifactManager(base_dir=str(tmp_path))
    return engine


def _popups(result):
    return [json.loads(h.evidence) for h in result.hops if h.mechanism == "popup_open"]


@requires_browser
@pytest.mark.asyncio
async def test_popup_on_load_is_recorded_not_loaded(popup_site, tmp_path):
    base, seen = popup_site
    result = await _engine(tmp_path).scan(f"{base}/pop-load")
    pops = _popups(result)
    assert [(p["to"], p["trigger"]) for p in pops] == [("http://localhost/ad-load", "load")]
    assert result.final_url == f"{base}/pop-load"  # the visitor's tab never moved
    assert result.is_redirect_chain_detected is False
    assert not any(path == "/ad-load" for path, _ in seen)  # blocked: nothing was fetched
    assert any("Popup to another site: localhost" in f for f in result.metadata["scoring_findings"])


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["default", "mobile-android"])  # touch emulation must not eat the click
async def test_click_probe_catches_a_popunder(popup_site, tmp_path, profile):
    base, _seen = popup_site
    result = await _engine(tmp_path).scan(f"{base}/pop-click", profile_name=profile)
    assert result.metadata["click_probe"] == "clicked"
    pops = _popups(result)
    assert len(pops) == 1
    assert pops[0]["trigger"] == "click" and pops[0]["user_gesture"] is True
    assert any("Popup to another site on click" in f for f in result.metadata["scoring_findings"])


@requires_browser
@pytest.mark.asyncio
async def test_popup_storm_is_capped(popup_site, tmp_path):
    from pnakotic.src.scanner.engine import MAX_POPUP_HOPS

    base, _seen = popup_site
    result = await _engine(tmp_path).scan(f"{base}/pop-storm")
    assert len(_popups(result)) == MAX_POPUP_HOPS
    assert result.metadata["popups_dropped"] == 40 - MAX_POPUP_HOPS


@requires_browser
@pytest.mark.asyncio
async def test_click_hijack_is_evidence_and_keeps_the_landing(popup_site, tmp_path):
    base, _seen = popup_site
    result = await _engine(tmp_path).scan(f"{base}/hijack")
    hijacks = [json.loads(h.evidence) for h in result.hops if h.mechanism == "click_hijack"]
    assert len(hijacks) == 1 and hijacks[0]["to"].endswith("/elsewhere")
    assert result.final_url == f"{base}/hijack"  # the landing is what loaded, not where the click went
    assert result.is_redirect_chain_detected is False


@requires_browser
@pytest.mark.asyncio
async def test_plain_page_has_no_popup_evidence(popup_site, tmp_path):
    base, _seen = popup_site
    result = await _engine(tmp_path).scan(f"{base}/plain")
    assert result.metadata["click_probe"] == "clicked"
    assert not [h for h in result.hops if h.mechanism in ("popup_open", "click_hijack")]


@requires_browser
@pytest.mark.asyncio
async def test_facebook_persona_sends_its_headers(popup_site, tmp_path):
    base, seen = popup_site
    await _engine(tmp_path).scan(f"{base}/ua", profile_name="facebook-android")
    headers = next(h for path, h in reversed(seen) if path == "/ua")
    assert headers.get("Referer") == "https://l.facebook.com/"
    assert headers.get("X-Requested-With") == "com.facebook.katana"
    assert "FB_IAB/FB4A" in headers.get("User-Agent", "")
    assert "{chrome}" not in headers["User-Agent"] and "HeadlessChrome" not in headers["User-Agent"]
    assert "Headless" not in headers.get("sec-ch-ua", "")
    assert '"Android WebView"' in headers.get("sec-ch-ua", "")
    assert headers.get("sec-ch-ua-platform") == '"Android"'


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["default", "mobile-android", "googlebot", "mobile-ios"])
async def test_no_persona_names_headless_chrome(popup_site, tmp_path, profile):
    base, seen = popup_site
    result = await _engine(tmp_path).scan(f"{base}/ua", profile_name=profile)
    headers = next(h for path, h in reversed(seen) if path == "/ua")
    assert "Headless" not in headers.get("sec-ch-ua", "") and "Headless" not in headers["User-Agent"]
    # navigator.userAgent (read by in-page cloaking scripts) matches the header
    assert result.metadata["page_signals"]["title"] == headers["User-Agent"]
