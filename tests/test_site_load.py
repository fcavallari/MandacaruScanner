"""Site-mode loads: one page load captures what the site check needs (served HTML, links,
script initiators, per-buffer YARA, challenge pages)."""
import json
import os

import pytest

from _support import _site_engine, requires_browser, requires_yara, site_server, yara_rules_dir  # noqa: F401


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_site_load_captures_served_links_scripts_and_injection(site_server, tmp_path, yara_rules_dir):
    from pnakotic.src.scanner.engine import LoadOptions

    engine = _site_engine(tmp_path)   # host_allowed: 127.0.0.1 and localhost
    async with engine.browser_session() as (browser, _proxy):
        r = await engine._scan_in_context(browser, f"{site_server}/", "default", engine.artifacts.create_task_folder("j"),
                                          primary=True, options=LoadOptions(site=True, shot_dir="pages/0/default"))
    assert r.metadata["main_status"] == 200 and r.metadata["served_bytes"] > 0
    assert f"{site_server}/about" in r.metadata["links"]
    assert any(rec["url"].endswith("/payload.js") and rec["initiator"] == "script" for rec in r.metadata["script_requests"])
    [inj] = r.metadata["injections"]
    assert inj["initiator_kind"] == "inline" and inj["block"] is not None
    assert r.metadata["challenge"] is False
    evidence = [json.loads(h.evidence) for h in r.hops if h.mechanism == "yara_match"]
    srcs = {e["source"] for e in evidence}
    assert "script" in srcs
    script_hit = next(e for e in evidence if e["source"] == "script")
    assert script_hit["url"].endswith("/payload.js") and script_hit["offset"] == 4
    assert script_hit["context"] is not None and isinstance(script_hit["buffer_index"], int)
    assert os.path.isdir(tmp_path / "j" / "pages" / "0" / "default")
    assert [f for f in os.listdir(tmp_path / "j" / "pages" / "0" / "default") if f.startswith("landing_")]


@requires_browser
@pytest.mark.asyncio
async def test_site_load_flags_challenge(site_server, tmp_path):
    from pnakotic.src.scanner.engine import LoadOptions

    engine = _site_engine(tmp_path)
    async with engine.browser_session() as (browser, _):
        r = await engine._scan_in_context(browser, f"{site_server}/challenge", "googlebot", engine.artifacts.create_task_folder("j"),
                                          primary=False, options=LoadOptions(site=True, shot_dir="pages/1/googlebot", full_page=False))
    assert r.metadata["challenge"] is True and r.metadata["main_status"] == 403


@requires_browser
@pytest.mark.asyncio
async def test_site_load_finishes_when_the_main_document_never_ends(site_server, tmp_path, monkeypatch):
    import asyncio
    import time
    from pnakotic.src.scanner import engine as engine_mod
    from pnakotic.src.scanner.engine import LoadOptions

    # Short waits elsewhere (the screenshot also waits on a still-loading document) keep this
    # test fast; the served-body bound itself stays at its real 5 s.
    monkeypatch.setattr(engine_mod, "SETTLE_MS", 500)
    monkeypatch.setattr(engine_mod, "SCREENSHOT_TIMEOUT_MS", 1000)
    engine = _site_engine(tmp_path)
    engine.timeout_ms = 3000
    started = time.monotonic()
    async with engine.browser_session() as (browser, _):
        r = await asyncio.wait_for(engine._scan_in_context(
            browser, f"{site_server}/stream", "default", engine.artifacts.create_task_folder("j"),
            primary=False, options=LoadOptions(site=True, shot_dir="pages/2/default", full_page=False)), 25)
    assert r.metadata["main_status"] == 200 and r.metadata["served_bytes"] == 0
    assert time.monotonic() - started < 15


@requires_browser
@pytest.mark.asyncio
async def test_probe_load_without_options_has_no_site_metadata(site_server, tmp_path):
    engine = _site_engine(tmp_path)
    async with engine.browser_session() as (browser, _):
        r = await engine._scan_in_context(browser, f"{site_server}/", "default", engine.artifacts.create_task_folder("j"),
                                          primary=True)
    for key in ("main_status", "served_bytes", "links", "script_requests", "injections", "challenge"):
        assert key not in r.metadata
    assert os.path.isdir(tmp_path / "j" / "screenshots")


def test_looks_like_challenge():
    from pnakotic.src.scanner.challenge import looks_like_challenge

    assert looks_like_challenge(403, "Just a moment...", "<html>")
    # Cloudflare injects challenge-platform scripts into ordinary pages: only a small 403/503 counts
    assert not looks_like_challenge(200, "Home", '<script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>')
    assert looks_like_challenge(403, "", '<script src="/cdn-cgi/challenge-platform/h/b"></script>')
    assert not looks_like_challenge(403, "", '<script src="/cdn-cgi/challenge-platform/h/b"></script>' + "x" * 20000)
    assert not looks_like_challenge(403, "Forbidden", "<h1>Forbidden</h1>")
    assert looks_like_challenge(503, "", "<p>Please complete the CAPTCHA</p>")
    assert not looks_like_challenge(200, "", "<p>Please complete the CAPTCHA</p>")  # only on 403/503
    assert not looks_like_challenge(403, "", "<p>captcha</p>" + "x" * 20000)  # too big to be a bare challenge
    assert looks_like_challenge(None, "Attention Required! | Cloudflare", "")
    assert looks_like_challenge(200, "", "<script>window._cf_chl_opt={}</script>")
