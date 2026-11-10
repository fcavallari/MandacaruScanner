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
    assert r.metadata["challenge_vendor"] == "cloudflare"


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
    for key in ("main_status", "served_bytes", "links", "script_requests", "challenge"):
        assert key not in r.metadata
    # The probe does keep the cross-site script injections (the scorer reads them); the
    # homepage's loader is plain and loads a plain script, so there is nothing to score.
    [inj] = r.metadata["injections"]
    assert inj["requested_url"].endswith("/payload.js") and inj["block"] is None  # no served HTML in a probe
    assert r.metadata.get("flagged_scripts") is None
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


def test_challenge_vendor_names_who_showed_the_check():
    from pnakotic.src.scanner.challenge import challenge_vendor

    assert challenge_vendor("Just a moment...", "<html>") == "cloudflare"
    assert challenge_vendor("Attention Required! | Cloudflare", "") == "cloudflare"
    assert challenge_vendor("", "<script>window._cf_chl_opt={}</script>") == "cloudflare"
    assert challenge_vendor("", '<script src="/cdn-cgi/challenge-platform/h/b"></script>') == "cloudflare"
    assert challenge_vendor("DDoS-Guard", "<div>ddos-guard</div>") == "ddos-guard"
    assert challenge_vendor("", '<script src="/_Incapsula_Resource?x=1"></script>') == "incapsula"
    assert challenge_vendor("", "<p>Please complete the CAPTCHA</p>") is None  # a bot check, vendor unknown
    assert challenge_vendor(None, None) is None


@requires_browser
@pytest.mark.asyncio
async def test_site_load_records_a_script_blocked_as_malware_by_the_cdn(site_server, tmp_path):
    from pnakotic.src.scanner.engine import LoadOptions

    engine = _site_engine(tmp_path)
    async with engine.browser_session() as (browser, _proxy):
        r = await engine._scan_in_context(browser, f"{site_server}/flagged/", "default",
                                          engine.artifacts.create_task_folder("j"), primary=True,
                                          options=LoadOptions(site=True, shot_dir="pages/0/default"))
    port = site_server.rsplit(":", 1)[1]
    assert r.metadata["flagged_scripts"] == [
        {"url": f"http://localhost:{port}/blocked.js", "status": 403, "reason": "cloudflare_suspected_malware"}]
    assert any(rec["url"].endswith("/blocked.js") for rec in r.metadata["script_requests"])


@requires_browser
@pytest.mark.asyncio
async def test_site_survey_of_a_page_with_a_cdn_blocked_script_is_suspicious(site_server, tmp_path):
    """End to end: the roll-up a site owner reads flips from Clean to Suspicious."""
    from pnakotic.src.scanner.site_engine import SiteScanner

    outcome = await SiteScanner(_site_engine(tmp_path), budget_s=60).scan(f"{site_server}/flagged/")
    report = outcome.report
    assert report["verdict"]["verdict"] == "suspicious" and report["verdict"]["label"] == "Suspicious"
    port = site_server.rsplit(":", 1)[1]
    by_kind = {b["location_kind"]: b for b in report["blocks"]}
    block = by_kind["script"]
    assert block["location"] == f"http://localhost:{port}/blocked.js"
    assert block["findings"][0]["kind"] == "flagged_script" and block["findings"][0]["severity"] == "suspicious"
    # the flagged script also lifts the page's own score to Suspicious (scorer: flagged_script, 0.4)
    page = by_kind["page"]
    assert page["location"] == f"{site_server}/flagged/" and page["findings"][0]["kind"] == "page_score"
    assert any("blocked by Cloudflare" in line for line in page["findings"][0]["details"]["scoring"])
    [host] = report["external_scripts"]["hosts"]
    assert host["host"] == "localhost" and host["urls"][0]["finding"] is True


@requires_browser
@pytest.mark.asyncio
async def test_url_probe_scores_a_cdn_blocked_script_without_yara(site_server, tmp_path):
    engine = _site_engine(tmp_path)
    r = await engine.scan(f"{site_server}/flagged/", "default", compare=False)
    port = site_server.rsplit(":", 1)[1]
    assert r.malicious_score == pytest.approx(0.5 + 0.4)  # the probe's IP landing (127.0.0.1) plus the flagged script
    assert r.metadata["scoring_findings"] == [
        "IP landing: 127.0.0.1",
        f"Script blocked by Cloudflare as suspected malware: http://localhost:{port}/blocked.js"]


@requires_browser
@pytest.mark.asyncio
async def test_url_probe_scores_a_plain_loader_fetching_an_obfuscated_script(site_server, tmp_path):
    engine = _site_engine(tmp_path)
    r = await engine.scan(f"{site_server}/plainobf/", "default", compare=False)
    port = site_server.rsplit(":", 1)[1]
    assert r.malicious_score == pytest.approx(0.5 + 0.4)  # the probe's IP landing (127.0.0.1) plus the injection
    assert r.metadata["scoring_findings"] == [
        "IP landing: 127.0.0.1",
        f"Obfuscated cross-site script (string_array_rotation) loaded by inline code: http://localhost:{port}/obf.js"]
    [inj] = r.metadata["injections"]
    assert inj["markers"] == [] and inj["body_markers"] == ["string_array_rotation"]


# ---------- code the page builds at runtime (eval_capture.py) ----------

async def _site_load(engine, url, shot="pages/0/default"):
    from pnakotic.src.scanner.engine import LoadOptions

    async with engine.browser_session() as (browser, _proxy):
        return await engine._scan_in_context(browser, url, "default", engine.artifacts.create_task_folder("j"),
                                             primary=True, options=LoadOptions(site=True, shot_dir=shot))


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_runtime_code_is_captured_matched_and_marked(site_server, tmp_path, yara_rules_dir):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-stage")
    stages = r.metadata["eval_stages"]
    assert len(stages) == 2  # the Playwright scripts of the load itself are not stages
    assert any(s["yara_matched"] for s in stages)
    assert any("string_array_rotation" in s["markers"] for s in stages)
    # Chromium gives eval and new Function a stack: the caller is the page that built them
    assert all(s["caller"].startswith(site_server) and s["caller_line"] == 1 for s in stages)
    assert all(set(s) == {"caller", "caller_line", "length", "markers", "context", "yara_matched"} for s in stages)
    assert all(s["context"]["text"] and s["length"] > 0 for s in stages)
    hits = [json.loads(h.evidence) for h in r.hops if h.mechanism == "yara_match"]
    assert any(h["source"] == "eval" and h["rule"] == "js_runtime_test_001" for h in hits)
    assert "eval_stages_dropped" not in r.metadata


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_runtime_code_disguised_with_a_source_url_is_still_a_stage(site_server, tmp_path, yara_rules_dir):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-sourceurl")
    assert any(s["yara_matched"] for s in r.metadata["eval_stages"])


@requires_browser
@pytest.mark.asyncio
async def test_runtime_templates_are_captured_but_quiet(site_server, tmp_path):
    from pnakotic.src.intelligence.scorer import PnakoticScorer

    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-template")
    assert len(r.metadata["eval_stages"]) == 3 and not any(s["markers"] for s in r.metadata["eval_stages"])
    PnakoticScorer().score(r, site_host="127.0.0.1")
    assert not any("built at runtime" in f for f in r.metadata["scoring_findings"])


@requires_browser
@pytest.mark.asyncio
async def test_runtime_code_flood_is_capped(site_server, tmp_path):
    import time

    started = time.monotonic()
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-flood")
    assert len(r.metadata["eval_stages"]) == 20 and r.metadata["eval_stages_dropped"] >= 480
    assert time.monotonic() - started < 30


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_debugger_loop_does_not_stall_the_load(site_server, tmp_path, yara_rules_dir):
    import asyncio

    r = await asyncio.wait_for(_site_load(_site_engine(tmp_path), f"{site_server}/eval-debugger"), 40)
    assert any(s["yara_matched"] for s in r.metadata["eval_stages"])


@requires_browser
@pytest.mark.asyncio
async def test_playwright_own_scripts_and_the_pages_own_scripts_are_not_stages(site_server, tmp_path):
    """The document's inline scripts and its network scripts are not stages, and a page that
    builds nothing at runtime has none (our own init scripts and evaluate calls don't count)."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/")
    assert r.metadata["eval_stages"] == []


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_runtime_code_built_from_a_timer_or_a_promise_is_a_stage_without_a_caller(site_server, tmp_path,
                                                                                         yara_rules_dir):
    """No JavaScript frame is on the stack when a timer or a promise runs eval, so the stage has no
    caller; it must still be captured (a stack requirement would be a one-line bypass)."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-stackless")
    stages = r.metadata["eval_stages"]
    assert len(stages) == 3 and all(s["caller"] == "" and s["caller_line"] is None for s in stages)
    assert sum(s["yara_matched"] for s in stages) == 1
