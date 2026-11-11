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
    assert all(set(s) == {"caller", "caller_line", "length", "markers", "context", "yara_matched", "oversized"} for s in stages)
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
    # three identical templates are one stage: the repeats take no slot, they are counted
    assert len(r.metadata["eval_stages"]) == 1 and r.metadata["eval_stages_repeated"] == 2
    assert not any(s["markers"] for s in r.metadata["eval_stages"])
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


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_a_copy_of_the_harness_utility_script_does_not_hide_what_it_runs(site_server, tmp_path, yara_rules_dir):
    """Bypass A: the page copies Playwright's main-world UtilityScript and calls it. The copy is the
    harness's own content and is skipped; what it evaluates is the page's code and is a stage."""
    import _support
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        ctx = await browser.new_context()
        page = await ctx.new_page()
        cdp = await ctx.new_cdp_session(page)
        parsed = []
        cdp.on("Debugger.scriptParsed", lambda event: parsed.append(event))
        await cdp.send("Debugger.enable")
        await page.evaluate("1 + 1")
        await cdp.send("Debugger.enable")  # replays the scripts parsed so far
        utility = None
        for event in parsed:
            if event.get("url") == "" and (event.get("executionContextAuxData") or {}).get("isDefault") is not False:
                source = (await cdp.send("Debugger.getScriptSource", {"scriptId": event["scriptId"]}))["scriptSource"]
                if "UtilityScript" in source and "this.global.eval(expression)" in source:
                    utility = source
                    break
        await browser.close()
    assert utility is not None, "this Playwright version keeps its utility script elsewhere: update the test"
    _support.DYNAMIC_PAGES["/eval-launder"] = (
        "<html><body><script>var src = " + json.dumps(utility) + "; var u = eval(src); "
        "u.evaluate(false, true, '/*PNAKOTIC_TEST_EVAL*/ 1');</script></body></html>")
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-launder")
    assert any(s["yara_matched"] for s in r.metadata["eval_stages"])


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_eval_run_through_a_hooked_global_is_still_a_stage(site_server, tmp_path, yara_rules_dir):
    """Bypass B: String = eval, then a call that makes the behavior hooks run String(): eval runs
    from a harness frame, and what it builds is still the page's."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-string-hook")
    assert any(s["yara_matched"] for s in r.metadata["eval_stages"])


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_scripts_from_data_and_blob_urls_are_stages(site_server, tmp_path, yara_rules_dir):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-dataurl")
    stages = r.metadata["eval_stages"]
    assert len(stages) == 2 and all(s["yara_matched"] and s["caller"] == "" for s in stages)


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_a_marked_stage_is_kept_after_the_slots_are_full_of_junk(site_server, tmp_path, yara_rules_dir):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/eval-crowd")
    stages = r.metadata["eval_stages"]
    assert len(stages) == 20
    marked = [s for s in stages if "string_array_rotation" in s["markers"]]
    assert len(marked) == 1 and marked[0]["yara_matched"]
    # 26 distinct stages ("return 0".."return 24", "return 99") and 9 repeats of the last one
    assert r.metadata["eval_stages_repeated"] == 9
    assert r.metadata["eval_stages_dropped"] == 7  # 6 distinct that found no slot, 1 replaced by the marked stage


@requires_browser
@pytest.mark.asyncio
async def test_behavior_hooks_firing_leave_no_stages(site_server, tmp_path):
    """Every hook report is a binding call, after which Playwright runs a delivery script in the page's
    main world. It is the harness's: the capture knows it by content (the warm-up makes one call), and
    the warm-up's own event is not recorded as the page's behavior."""
    engine = _site_engine(tmp_path)
    r = await _site_load(engine, f"{site_server}/hooks-only")
    assert any(h.mechanism == "page_behavior" for h in r.hops)  # the binding did fire
    assert r.metadata["eval_stages"] == []
    plain = await _site_load(engine, f"{site_server}/", shot="pages/1/default")
    assert not any(h.mechanism == "page_behavior" for h in plain.hops)


# ---------- card inputs inserted into the page, and by whose code (card_watch.py) ----------

@requires_browser
@pytest.mark.asyncio
async def test_card_form_built_by_the_store_is_the_stores(site_server, tmp_path):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-store")
    ci = r.metadata["card_inputs"]
    assert ci["present"] >= 1 and [e["owner"] for e in ci["inserted"]] == ["store"]
    [e] = ci["inserted"]
    assert e["via"] == "appendChild" and e["frames"] == [f"{site_server}/js/form.js"] and e["cut"] is False
    assert ci["dropped"] == 0
    assert r.metadata["eval_stages"] == []  # the watch's own scripts are not runtime-built code


@requires_browser
@pytest.mark.asyncio
async def test_card_form_written_by_a_cross_site_script_is_unknown(site_server, tmp_path):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-skim")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == 3
    assert any(e["owner"] == "unknown" and any("localhost" in f for f in e["frames"]) for e in ci["inserted"])
    assert [e["via"] for e in ci["inserted"]] == ["innerHTML"]


@requires_browser
@pytest.mark.asyncio
async def test_card_inputs_served_with_the_page_are_not_insertions(site_server, tmp_path):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-served")
    ci = r.metadata["card_inputs"]
    assert ci["present"] >= 1 and ci["inserted"] == []


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/card-hidden-stack", "/card-forged-stack", "/card-short-stack"])
async def test_a_hidden_or_forged_stack_is_unknown(site_server, tmp_path, path):
    """prepareStackTrace returning "" and stackTraceLimit 0 are overridden for the one capture;
    a read-only forged prepareStackTrace, or a read-only stackTraceLimit of 1 that would show only
    the store helper the skimmer calls, gives an empty stack: unknown code."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}{path}")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == 3
    assert ci["inserted"] and all(e["owner"] == "unknown" for e in ci["inserted"])
    if path == "/card-hidden-stack":
        assert any("localhost" in f for f in ci["inserted"][0]["frames"])
    else:
        assert ci["inserted"][0]["frames"] == []


@requires_browser
@pytest.mark.asyncio
async def test_a_huge_innerhtml_write_does_not_slow_the_load(site_server, tmp_path):
    import time

    started = time.monotonic()
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-big-html")
    assert time.monotonic() - started < 30
    ci = r.metadata["card_inputs"]
    assert [(e["via"], e["owner"]) for e in ci["inserted"]] == [("innerHTML", "store")]
    assert ci["present"] == 1


@requires_browser
@pytest.mark.asyncio
async def test_an_input_renamed_after_insertion_fails_closed(site_server, tmp_path):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-renamed")
    ci = r.metadata["card_inputs"]
    assert ci["present"] >= 1 and [e["via"] for e in ci["inserted"]] == ["unseen"]
    assert ci["inserted"][0]["owner"] == "unknown"


@requires_browser
@pytest.mark.asyncio
async def test_an_inline_script_inserted_at_runtime_is_not_the_served_block(site_server, tmp_path):
    """V8 gives a runtime-inserted inline script no URL (`<anonymous>:line:col`), so its frames
    can't be mistaken for a served inline block's lines, from its first run or from a timer."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-inline-runtime")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == 2
    assert [(e["via"], e["owner"]) for e in ci["inserted"]] == [("appendChild", "unknown"), ("appendChild", "unknown")]
    assert ci["inserted"][0]["frames"] == ["", f"{site_server}/js/inline-ins.js"]
    assert ci["inserted"][1]["frames"] == [""]
    # The inserted script is a runtime stage. CDP gives scriptParsed only the top frame, which is our
    # appendChild hook's: it is passed over, so the stage has no caller rather than the hook's line.
    assert [(s["caller"], s["caller_line"]) for s in r.metadata["eval_stages"]] == [("", None)]


@requires_browser
@pytest.mark.asyncio
async def test_a_stack_deeper_than_is_read_is_marked_cut(site_server, tmp_path):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-deep")
    [e] = r.metadata["card_inputs"]["inserted"]
    assert e["cut"] is True and e["owner"] == "store" and len(e["frames"]) == 10


@requires_browser
@pytest.mark.asyncio
async def test_a_source_url_naming_a_store_file_does_not_make_it_the_stores(site_server, tmp_path):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-sourceurl")
    port = site_server.rsplit(":", 1)[1]
    [e] = r.metadata["card_inputs"]["inserted"]
    assert e["owner"] == "unknown" and e["frames"] == [f"http://localhost:{port}/renamed-source.js"]


@requires_browser
@pytest.mark.asyncio
async def test_store_code_run_inside_a_hooked_call_is_still_the_stores(site_server, tmp_path):
    """A custom element's connectedCallback runs inside appendChild / the innerHTML setter, so our
    wrapper's own frame is under the store's: it is left out, and the insertion is the store's."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-custom-element")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == 2
    assert [(e["via"], e["owner"]) for e in ci["inserted"]] == [("appendChild", "store"), ("appendChild", "store")]
    assert all(set(e["frames"]) == {f"{site_server}/js/element.js"} for e in ci["inserted"])


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/card-onerror-shift", "/card-onerror-min"])
async def test_an_event_handler_set_at_runtime_is_not_a_served_block(site_server, tmp_path, path):
    """A handler attribute a cross-site script sets runs at the page URL, at a line inside a served
    inline block (newline-shifted, or line 1 of a one-line page): its script hash is not a served
    block's, so it is unknown code."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}{path}")
    [e] = r.metadata["card_inputs"]["inserted"]
    assert e["frames"] == [f"{site_server}{path}"]  # the handler's own frame, at the page URL
    assert e["owner"] == "unknown"


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/card-served-inline", "/card-served-inline-1252"])
async def test_a_served_inline_script_is_the_stores(site_server, tmp_path, path):
    """CRLF line ends and non-ASCII text in the block, on a UTF-8 page and on one with no declared
    charset: its hash still matches the served text."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}{path}")
    [e] = r.metadata["card_inputs"]["inserted"]
    assert (e["via"], e["owner"], e["frames"]) == ("appendChild", "store", [f"{site_server}{path}"])


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/card-handler-copy", "/card-handler-moji"])
async def test_an_event_handler_copying_a_served_block_is_not_the_stores(site_server, tmp_path, path):
    """A handler with a served block's exact text (or its windows-1252 reading) has that block's
    hash at the page URL, and the element's expandos stand in for `document`; but the browser parsed
    it at the handler's position, not a served block's, so no frame with that hash is the store's."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}{path}")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == 1
    [e] = ci["inserted"]
    assert e["via"] == "insertBefore" and set(e["frames"]) == {f"{site_server}{path}"}  # the IIFE and the handler
    assert e["owner"] == "unknown"


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("path,count", [("/card-paren-url", 1), ("/card-data-url", 2)])
async def test_a_script_url_holding_a_store_url_is_not_the_stores(site_server, tmp_path, path, count):
    """A script URL with "(" and a store URL in it, or a data: URL ending in a comment that names
    a store file, is written as <anonymous>: unknown code."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}{path}")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == count
    assert [(e["owner"], e["frames"]) for e in ci["inserted"]] == [("unknown", [""])] * count


@requires_browser
@pytest.mark.asyncio
async def test_html_given_as_an_object_is_seen_after_the_call(site_server, tmp_path):
    r = await _site_load(_site_engine(tmp_path), f"{site_server}/card-object-html")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == 3
    assert [(e["via"], e["owner"]) for e in ci["inserted"]] == [
        ("innerHTML", "unknown"), ("insertAdjacentHTML", "unknown"), ("outerHTML", "unknown")]
    port = site_server.rsplit(":", 1)[1]
    assert all(e["frames"] == [f"http://localhost:{port}/object-html.js"] for e in ci["inserted"])


@requires_browser
@pytest.mark.asyncio
@pytest.mark.parametrize("path,owner", [("/card-builtins-store", "store"), ("/card-builtins-skim", "unknown")])
async def test_builtin_frames_are_nobodys(site_server, tmp_path, path, owner):
    """forEach and a Promise executor put a builtin frame between two of the inserting script's
    own frames: it is left out, so the owner is the script's."""
    r = await _site_load(_site_engine(tmp_path), f"{site_server}{path}")
    ci = r.metadata["card_inputs"]
    assert ci["present"] == 2
    assert [e["owner"] for e in ci["inserted"]] == [owner, owner]
    assert all(len(e["frames"]) == 2 and "" not in e["frames"] for e in ci["inserted"])


@requires_browser
@pytest.mark.asyncio
async def test_url_probe_has_no_card_inputs(site_server, tmp_path):
    engine = _site_engine(tmp_path)
    async with engine.browser_session() as (browser, _):
        r = await engine._scan_in_context(browser, f"{site_server}/card-skim", "default",
                                          engine.artifacts.create_task_folder("j"), primary=True)
    assert "card_inputs" not in r.metadata


@requires_browser
@pytest.mark.asyncio
async def test_hooks_stay_invisible_with_both_init_scripts(site_server):
    from playwright.async_api import async_playwright

    from pnakotic.src.scanner.behavior import BehaviorRecorder
    from pnakotic.src.scanner.card_watch import CardWatcher

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        ctx = await browser.new_context()
        behavior, cards = BehaviorRecorder(), CardWatcher()
        await behavior.attach(ctx)
        await cards.attach(ctx)
        page = await ctx.new_page()
        await page.goto(f"{site_server}/card-store")
        assert len(cards.events) == 1  # the hooks are installed and fired
        for fn in ("Element.prototype.appendChild", "Element.prototype.insertAdjacentHTML", "Function.prototype.toString",
                   "Clipboard.prototype.writeText", "Element.prototype.append", "Node.prototype.insertBefore",
                   "Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set",
                   "Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML').set",
                   "Function.prototype.toString.call(Element.prototype.appendChild)"):
            assert (await page.evaluate(f"({fn}).toString()")).endswith("{ [native code] }"), fn
        assert await page.evaluate("Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set.name") \
            == "set innerHTML"
        assert await page.evaluate("[Node.prototype.appendChild.name, Node.prototype.appendChild.length, "
                                   "Element.prototype.insertAdjacentHTML.length]") == ["appendChild", 1, 2]
        ours = await page.evaluate("Object.keys(window).filter(k => k.startsWith('__') "
                                   "&& !k.startsWith('__playwright') && !k.startsWith('__pw'))")
        assert ours == []
        for name in (behavior.binding, cards.binding):
            assert await page.evaluate(f"{name!r} in window") is False
            assert await page.evaluate(f"Object.getOwnPropertyNames(window).includes({name!r})") is False
        # the stack capture leaves Error as it found it
        assert await page.evaluate("['prepareStackTrace' in Error, Error.stackTraceLimit]") == [False, 10]
        await browser.close()
