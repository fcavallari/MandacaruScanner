import time


def _ids(findings):
    return [f["id"] for f in findings]


def test_adversarial_atob_is_fast():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    html = ("atob('" + "x" * 494) * 4000  # ~2 MB, no closing quote
    start = time.perf_counter()
    StaticAnalyst().analyze_content(html)
    assert time.perf_counter() - start < 1.0


def test_adversarial_meta_is_fast():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    html = ("<meta " + "x" * 494) * 4000  # ~2 MB, no closing '>'
    start = time.perf_counter()
    StaticAnalyst().analyze_content(html)
    assert time.perf_counter() - start < 1.0


def test_atob_still_matches_normal_and_multiline():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    a = StaticAnalyst()
    assert "js_atob" in _ids(a.analyze_content("<script>atob('aGVsbG8=')</script>"))
    assert "js_atob" in _ids(a.analyze_content("atob(\n'aGVs\nbG8='\n)"))
    assert "js_atob" not in _ids(a.analyze_content("var x = atob(b);"))


def test_meta_refresh_still_matches_both_attribute_orders():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    a = StaticAnalyst()
    first = '<meta http-equiv="refresh" content="0;url=/x">'
    second = '<meta content="0;url=/x" http-equiv=refresh>'
    assert "meta_refresh" in _ids(a.analyze_content(first))
    assert "meta_refresh" in _ids(a.analyze_content(second))


def test_oversized_content_is_truncated_with_finding():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst, MAX_CONTENT_CHARS

    a = StaticAnalyst()

    # Signature beyond the cap is not seen; only the truncation finding remains.
    beyond = "a" * (MAX_CONTENT_CHARS + 1000) + "atob('x')"
    ids = _ids(a.analyze_content(beyond))
    assert ids == ["content_truncated"]

    # Signature inside the cap is kept, and the truncation finding comes last.
    within = "atob('x')" + "a" * 91 + "a" * (MAX_CONTENT_CHARS + 1000)
    findings = a.analyze_content(within)
    ids = _ids(findings)
    assert "js_atob" in ids
    assert ids.count("content_truncated") == 1
    assert ids[-1] == "content_truncated"
    trunc = findings[-1]
    assert trunc["type"] == "content_truncated"
    assert trunc["count"] == 1
    assert set(trunc) == {"type", "id", "count", "snippet"}


def test_small_content_has_no_truncation_finding():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    findings = StaticAnalyst().analyze_content("<html>atob('x')</html>")
    assert "content_truncated" not in _ids(findings)
    assert "js_atob" in _ids(findings)


def test_adversarial_clickfix_is_fast():
    from pnakotic.src.scanner.static_analyzer import MAX_CONTENT_CHARS, StaticAnalyst

    html = ("windows key + " * (MAX_CONTENT_CHARS // 14))[:MAX_CONTENT_CHARS]
    start = time.perf_counter()
    StaticAnalyst().analyze_content(html)
    assert time.perf_counter() - start < 1.0


def test_clickfix_lure_needs_run_and_paste():
    from pnakotic.src.scanner.static_analyzer import StaticAnalyst

    analyst = StaticAnalyst()
    lure = "<p>1. Press Windows Key + R</p><p>2. Press CTRL + V</p><p>3. Press Enter</p>"
    assert any(f["id"] == "clickfix_lure" for f in analyst.analyze_content(lure))
    assert any(f["id"] == "clickfix_lure" for f in analyst.analyze_content("Hold ⊞ + R, then Ctrl+V"))
    assert not any(f["id"] == "clickfix_lure" for f in analyst.analyze_content("<p>Press Win+R to open Run.</p>"))
    assert not any(f["id"] == "clickfix_lure" for f in analyst.analyze_content("<p>Copy with Ctrl+C, paste with Ctrl+V.</p>"))
    assert not any(f["id"] == "clickfix_lure" for f in analyst.analyze_content("twin+rocket ctrl+value"))
