"""card_watch: which inputs are card inputs, and whose code inserted them (offline, plus one
browser test of CARD_SELECTOR in a real DOM)."""
import pytest

from _support import requires_browser

CARD_FIELDS = [
    '<input autocomplete="cc-number">', '<input autocomplete="billing cc-number">', '<input autocomplete="cc-csc">',
    '<input autocomplete="cc-exp">', '<select autocomplete="cc-exp-month"></select>', '<input autocomplete="CC-EXP-YEAR">',
    '<input name="cardnumber">', '<input name="card_number">', '<input id="Card-Number">', '<input name="card[number]">',
    '<input name="ccnum">', '<input name="cvc">', '<input name="card_cvv">', '<input id="payment-cvc">',
    '<input name="card-expiry">', '<input name="cc_exp">', '<select name="exp_month"></select>', '<input name="expyear">',
]
OTHER_FIELDS = [
    '<input name="billing_email">', '<input id="billing_postcode" name="billing_postcode">',
    '<input id="coupon_code" name="coupon_code">', '<input name="account_password" type="password">',
    '<input autocomplete="email">', '<div id="cardnumber"></div>', '<input name="accept_terms">',
]

STORE = "https://shop.example"
PAGE = STORE + "/checkout/"
SKIMMER = "Error\n    at https://evil.example/s.js:1:200\n    at https://shop.example/wp-includes/js/jquery/jquery.min.js:2:1"
STORE_STACK = "Error\n    at https://shop.example/wp-content/plugins/pay/form.js:10:5"


def test_card_html_re_matches_card_fields_only():
    from pnakotic.src.scanner.card_watch import CARD_HTML_RE

    for html in CARD_FIELDS:
        assert CARD_HTML_RE.search(f"<p>x</p>{html}<p>y</p>"), html
    for html in OTHER_FIELDS:
        assert not CARD_HTML_RE.search(html), html


def test_card_html_re_is_fast_on_hostile_markup():
    import time

    from pnakotic.src.scanner.card_watch import CARD_HTML_RE, MAX_HTML_CHARS

    hostile = [
        ("<input " + "name=id=" * 130 + " ") * 400,
        ("<input autocomplete=" + "a " * 500) * 400,
        "<input " + "x" * 3000,
        ("<select name='" + "c" * 59) * 4000,
    ]
    for text in hostile:
        started = time.monotonic()
        assert not CARD_HTML_RE.search(text[:MAX_HTML_CHARS])
        assert time.monotonic() - started < 1.0


def test_served_html_check_agrees_and_is_linear_on_a_whole_body():
    import time

    from pnakotic.src.scanner.card_watch import html_has_card_input
    from pnakotic.src.scanner.yara_scan import MAX_BUFFER_BYTES

    for html in CARD_FIELDS:
        assert html_has_card_input(f"<p>x</p>{html}<p>y</p>"), html
    assert html_has_card_input("<input type=text name=cardnumber>")
    assert html_has_card_input("<INPUT AUTOCOMPLETE='shipping cc-number'>")
    for html in OTHER_FIELDS:
        assert not html_has_card_input(html), html
    hostile = [  # the served body is read whole (up to MAX_BUFFER_BYTES) in the worker
        ("<input " + "name=id=" * 130 + " ") * 4000,
        ("<input autocomplete=" + "a " * 500) * 4000,
        ("<select name='" + "c" * 59) * 40000,
        "<input " * 400000,
        ("<input id='" + "cc_" * 19 + "' ") * 40000,
    ]
    for text in hostile:
        text = text[:MAX_BUFFER_BYTES]
        started = time.monotonic()
        assert not html_has_card_input(text)
        assert time.monotonic() - started < 1.0


def test_summarize_owner_of_each_insertion():
    from pnakotic.src.scanner.card_watch import summarize

    events = [{"via": "innerHTML", "stack": SKIMMER}, {"via": "appendChild", "stack": ""},
              {"via": "appendChild", "stack": STORE_STACK}]
    out = summarize(events, 3, "shop.example", PAGE, None)
    assert out["present"] == 3 and out["dropped"] == 0
    skim, empty, store = out["inserted"]
    assert skim == {"via": "innerHTML", "owner": "unknown", "vendors": [], "cut": False, "verified": True,
                    "first_unknown": "https://evil.example/s.js",
                    "frames": ["https://evil.example/s.js", "https://shop.example/wp-includes/js/jquery/jquery.min.js"]}
    assert empty["owner"] == "unknown" and empty["frames"] == [] and empty["verified"] is True
    assert empty["first_unknown"] == ""
    assert store["owner"] == "store" and store["frames"] == ["https://shop.example/wp-content/plugins/pay/form.js"]
    assert store["verified"] is True and store["first_unknown"] == ""


def test_summarize_reads_the_page_frame_against_the_served_inline_block_hashes():
    from pnakotic.src.scanner.card_watch import summarize

    import hashlib

    served = b"<html><head>\n<script>\nvar a = 1;\nvar b = 2;\n</script>\n</head><body></body></html>"
    block = hashlib.sha256(b"\nvar a = 1;\nvar b = 2;\n").hexdigest()
    served_block = {"via": "appendChild", "stack": f"Error\n    at {PAGE}:3:5 sha256={block}"}
    handler = {"via": "appendChild", "stack": f"Error\n    at {PAGE}:3:5 sha256={'0' * 64}"}  # same line
    no_hash = {"via": "appendChild", "stack": f"Error\n    at {PAGE}:3:5"}
    parsed = {block: {(1, 8)}}  # where the browser parsed it: the served block's own start
    [a, b, c] = summarize([served_block, handler, no_hash], 1, "shop.example", PAGE + "#x", served,
                          parsed=parsed)["inserted"]
    assert a["owner"] == "store" and b["owner"] == "unknown" and c["owner"] == "unknown"
    # a copy of the block parsed somewhere else (an event handler with its exact text): not proof
    copied = summarize([served_block], 1, "shop.example", PAGE, served, parsed={block: {(1, 8), (0, 0)}})
    assert copied["inserted"][0]["owner"] == "unknown"
    assert summarize([served_block], 1, "shop.example", PAGE, served)["inserted"][0]["owner"] == "unknown"


def test_summarize_bounds_frames_and_marks_a_cut_stack():
    from pnakotic.src.scanner.card_watch import summarize

    long_url = STORE + "/" + "a" * 400 + ".js"
    deep = "Error\n" + "".join(f"    at https://shop.example/{i}.js:1:1\n" for i in range(31))
    out = summarize([{"via": "append", "stack": f"Error\n    at {long_url}:1:1"},
                     {"via": "append", "stack": deep}], 1, "shop.example", PAGE, None, dropped=4)
    wide, tall = out["inserted"]
    assert wide["frames"] == [""]  # a URL over 300 characters is unreadable, so unknown
    assert wide["owner"] == "unknown"
    assert len(tall["frames"]) == 10 and all(len(f) <= 300 for f in tall["frames"])
    assert tall["cut"] is True and tall["owner"] == "store"
    assert out["dropped"] == 4


def test_summarize_fails_closed_when_inputs_appeared_unseen():
    from pnakotic.src.scanner.card_watch import summarize

    unseen = {"via": "unseen", "owner": "unknown", "vendors": [], "frames": [], "cut": False, "verified": True,
              "first_unknown": ""}
    assert summarize([], 1, "shop.example", PAGE, b"<html><body></body></html>")["inserted"] == [unseen]
    # no served body, or one cut at the cap: the inputs may well be in the part we didn't get, so
    # the insertion can't be called outside code
    missing = summarize([], 1, "shop.example", PAGE, None)
    assert missing["inserted"] == [dict(unseen, verified=False)] and missing["unverifiable"] == "served_html"
    served = b"<form><input name='cardnumber' autocomplete='cc-number'></form>"
    assert summarize([], 1, "shop.example", PAGE, served)["inserted"] == []  # served with the page
    assert summarize([], 0, "shop.example", PAGE, None)["inserted"] == []  # no card inputs at all
    seen = summarize([{"via": "append", "stack": STORE_STACK}], 2, "shop.example", PAGE, None)["inserted"]
    assert [e["via"] for e in seen] == ["append"]


HANDLER_ONLY = {"via": "appendChild", "stack": f"Error\n    at {PAGE}:1:9 sha256={'0' * 64}"}
CROSS_SITE = {"via": "innerHTML", "stack": SKIMMER}


def _hash(text):
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_summarize_marks_page_url_frames_it_could_not_check():
    """`verified` is false only when every frame that made the owner unknown is at the page URL and
    page-URL frames couldn't be checked on that load: no parse record (the debugger domain failed or
    the record overflowed), no served HTML, or no script hash in this browser."""
    from pnakotic.src.scanner.card_watch import summarize

    served = b"<html><head><script>var a = 1;</script></head><body></body></html>"
    # a runtime handler at the page URL on a load that could check page frames: unknown, and verified
    checked = summarize([HANDLER_ONLY], 1, "shop.example", PAGE, served, parsed={_hash("var a = 1;"): {(0, 20)}})
    assert checked["unverifiable"] is None
    assert [(e["owner"], e["verified"], e["first_unknown"]) for e in checked["inserted"]] == [("unknown", True, PAGE)]
    # no parse record: the same insertion can't be checked, but another site's frame, an empty
    # stack and an eval frame on that load still can
    events = [HANDLER_ONLY, CROSS_SITE, {"via": "append", "stack": ""},
              {"via": "append", "stack": f"Error\n    at eval (eval at <anonymous>)\n    at {PAGE}:1:9"},
              {"via": "append", "stack": f"Error\n    at {PAGE}:1:9\n    at https://evil.example/s.js:1:1"},
              {"via": "append", "stack": STORE_STACK}]
    out = summarize(events, 1, "shop.example", PAGE, served, parsed=None)
    assert out["unverifiable"] == "parse_record"
    assert [(e["owner"], e["verified"]) for e in out["inserted"]] == [
        ("unknown", False), ("unknown", True), ("unknown", True), ("unknown", True), ("unknown", True), ("store", True)]
    assert [e["first_unknown"] for e in out["inserted"][3:5]] == ["", PAGE]  # the first unknown frame, as it is
    # no served HTML to hash the inline blocks of, or only its first MAX_BUFFER_BYTES
    none = summarize([HANDLER_ONLY], 1, "shop.example", PAGE, None, parsed={})
    assert none["unverifiable"] == "served_html" and none["inserted"][0]["verified"] is False
    from pnakotic.src.scanner.yara_scan import MAX_BUFFER_BYTES

    cut = (served + b" " * MAX_BUFFER_BYTES)[:MAX_BUFFER_BYTES]
    out = summarize([HANDLER_ONLY, CROSS_SITE], 1, "shop.example", PAGE, cut, parsed={_hash("var a = 1;"): {(0, 20)}})
    assert out["unverifiable"] == "served_html" and [e["verified"] for e in out["inserted"]] == [False, True]
    unseen = summarize([], 1, "shop.example", PAGE, cut, parsed={})
    assert [(e["via"], e["verified"]) for e in unseen["inserted"]] == [("unseen", False)]
    # served_html wins over parse_record: an unseen insertion's check needs the body
    both = summarize([], 1, "shop.example", PAGE, None, parsed=None)
    assert both["unverifiable"] == "served_html" and both["inserted"][0]["verified"] is False
    # a browser without CallSite.getScriptHash: the hook says so on each event
    no_hash = dict(HANDLER_ONLY, stack=f"Error\n    at {PAGE}:1:9", no_hash=True)
    out = summarize([no_hash, dict(CROSS_SITE, no_hash=True)], 1, "shop.example", PAGE, served, parsed={})
    assert out["unverifiable"] == "script_hash"
    assert [e["verified"] for e in out["inserted"]] == [False, True]


def test_summarize_cannot_check_page_frames_in_a_charset_it_does_not_read():
    from pnakotic.src.scanner.card_watch import summarize

    page_frame = dict(HANDLER_ONLY)
    ascii_page = b"<html><head><script>var a = 1;</script></head><body></body></html>"
    sjis_page = "<html><head><script>var a = '\u30c6\u30b9\u30c8';</script></head><body></body></html>".encode("shift_jis")
    after = b"<html><head><script>var a = 1;</script></head><body>\x82\xa0</body></html>"  # only after the last block
    # what Playwright's Response.body() gives for that page: the browser's decoded text as UTF-8
    decoded = sjis_page.decode("shift_jis").encode("utf-8")
    cases = [
        (sjis_page, "Shift_JIS", False),  # raw Shift_JIS bytes: not what we hash
        (sjis_page, None, False),  # the browser's charset couldn't be read
        (decoded, "Shift_JIS", True), (decoded, None, True),
        (sjis_page, "UTF-8", True), (sjis_page, "windows-1252", True), (sjis_page, "utf-8", True),
        (ascii_page, "Shift_JIS", True),  # plain ASCII reads the same in it
        (after, "Shift_JIS", True),  # nothing before or in a block is read differently
        (ascii_page.replace(b"var", b"\x1b$Bvar"), "ISO-2022-JP", False),  # escapes are control bytes
    ]
    for served, charset, verified in cases:
        out = summarize([page_frame], 1, "shop.example", PAGE, served, parsed={}, charset=charset)
        assert out["inserted"][0]["verified"] is verified, (served, charset)
        assert out["unverifiable"] == (None if verified else "charset")


def test_watcher_records_a_browser_without_script_hashes():
    from pnakotic.src.scanner.card_watch import CardWatcher

    w = CardWatcher()
    w._on_page_event(_source(), {"via": "append", "stack": STORE_STACK, "no_hash": 1})
    w._on_page_event(_source(), {"via": "append", "stack": STORE_STACK, "no_hash": "yes"})
    assert [e["no_hash"] for e in w.events] == [True, False]


class _Frame:
    pass


def _source(main=True):
    page = type("Page", (), {})()
    page.main_frame = _Frame()
    return {"page": page, "frame": page.main_frame if main else _Frame()}


def test_watcher_keeps_bounded_events_from_the_main_frame_only():
    from pnakotic.src.scanner.card_watch import MAX_EVENTS, CardWatcher

    w = CardWatcher()
    assert w.binding.startswith("__") and len(w.binding) == 18
    w._on_page_event(_source(), {"via": "innerHTML", "stack": "Error\n" + "x" * 5000})
    assert w.events == [{"via": "innerHTML", "stack": "Error", "cut": True, "no_hash": False}]  # the cut line is dropped
    w._on_page_event(_source(), {"via": "eval", "stack": ""})  # not a hook's name
    w._on_page_event(_source(), "appendChild")
    w._on_page_event(_source(main=False), {"via": "appendChild", "stack": ""})  # a subframe's own document
    w._on_page_event(_source(), {"via": "appendChild", "stack": 42})
    assert len(w.events) == 2 and w.events[1] == {"via": "appendChild", "stack": "", "cut": False, "no_hash": False}
    for _ in range(MAX_EVENTS + 3):
        w._on_page_event(_source(), {"via": "append", "stack": STORE_STACK})
    assert len(w.events) == MAX_EVENTS and w.dropped == 5
    w._on_page_event(_source(), {"via": "append", "over": 1})
    w._on_page_event(_source(), {"via": "append", "over": 1000})
    w._on_page_event(_source(), {"via": "append", "over": 10 ** 9})  # not a count the hook sends
    w._on_page_event(_source(), {"via": "append", "over": True})
    assert w.dropped == 5 + 1 + 1000


def test_init_script_carries_its_values():
    from pnakotic.src.scanner.card_watch import CARD_HTML_PATTERN, CARD_SELECTOR, _init_script

    script = _init_script("__abc")
    assert '"__abc"' in script and "__NAME__" not in script and "__SELECTOR__" not in script
    assert "Function.prototype.toString = patchedToString" in script  # the shared prelude
    import json
    assert json.dumps(CARD_SELECTOR) in script and json.dumps(CARD_HTML_PATTERN) in script


@requires_browser
@pytest.mark.asyncio
async def test_card_selector_in_a_real_dom():
    """CARD_SELECTOR in Chromium (the hook's matches) and in Playwright's locator (the count)."""
    from playwright.async_api import async_playwright

    from pnakotic.src.scanner.card_watch import CARD_HTML_PATTERN, CARD_SELECTOR

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        await page.set_content("<body>" + "".join(CARD_FIELDS + OTHER_FIELDS) + "</body>")
        hits = await page.evaluate("""([sel]) => Array.from(document.body.children).map(e => e.matches(sel))""",
                                   [CARD_SELECTOR])
        assert hits == [True] * len(CARD_FIELDS) + [False] * len(OTHER_FIELDS)
        assert await page.locator("css=" + CARD_SELECTOR).count() == len(CARD_FIELDS)
        # the page-side regex agrees with Python's on the same markup
        js = await page.evaluate("""([pat, html]) => html.map(h => new RegExp(pat, 'i').test(h))""",
                                 [CARD_HTML_PATTERN, CARD_FIELDS + OTHER_FIELDS])
        assert js == [True] * len(CARD_FIELDS) + [False] * len(OTHER_FIELDS)
        await browser.close()
