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


def test_summarize_owner_of_each_insertion():
    from pnakotic.src.scanner.card_watch import summarize

    events = [{"via": "innerHTML", "stack": SKIMMER}, {"via": "appendChild", "stack": ""},
              {"via": "appendChild", "stack": STORE_STACK}]
    out = summarize(events, 3, "shop.example", PAGE, None)
    assert out["present"] == 3 and out["dropped"] == 0
    skim, empty, store = out["inserted"]
    assert skim == {"via": "innerHTML", "owner": "unknown", "vendors": [], "cut": False,
                    "frames": ["https://evil.example/s.js", "https://shop.example/wp-includes/js/jquery/jquery.min.js"]}
    assert empty["owner"] == "unknown" and empty["frames"] == []
    assert store["owner"] == "store" and store["frames"] == ["https://shop.example/wp-content/plugins/pay/form.js"]


def test_summarize_reads_the_page_frame_against_the_served_inline_blocks():
    from pnakotic.src.scanner.card_watch import summarize

    served = b"<html><head>\n<script>\nvar a = 1;\nvar b = 2;\n</script>\n</head><body></body></html>"
    inside = {"via": "appendChild", "stack": f"Error\n    at {PAGE}:3:5"}
    outside = {"via": "appendChild", "stack": f"Error\n    at {PAGE}:7:5"}
    [a, b] = summarize([inside, outside], 1, "shop.example", PAGE + "#x", served)["inserted"]
    assert a["owner"] == "store" and b["owner"] == "unknown"


def test_summarize_bounds_frames_and_marks_a_cut_stack():
    from pnakotic.src.scanner.card_watch import summarize

    long_url = STORE + "/" + "a" * 400 + ".js"
    deep = "Error\n" + "".join(f"    at f (https://shop.example/{i}.js:1:1)\n" for i in range(31))
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

    unseen = {"via": "unseen", "owner": "unknown", "vendors": [], "frames": [], "cut": False}
    assert summarize([], 1, "shop.example", PAGE, b"<html><body></body></html>")["inserted"] == [unseen]
    assert summarize([], 1, "shop.example", PAGE, None)["inserted"] == [unseen]
    served = b"<form><input name='cardnumber' autocomplete='cc-number'></form>"
    assert summarize([], 1, "shop.example", PAGE, served)["inserted"] == []  # served with the page
    assert summarize([], 0, "shop.example", PAGE, None)["inserted"] == []  # no card inputs at all
    seen = summarize([{"via": "append", "stack": STORE_STACK}], 2, "shop.example", PAGE, None)["inserted"]
    assert [e["via"] for e in seen] == ["append"]


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
    w._on_page_event(_source(), {"via": "innerHTML", "stack": "x" * 5000})
    assert w.events == [{"via": "innerHTML", "stack": "x" * 4000, "cut": True}]
    w._on_page_event(_source(), {"via": "eval", "stack": ""})  # not a hook's name
    w._on_page_event(_source(), "appendChild")
    w._on_page_event(_source(main=False), {"via": "appendChild", "stack": ""})  # a subframe's own document
    w._on_page_event(_source(), {"via": "appendChild", "stack": 42})
    assert len(w.events) == 2 and w.events[1] == {"via": "appendChild", "stack": "", "cut": False}
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
