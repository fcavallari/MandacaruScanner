#!/usr/bin/env python3
"""Card-field watch on real WooCommerce checkouts (controller's extra observation).

Attaches Pnakotic's CardWatcher and EvalCapture to a plain Playwright context the way
engine._scan_in_context does (watcher before new_page, eval capture on the page's CDP session
before goto, served body and document charset read the engine's way), loads each checkout
with a filled cart, and prints card_watch.summarize() with site_host="localhost" and the
checkout URL as landing_url. Skimmer OFF first; then once with the skimmer ON (typing the
test card and blurring the field, which the testbed skimmer reads and sends).

Needs PYTHONPATH set to the directory that holds the pnakotic checkout, e.g.
  PYTHONPATH=/path/to/parent-of-pnakotic python3 card_watch_observe.py
"""
import asyncio
import sys

from playwright.async_api import async_playwright

from spike_common import STORE, Out, cheapest_product, fill_card, launch, option, settle, toggle

from pnakotic.src.scanner.card_watch import CARD_SELECTOR, CardWatcher, html_has_card_input, summarize
from pnakotic.src.scanner.engine import _document_charset, _served_body
from pnakotic.src.scanner.eval_capture import EvalCapture

out = Out("card_watch_observe")
CHECKOUTS = (("block", "/checkout/"), ("classic", "/checkout-classic/"))


async def observe(browser, kind: str, path: str, pid: int, type_card: bool) -> None:
    ctx = await browser.new_context(viewport={"width": 1280, "height": 1600})
    # Fill the cart without a page, so the watcher and the parse record see only the checkout.
    r = await ctx.request.get(STORE + "/?add-to-cart={}".format(pid))
    cards = CardWatcher()
    await cards.attach(ctx)  # before new_page, as the engine does
    page = await ctx.new_page()
    cdp = await ctx.new_cdp_session(page)
    await cdp.send("Page.enable")
    main_frame_id = (await cdp.send("Page.getFrameTree"))["frameTree"]["frame"]["id"]
    evals = EvalCapture()

    async def warm_up():
        await page.evaluate("'pnakotic' + '-warm-up'")
    await evals.attach(cdp, warm_up=warm_up)
    served_resp = None

    def on_resp(resp):
        nonlocal served_resp
        if resp.request.is_navigation_request() and resp.request.frame == page.main_frame and not (300 <= resp.status < 400):
            served_resp = resp
    page.on("response", on_resp)
    await page.goto(STORE + path, wait_until="load")
    await settle(page, 1500)
    await page.locator('input[autocomplete="cc-number"]').first.wait_for(state="visible", timeout=15000)
    await settle(page, 2000)
    if type_card:
        await fill_card(page)
        await settle(page, 1500)
    present = await page.locator("css=" + CARD_SELECTOR).count()
    charset = await _document_charset(cdp, main_frame_id)
    served = await _served_body(served_resp)
    served_url = served_resp.url
    await evals.drain()
    parsed = evals.positions_at(served_url)
    summary = summarize(cards.events, present, "localhost", served_url, served, dropped=cards.dropped,
                        parsed=parsed, charset=charset)
    out("  served: {} ({} bytes, status {}), charset {}, parse record: {} hashes at the page URL, eval stages: {}".format(
        served_url.replace(STORE, ""), len(served or b""), served_resp.status, charset,
        len(parsed) if parsed is not None else None, len(evals.stages)))
    out("  present={} dropped={} unverifiable={} insertions={}".format(
        summary["present"], summary["dropped"], summary["unverifiable"], len(summary["inserted"])))
    for i, ins in enumerate(summary["inserted"]):
        out("  #{} via={} owner={} verified={} vendors={} cut={} first_unknown={!r}".format(
            i + 1, ins["via"], ins["owner"], ins["verified"], ins["vendors"], ins["cut"], ins["first_unknown"]))
        for f in ins["frames"]:
            out("       frame: {}".format(f.replace(STORE, "")))
        if ins["owner"] != "store" and i < len(cards.events):
            for line in cards.events[i]["stack"].splitlines()[1:6]:
                out("       raw: {}".format(line.strip()[:160]))
    text = served.decode("utf-8", "replace") if served else ""
    out("  card inputs in the served HTML (card_watch.html_has_card_input): {}; served text names "
        "autocomplete=\"cc-number\" anywhere (e.g. in a script): {}".format(
            html_has_card_input(text), 'autocomplete="cc-number"' in text))
    out("  watcher events seen: {} ({})".format(len(cards.events), [e["via"] for e in cards.events]))
    await ctx.close()


async def main() -> None:
    pid = int(cheapest_product()["id"])
    try:
        async with async_playwright() as p:
            browser = await launch(p)
            out("browser:", browser.version, "headless; site_host='localhost'; product", pid)
            out("skimmer option =", option("pnakotic_test_skimmer"))
            for kind, path in CHECKOUTS:
                out("\n== {} checkout {} , skimmer OFF ==".format(kind, path))
                await observe(browser, kind, path, pid, type_card=False)
            toggle("skimmer", "on")
            out("\nskimmer option =", option("pnakotic_test_skimmer"))
            for kind, path in CHECKOUTS:
                out("\n== {} checkout {} , skimmer ON, test card typed and blurred ==".format(kind, path))
                await observe(browser, kind, path, pid, type_card=True)
            await browser.close()
    finally:
        toggle("skimmer", "off")
        out("\nskimmer option restored =", option("pnakotic_test_skimmer"))


if __name__ == "__main__":
    asyncio.run(main())
