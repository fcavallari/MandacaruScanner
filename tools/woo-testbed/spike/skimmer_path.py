#!/usr/bin/env python3
"""Brief step 2: the skimmer path with the order guard, on both checkouts.

Skimmer on. Per checkout: fill the form and the test card, blur the card field, check the
collector got the typed number before the click; arm the guard (Fetch, Request stage, page
session), click Place Order, and check the guard's record holds the skimmer's click-time POST
body. Collector timestamps (its own time.time()) are compared with the click time.

Then, with the store's checkout page switched to the classic one (toggle.sh checkout classic),
check whether the skimmer still renders and fires on /checkout/ and /checkout-classic/
(blur only, no click). Restores: skimmer off, checkout block.
"""
import asyncio
import time

from playwright.async_api import async_playwright

from spike_common import (COLLECTOR, STORE, TEST_CARD, OrderGuard, Out, cheapest_product, click_place_order,
                          collector_lines, fill_block, fill_card, fill_classic, launch, option, orders_sql,
                          select_gateway, settle, toggle)

out = Out("skimmer_path")
COLLECTOR_HOST = COLLECTOR.split("//")[1]


def fmt(line, t_click=None) -> str:
    rel = "" if t_click is None else " ({:+.2f}s vs click)".format(line["ts"] - t_click)
    payload = line.get("body") or line.get("query") or ""
    return "{} {}{} card={} {}".format(line["method"], line["path"], rel, TEST_CARD in payload, payload[:110])


async def guarded(browser, kind: str, path: str, pid: int) -> None:
    ctx = await browser.new_context(viewport={"width": 1280, "height": 1600})
    page = await ctx.new_page()
    await page.goto(STORE + "/?add-to-cart={}".format(pid), wait_until="load")
    await page.goto(STORE + path, wait_until="load")
    await settle(page)
    has_skimmer = await page.locator("script#mandacaru-test-skimmer").count()
    await page.locator('input[autocomplete="cc-number"]').first.wait_for(state="visible", timeout=15000)
    if kind == "block":
        await fill_block(page, "spike-skimmer-{}@checkout-check.invalid".format(kind))
    else:
        await fill_classic(page, "spike-skimmer-{}@checkout-check.invalid".format(kind))
    await select_gateway(page, "mandacaru_test")
    await settle(page)
    n0 = len(collector_lines())
    await fill_card(page)  # types the number and tabs out: blur
    await settle(page, 2000)
    before_click = collector_lines()[n0:]
    out("  skimmer script in the page: {}".format(bool(has_skimmer)))
    out("  collector before the click (blur):")
    for line in before_click:
        out("    " + fmt(line))
    orders_before = orders_sql()
    guard = OrderGuard()
    await guard.arm(await ctx.new_cdp_session(page), "page")
    n1 = len(collector_lines())
    t_click = time.time()
    point = await click_place_order(page)
    await page.wait_for_timeout(5000)
    after = collector_lines()[n1:]
    out("  Place Order clicked at {} with the guard armed; collector after the click:".format(point))
    for line in after:
        out("    " + fmt(line, t_click))
    out("  guard record (all paused requests):")
    for rec in guard.records:
        out("    {} {} {} {}{}".format("FAILED" if rec["blocked"] else "passed", rec["method"], rec["url"][:100],
                                       "card-in-url " if TEST_CARD in rec["url"] else "",
                                       ("body=" + rec["body"][:160]) if rec["blocked"] else ""))
    skim_post = [r for r in guard.blocked if COLLECTOR_HOST in r["url"]]
    out("  => blur hits with the card before the click: {}; guard holds the skimmer's click-time POST with the card: {}; "
        "click-time GET beacon reached the collector: {}".format(
            sum(1 for line in before_click if TEST_CARD in (line.get("body", "") + line.get("query", ""))),
            any(TEST_CARD in r["body"] and '"trigger":"click"' in r["body"] for r in skim_post),
            any(line["method"] == "GET" and "t=click" in line.get("query", "") and TEST_CARD in line.get("query", "")
                for line in after)))
    await ctx.close()
    await asyncio.sleep(1)
    out("  orders: before click {} -> after {}".format(
        [(o["id"], o["status"]) for o in orders_before], [(o["id"], o["status"]) for o in orders_sql()]))


async def blur_only(browser, path: str, pid: int) -> None:
    ctx = await browser.new_context(viewport={"width": 1280, "height": 1600})
    page = await ctx.new_page()
    await page.goto(STORE + "/?add-to-cart={}".format(pid), wait_until="load")
    await page.goto(STORE + path, wait_until="load")
    await settle(page)
    has_skimmer = await page.locator("script#mandacaru-test-skimmer").count()
    n0 = len(collector_lines())
    try:
        await page.locator('input[autocomplete="cc-number"]').first.wait_for(state="visible", timeout=15000)
        await fill_card(page)
        await settle(page, 1500)
    except Exception as exc:
        out("    card fields not usable: {}".format(str(exc)[:120]))
    hits = [line for line in collector_lines()[n0:] if TEST_CARD in (line.get("body", "") + line.get("query", ""))]
    out("  {:<20} final {}  skimmer script: {}  collector hits with the card on blur: {}".format(
        path, page.url.replace(STORE, ""), bool(has_skimmer), len(hits)))
    await ctx.close()


async def main() -> None:
    pid = int(cheapest_product()["id"])
    try:
        toggle("skimmer", "on")
        out("skimmer option =", option("mandacaru_test_skimmer"), "| checkout page id =", option("woocommerce_checkout_page_id"))
        async with async_playwright() as p:
            browser = await launch(p)
            out("browser:", browser.version, "headless")
            for kind, path in (("block", "/checkout/"), ("classic", "/checkout-classic/")):
                out("\n== {} checkout {} ==".format(kind, path))
                await guarded(browser, kind, path, pid)
            toggle("checkout", "classic")
            out("\n== store checkout page switched to classic (id {}): blur only ==".format(option("woocommerce_checkout_page_id")))
            for path in ("/checkout/", "/checkout-classic/"):
                await blur_only(browser, path, pid)
            await browser.close()
    finally:
        toggle("checkout", "block")
        toggle("skimmer", "off")
        out("\nrestored: checkout page id =", option("woocommerce_checkout_page_id"), "| skimmer =", option("mandacaru_test_skimmer"))


if __name__ == "__main__":
    asyncio.run(main())
