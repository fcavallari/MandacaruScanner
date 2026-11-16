#!/usr/bin/env python3
"""Q4: which requests create an order, when the block checkout makes its draft, how long stock
is held, and whether the order guard keeps every order out of existence (5 runs per checkout).

Per checkout (block /checkout/, classic /checkout-classic/), each run in a fresh context with
its own billing email (spike-q4-<run>@checkout-check.invalid):
  observe   guard off, mandacaru_test: every non-GET request, with order snapshots after each
            phase (cart, checkout load, fill, click). Shows the gateway's server-side failure.
  control   guard off, cash on delivery (toggle.sh gateways extra on, then off): an order really
            gets created when nothing blocks the click (positive control). One per checkout.
  guard x5  mandacaru_test, the guard armed after the form settled, then a mouse click on Place
            Order and 5 s of waiting. The guard is CDP Fetch at the Request stage on the page
            session (as EgressGuard is attached today; q5 covers frames and workers): every
            non-GET request is recorded and failed with BlockedByClient.

Orders are counted with wp-cli (--status=any and --status=checkout-draft, asked separately)
before and after every run, and read straight from wp_posts (HPOS is off on the testbed) for
the per-phase snapshots. Stock: the product gets managed stock (100) for the duration, so
wp_wc_reserved_stock can show a hold; restored at the end. Orders are left for cleanup.py.
"""
import asyncio
import json
import sys

from playwright.async_api import async_playwright

from spike_common import (STORE, TEST_CARD, OrderGuard, Out, cheapest_product, click_place_order, fill_block,
                          fill_card, fill_classic, launch, notices, option, orders_sql, orders_wpcli,
                          reserved_stock, select_gateway, settle, sql, toggle, wp)

out = Out("q4_order_guard")
CHECKOUTS = (("block", "/checkout/"), ("classic", "/checkout-classic/"))
RUNS = 5


def diff(before, after) -> str:
    b = {o["id"]: o for o in before}
    a = {o["id"]: o for o in after}
    new = ["#{} {}".format(i, a[i]["status"]) for i in a if i not in b]
    changed = ["#{} {}->{}".format(i, b[i]["status"], a[i]["status"]) for i in a
               if i in b and b[i]["status"] != a[i]["status"]]
    touched = ["#{} modified".format(i) for i in a if i in b and b[i]["status"] == a[i]["status"]
               and b[i]["modified"] != a[i]["modified"]]
    gone = ["#{} gone".format(i) for i in b if i not in a]
    return ", ".join(new + changed + touched + gone) or "no change"


def wpcli_line(counts) -> str:
    any_ = counts["any"]
    drafts = counts["checkout-draft"]
    return "wp-cli --status=any: {} | --status=checkout-draft: {}".format(
        [(o["id"], o["status"]) for o in any_] if isinstance(any_, list) else any_,
        [(o["id"], o["status"]) for o in drafts] if isinstance(drafts, list) else drafts)


class RequestLog:
    """Non-GET requests the page made, with their outcome (Playwright's view, not the guard's)."""

    def __init__(self, page, t0) -> None:
        self.rows = []
        self.t0 = t0
        page.on("request", self._req)
        page.on("requestfailed", self._failed)
        page.on("requestfinished", self._finished)

    def _req(self, r):
        if r.method not in ("GET", "HEAD", "OPTIONS"):
            body = r.post_data or ""
            self.rows.append({"req": r, "t": round(asyncio.get_event_loop().time() - self.t0, 2), "method": r.method,
                              "url": r.url.replace(STORE, ""), "body": body[:300], "card": TEST_CARD in body,
                              "outcome": "pending"})

    def _failed(self, r):
        for row in self.rows:
            if row["req"] is r:
                row["outcome"] = "failed: " + (r.failure or "")

    def _finished(self, r):
        for row in self.rows:
            if row["req"] is r:
                row["outcome"] = "finished"

    async def statuses(self):
        for row in self.rows:
            if row["outcome"] == "finished":
                try:
                    resp = await row["req"].response()
                    row["outcome"] = "HTTP {}".format(resp.status if resp else "?")
                except Exception:
                    pass


async def browser_targets(browser) -> list:
    bs = await browser.new_browser_cdp_session()
    res = await bs.send("Target.getTargets")
    await bs.detach()
    return sorted("{}:{}".format(t["type"], t["url"].replace(STORE, "")[:50]) for t in res["targetInfos"]
                  if t["type"] not in ("page", "browser", "tab"))


async def run(browser, kind: str, path: str, label: str, gateway: str, guard_on: bool, pid: int) -> dict:
    email = "spike-q4-{}@checkout-check.invalid".format(label)
    ctx = await browser.new_context(viewport={"width": 1280, "height": 1600})
    page = await ctx.new_page()
    t0 = asyncio.get_event_loop().time()
    log = RequestLog(page, t0)
    snaps = [("start", orders_sql())]
    await page.goto(STORE + "/?add-to-cart={}".format(pid), wait_until="load")
    snaps.append(("after add-to-cart", orders_sql()))
    n_cart = len(log.rows)
    await page.goto(STORE + path, wait_until="load")
    await settle(page)
    await page.locator('input[autocomplete="cc-number"]').first.wait_for(state="visible", timeout=15000)
    snaps.append(("after checkout load", orders_sql()))
    n_load = len(log.rows)
    if kind == "block":
        await fill_block(page, email)
    else:
        await fill_classic(page, email)
    await select_gateway(page, gateway)
    await settle(page)
    if gateway == "mandacaru_test":
        await fill_card(page)
    await settle(page, 2000)  # let the pre-click POSTs finish before arming
    snaps.append(("after fill", orders_sql()))
    n_fill = len(log.rows)
    guard = None
    targets = await browser_targets(browser)
    if guard_on:
        guard = OrderGuard()
        await guard.arm(await ctx.new_cdp_session(page), "page")
    point = await click_place_order(page)
    await page.wait_for_timeout(5000)
    shown = await notices(page)
    final = page.url.replace(STORE, "")
    snaps.append(("after click +5s", orders_sql()))
    await log.statuses()
    await ctx.close()
    await asyncio.sleep(1.5)
    snaps.append(("after context closed", orders_sql()))
    return {"label": label, "snaps": snaps, "log": log, "marks": (n_cart, n_load, n_fill), "guard": guard,
            "point": point, "notices": shown, "final": final, "targets": targets}


def show(res: dict, verbose: bool) -> None:
    snaps = res["snaps"]
    for (name, s), (_, prev) in zip(snaps[1:], snaps[:-1]):
        out("    orders {:<22} {}".format(name + ":", diff(prev, s)))
    if verbose:
        n_cart, n_load, n_fill = res["marks"]
        out("    non-GET requests (Playwright's view; t from context start):")
        log = res["log"]
        for title, rows in (("add-to-cart", log.rows[:n_cart]), ("checkout load", log.rows[n_cart:n_load]),
                            ("fill and select gateway", log.rows[n_load:n_fill]),
                            ("Place Order click at {}".format(res["point"]), log.rows[n_fill:])):
            out("      -- {} --".format(title))
            for row in rows:
                out("      {:>6}s {} {} -> {}{}".format(row["t"], row["method"], row["url"][:110], row["outcome"],
                                                      "  [body has the test card]" if row["card"] else ""))
                if title.startswith("Place Order"):
                    out("               body: {}".format(row["body"][:240]))
    out("    other targets at arming time:", res["targets"] or "none")
    out("    after click: final URL {} notices {}".format(res["final"], res["notices"]))
    if res["guard"] is not None:
        g = res["guard"]
        out("    guard: {} paused, {} failed (non-GET):".format(len(g.records), len(g.blocked)))
        for rec in g.blocked:
            out("      FAILED {} {} (t={}s, {} body bytes kept, test card in body: {})".format(
                rec["method"], rec["url"].replace(STORE, "")[:110], rec["t"], len(rec["body"]), TEST_CARD in rec["body"]))


async def main() -> None:
    prod = cheapest_product()
    pid = int(prod["id"])
    out("product:", pid, prod["name"], "| woocommerce_hold_stock_minutes =", option("woocommerce_hold_stock_minutes"))
    out("gateways:", wp("wc", "payment_gateway", "list", "--fields=id,enabled", "--format=csv", "--user=admin").replace("\n", " "))
    out("baseline", wpcli_line(orders_wpcli()), "| wp_posts:", orders_sql(), "| reserved:", reserved_stock())
    stock_before = sql("select meta_key, meta_value from wp_postmeta where post_id={} and meta_key in ('_manage_stock','_stock')".format(pid))
    wp("wc", "product", "update", str(pid), "--manage_stock=true", "--stock_quantity=100", "--user=admin")
    out("managed stock on for the run:", sql("select meta_key, meta_value from wp_postmeta where post_id={} and meta_key in ('_manage_stock','_stock')".format(pid)),
        "(was {})".format(stock_before))
    summary = []
    try:
        async with async_playwright() as p:
            browser = await launch(p)
            out("browser:", browser.version, "headless")
            for kind, path in CHECKOUTS:
                out("\n==================== {} checkout ({}) ====================".format(kind, path))

                out("\n[{}] observe: guard OFF, mandacaru_test (the gateway's server-side failure)".format(kind))
                before = orders_wpcli()
                res = await run(browser, kind, path, "{}-observe".format(kind), "mandacaru_test", False, pid)
                show(res, verbose=True)
                out("    reserved stock now:", reserved_stock())
                out("    before:", wpcli_line(before))
                out("    after: ", wpcli_line(orders_wpcli()))

                out("\n[{}] control: guard OFF, cod (positive control)".format(kind))
                out("    ", toggle("gateways", "extra", "on"))
                try:
                    before = orders_wpcli()
                    res = await run(browser, kind, path, "{}-control-cod".format(kind), "cod", False, pid)
                    show(res, verbose=True)
                    out("    reserved stock now:", reserved_stock(), "| stock:",
                        sql("select meta_value from wp_postmeta where post_id={} and meta_key='_stock'".format(pid)))
                    out("    before:", wpcli_line(before))
                    out("    after: ", wpcli_line(orders_wpcli()))
                finally:
                    out("    ", toggle("gateways", "extra", "off"))

                for i in range(1, RUNS + 1):
                    out("\n[{}] guard run {}/{}: guard ON, mandacaru_test".format(kind, i, RUNS))
                    before_cli = orders_wpcli()
                    res = await run(browser, kind, path, "{}-guard-{}".format(kind, i), "mandacaru_test", True, pid)
                    show(res, verbose=(i == 1))
                    after_cli = orders_wpcli()
                    out("    before:", wpcli_line(before_cli))
                    out("    after: ", wpcli_line(after_cli))
                    out("    reserved stock now:", reserved_stock())
                    g = res["guard"]
                    order_req = [r for r in g.blocked if ("wc-ajax=checkout" in r["url"]) or
                                 (r["url"].split("?")[0].endswith("/wc/store/v1/checkout") and r["method"] == "POST")]
                    first, last = res["snaps"][3][1], res["snaps"][-1][1]  # after fill, after close
                    summary.append((kind, i, len(order_req), diff(first, last),
                                    [r["method"] + " " + r["url"].replace(STORE, "")[:60] for r in g.blocked]))
            await browser.close()
    finally:
        wp("wc", "product", "update", str(pid), "--manage_stock=false", "--user=admin")
        sql("update wp_postmeta set meta_value=NULL where post_id={} and meta_key='_stock'".format(pid))
        sql("update wp_wc_product_meta_lookup set stock_quantity=NULL where product_id={}".format(pid))
        out("\nstock restored:", sql("select meta_key, meta_value from wp_postmeta where post_id={} and meta_key in ('_manage_stock','_stock')".format(pid)))
        out("gateways now:", wp("wc", "payment_gateway", "list", "--fields=id,enabled", "--format=csv", "--user=admin").replace("\n", " "))

    out("\n==================== summary of the guard runs ====================")
    out("  checkout run  order-request-failed-by-guard  orders: after fill -> after close   guard failed")
    for kind, i, n, d, blocked in summary:
        out("  {:<8} {}    {}                              {:<30} {}".format(kind, i, n, d, blocked))
    out("\nall orders now (wp_posts):", orders_sql())
    out("reserved stock now:", reserved_stock())


if __name__ == "__main__":
    asyncio.run(main())
