#!/usr/bin/env python3
"""Q2: does /?add-to-cart=<id> fill the cart the block checkout reads?

Fresh cookie-less contexts. (a) a page navigation to /?add-to-cart=<id>, then the Store API
cart from the same context and both checkouts; (b) the same URL fetched with the context's
APIRequestContext (no page), then the block checkout; (c) the URL loaded twice; (d) the
sold-out and the variable product.
"""
import asyncio

from playwright.async_api import async_playwright

from spike_common import STORE, Out, cheapest_product, launch, settle

out = Out("q2_add_to_cart")


async def cart_api(ctx):
    r = await ctx.request.get(STORE + "/wp-json/wc/store/v1/cart")
    data = await r.json()
    return [(i["id"], i["name"], i["quantity"]) for i in data.get("items", [])], data.get("totals", {}).get("total_price")


async def checkout_view(ctx, path: str):
    page = await ctx.new_page()
    chain = []
    page.on("response", lambda r: chain.append("{} {}".format(r.status, r.url.replace(STORE, "")))
            if r.request.is_navigation_request() and r.request.frame == page.main_frame else None)
    await page.goto(STORE + path, wait_until="load")
    await settle(page, 1000)
    try:
        await page.locator('input[autocomplete="cc-number"]').first.wait_for(state="visible", timeout=10000)
    except Exception:
        pass
    view = await page.evaluate("""() => ({
        summary: (document.querySelector('.wp-block-woocommerce-checkout-order-summary-block, .woocommerce-checkout-review-order-table') || {textContent: ''})
                 .textContent.replace(/\\s+/g, ' ').slice(0, 160),
        card_inputs: document.querySelectorAll('input[autocomplete="cc-number"]').length,
        empty: !!document.querySelector('.wc-block-checkout-empty, .wp-block-woocommerce-empty-cart-block'),
    })""")
    out("    {:<20} {} -> final {}  {}".format(path, " | ".join(chain), page.url.replace(STORE, ""), view))
    await page.close()


async def main() -> None:
    prod = cheapest_product()
    pid = prod["id"]
    out("product:", pid, prod["name"])
    async with async_playwright() as p:
        browser = await launch(p)
        out("browser:", browser.version, "headless")

        out("\n(a) page navigation to /?add-to-cart={}".format(pid))
        ctx = await browser.new_context()
        page = await ctx.new_page()
        chain = []
        page.on("response", lambda r: chain.append("{} {}".format(r.status, r.url.replace(STORE, "")))
                if r.request.is_navigation_request() and r.request.frame == page.main_frame else None)
        await page.goto(STORE + "/?add-to-cart={}".format(pid), wait_until="load")
        msg = await page.evaluate("""() => [...document.querySelectorAll('.woocommerce-message, .wc-block-components-notice-banner')]
                                   .map(e => e.innerText.replace(/\\s+/g, ' ').trim()).join(' / ')""")
        out("    navigation:", " | ".join(chain), " final:", page.url.replace(STORE, ""))
        out("    notice:", repr(msg))
        cookies = sorted(c["name"] for c in await ctx.cookies())
        out("    cookies set:", [c if not c.startswith("wp_woocommerce_session_") else "wp_woocommerce_session_<hash>" for c in cookies])
        out("    Store API cart (same context):", await cart_api(ctx))
        await checkout_view(ctx, "/checkout/")
        await checkout_view(ctx, "/checkout-classic/")
        await ctx.close()

        out("\n(b) APIRequestContext GET /?add-to-cart={} (no page), then the block checkout".format(pid))
        ctx = await browser.new_context()
        r = await ctx.request.get(STORE + "/?add-to-cart={}".format(pid), max_redirects=0)
        out("    status:", r.status, " cart:", await cart_api(ctx))
        await checkout_view(ctx, "/checkout/")
        await ctx.close()

        out("\n(c) the add-to-cart URL loaded twice in one context")
        ctx = await browser.new_context()
        page = await ctx.new_page()
        for _ in range(2):
            await page.goto(STORE + "/?add-to-cart={}".format(pid), wait_until="load")
        out("    cart:", await cart_api(ctx))
        await ctx.close()

        for other, label in ((14, "sold out"), (15, "variable")):
            out("\n(d) /?add-to-cart={} ({})".format(other, label))
            ctx = await browser.new_context()
            page = await ctx.new_page()
            await page.goto(STORE + "/?add-to-cart={}".format(other), wait_until="load")
            msg = await page.evaluate("""() => [...document.querySelectorAll('.woocommerce-error, .woocommerce-message, .woocommerce-info, .wc-block-components-notice-banner')]
                                       .map(e => e.innerText.replace(/\\s+/g, ' ').trim()).join(' / ')""")
            out("    final:", page.url.replace(STORE, ""), " notice:", repr(msg[:200]), " cart:", await cart_api(ctx))
            await ctx.close()
        await browser.close()


if __name__ == "__main__":
    asyncio.run(main())
