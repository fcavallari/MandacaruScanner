#!/usr/bin/env python3
"""Q1: what /checkout/ does with an empty cart, block and classic.

Both checkout pages under both settings of the store's checkout page (toggle.sh checkout
block|classic), each in a fresh cookie-less browser context: navigation statuses and
Location headers, final URL, what rendered. Restores the block checkout at the end.
"""
import asyncio

from playwright.async_api import async_playwright

from spike_common import STORE, Out, launch, option, settle, toggle

out = Out("q1_empty_cart")
PAGES = ("/checkout/", "/checkout-classic/")


async def visit(browser, path: str) -> None:
    ctx = await browser.new_context()
    page = await ctx.new_page()
    chain = []

    def on_response(r):
        if r.request.is_navigation_request() and r.request.frame == page.main_frame:
            chain.append("{} {}{}".format(r.status, r.url.replace(STORE, ""),
                                          " -> " + r.headers.get("location", "").replace(STORE, "")
                                          if 300 <= r.status < 400 else ""))
    page.on("response", on_response)
    await page.goto(STORE + path, wait_until="load")
    await settle(page, 1000)
    text = await page.evaluate("""() => {
        const main = document.querySelector('main, #main, .wp-site-blocks') || document.body;
        return main.innerText.replace(/\\s+/g, ' ').slice(0, 300);
    }""")
    blocks = await page.evaluate("""() => ({
        block_checkout: !!document.querySelector('.wp-block-woocommerce-checkout, [data-block-name="woocommerce/checkout"]'),
        classic_form: !!document.querySelector('form.checkout.woocommerce-checkout'),
        block_cart: !!document.querySelector('.wp-block-woocommerce-cart'),
        empty_cart_block: !!document.querySelector('.wp-block-woocommerce-empty-cart-block, .wc-block-checkout-empty, .wc-block-cart__empty-cart__title'),
        card_inputs: document.querySelectorAll('input[autocomplete="cc-number"]').length,
        body_class: document.body.className.split(/\\s+/).filter(c => /woocommerce|checkout|cart/.test(c)).join(' '),
    })""")
    out("  {:<20} chain: {}".format(path, " | ".join(chain)))
    out("  {:<20} final: {}  title: {!r}".format("", page.url.replace(STORE, ""), await page.title()))
    out("  {:<20} dom: {}".format("", blocks))
    out("  {:<20} text: {!r}".format("", text[:220]))
    await ctx.close()


async def main() -> None:
    try:
        async with async_playwright() as p:
            browser = await launch(p)
            out("browser:", browser.version, "headless")
            for mode in ("block", "classic"):
                toggle("checkout", mode)
                out("\n== store checkout page = {} (woocommerce_checkout_page_id={}), cookie-less context ==".format(
                    mode, option("woocommerce_checkout_page_id")))
                for path in PAGES:
                    await visit(browser, path)
            await browser.close()
    finally:
        toggle("checkout", "block")
        out("\nrestored: woocommerce_checkout_page_id =", option("woocommerce_checkout_page_id"))


if __name__ == "__main__":
    asyncio.run(main())
