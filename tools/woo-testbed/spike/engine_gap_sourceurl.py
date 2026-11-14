"""Regression check for the spike's inline-block gap, fixed in 0fa9372: a served inline <script>
carrying `//# sourceURL=` (WordPress adds one to every inline script it prints).

Chromium reports such a block's `Debugger.scriptParsed` with `url` set to the sourceURL name and
`embedderName` set to the page URL. Before the fix, EvalCapture recorded it under the name, so
code_origin never trusted its hash and a card input it inserted read owner=unknown, verified=True
(a false alarm against the store's own code). EvalCapture now records it under `embedderName`, so
both pages below should print owner=store."""
import asyncio, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))  # the directory that holds mandacaru/
from playwright.async_api import async_playwright
from mandacaru.src.scanner.card_watch import CARD_SELECTOR, CardWatcher, summarize
from mandacaru.src.scanner.eval_capture import EvalCapture

ADD = "var i=document.createElement('input');i.setAttribute('autocomplete','cc-number');document.body.appendChild(i);"
PAGES = {
    "/plain": "<!doctype html><html><body><script>" + ADD + "</script></body></html>",
    "/sourceurl": "<!doctype html><html><body><script>" + ADD + "\n//# sourceURL=wc-gateway-js-after\n</script></body></html>",
}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        body = PAGES.get(self.path, "").encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

async def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    async with async_playwright() as p:
        b = await p.chromium.launch()
        for path in PAGES:
            ctx = await b.new_context(); cards = CardWatcher(); await cards.attach(ctx)
            page = await ctx.new_page(); cdp = await ctx.new_cdp_session(page)
            parsed_urls = []
            cdp.on("Debugger.scriptParsed", lambda e: parsed_urls.append(e.get("url")) if e.get("startLine") else None)
            evals = EvalCapture(); await evals.attach(cdp, warm_up=lambda: page.evaluate("1"))
            resp = await page.goto(base + path); await page.wait_for_timeout(500)
            served = await resp.body(); await evals.drain()
            present = await page.locator("css=" + CARD_SELECTOR).count()
            s = summarize(cards.events, present, "127.0.0.1", resp.url, served, parsed=evals.positions_at(resp.url), charset="UTF-8")
            ins = s["inserted"][0]
            print(path, "| scriptParsed url of the block:", parsed_urls, "| positions_at(page):", evals.positions_at(resp.url) and len(evals.positions_at(resp.url)),
                  "| frames:", ins["frames"], "| owner:", ins["owner"], "verified:", ins["verified"])
            await ctx.close()
        await b.close()
    srv.shutdown()
asyncio.run(main())
