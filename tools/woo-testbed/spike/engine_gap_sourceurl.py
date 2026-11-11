"""Repro: a served inline <script> carrying `//# sourceURL=` (WordPress adds one to every inline
script it prints) is recorded by EvalCapture under the sourceURL name, not the page URL, so
code_origin never trusts its hash; a card input it inserts reads owner=unknown, verified=True."""
import asyncio, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, "/Users/fioa8c/WORK/Pnakotic/pnakotic/.claude/worktrees/checkout-skimmer")
from playwright.async_api import async_playwright
from pnakotic.src.scanner.card_watch import CARD_SELECTOR, CardWatcher, summarize
from pnakotic.src.scanner.eval_capture import EvalCapture

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
