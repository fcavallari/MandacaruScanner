#!/usr/bin/env python3
"""Q5: does CDP Fetch on the page session reach a cross-site iframe and workers?

A small server on a third origin (127.0.0.1, a free port; started here, not the collector)
serves an iframe page, a dedicated worker and a SharedWorker, and logs every request it gets:
that log is the ground truth for what left the browser. The top page is the store's homepage
(localhost:8188), so the 127.0.0.1 iframe is cross-site and should be out of process.

Every sender fires one POST "at start-up" (as soon as it runs) and more on a later "go"
message, after any guard has been armed:
  main frame (store):   main-fetch, main-beacon, and a blob: dedicated worker (main-blob-worker[-startup])
  iframe (127.0.0.1):   iframe-startup, iframe-fetch, iframe-beacon, iframe-form (a form submit),
                        a dedicated worker (iframe-worker[-startup]), a SharedWorker (shared-[startup|worker])
plus GET controls (iframe-get, iframe-worker-get) that the guard lets through.

Modes, each in a fresh browser:
  A  page-session   Playwright ctx.new_cdp_session(page) + Fetch.enable (what EgressGuard does today)
  C  pw-frame       A, plus ctx.new_cdp_session(iframe) + Fetch.enable once the iframe exists
  B  autoattach     raw CDP WebSocket (--remote-debugging-port): page session with
                    Target.setAutoAttach {flatten, waitForDebuggerOnStart} and Fetch.enable on
                    every attached target, recursively; plus browser-level auto-attach for shared_worker
  B0 autoattach-nowait   B with waitForDebuggerOnStart false (the start-up race)
  P  pw-autoattach  Playwright CDPSession: Target.setAutoAttach flatten on the page session; can
                    the child sessions be driven at all?
"""
import asyncio
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from playwright.async_api import async_playwright

from spike_common import STORE, OrderGuard, Out, RawCDP, free_port, launch

# `python3 q5_fetch_reach.py run2` writes out/q5_fetch_reach-run2.log, so repeated runs keep their logs.
out = Out("q5_fetch_reach" + ("-" + sys.argv[1] if len(sys.argv) > 1 else ""))

FRAME_HTML = """<!doctype html><html><body>spike frame
<script>
const H = (from, init) => fetch('/hit?from=' + from, init).catch(() => {});
H('iframe-startup', {method: 'POST', body: 'startup'});
const w = new Worker('/worker.js');
let sw = null;
try { sw = new SharedWorker('/shared.js'); sw.port.start(); } catch (e) {}
addEventListener('message', (e) => {
  if (e.data !== 'go') return;
  H('iframe-fetch', {method: 'POST', body: 'f'});
  H('iframe-get', {});
  navigator.sendBeacon('/hit?from=iframe-beacon', 'b');
  w.postMessage('go');
  if (sw) sw.port.postMessage('go');
  setTimeout(() => {
    const f = document.createElement('form'); f.method = 'POST'; f.action = '/hit?from=iframe-form';
    const i = document.createElement('input'); i.name = 'x'; i.value = '1'; f.appendChild(i);
    document.body.appendChild(f); f.submit();
  }, 1500);
});
parent.postMessage('ready', '*');
</script></body></html>"""

WORKER_JS = """fetch('/hit?from=iframe-worker-startup', {method: 'POST', body: 'ws'}).catch(() => {});
onmessage = () => {
  fetch('/hit?from=iframe-worker', {method: 'POST', body: 'w'}).catch(() => {});
  fetch('/hit?from=iframe-worker-get').catch(() => {});
};"""

SHARED_JS = """fetch('/hit?from=shared-startup', {method: 'POST', body: 'ss'}).catch(() => {});
onconnect = (e) => {
  const port = e.ports[0];
  port.onmessage = () => fetch('/hit?from=shared-worker', {method: 'POST', body: 's'}).catch(() => {});
  port.start();
};"""

POST_LABELS = ["main-fetch", "main-beacon", "main-blob-worker-startup", "main-blob-worker",
               "iframe-startup", "iframe-fetch", "iframe-beacon", "iframe-form",
               "iframe-worker-startup", "iframe-worker", "shared-startup", "shared-worker"]

HITS = []  # (method, from) the server received


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _handle(self):
        parts = urlsplit(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(min(n, 10000))
        if parts.path == "/hit":
            HITS.append((self.command, parse_qs(parts.query).get("from", ["?"])[0]))
            return self._send(204)
        pages = {"/frame.html": (FRAME_HTML, "text/html"), "/worker.js": (WORKER_JS, "text/javascript"),
                 "/shared.js": (SHARED_JS, "text/javascript")}
        if parts.path in pages:
            body, ctype = pages[parts.path]
            return self._send(200, body.encode(), ctype)
        return self._send(404)

    do_GET = do_POST = do_OPTIONS = _handle


MAIN_JS = """async (base) => {
  await new Promise((resolve) => {
    addEventListener('message', (e) => { if (e.data === 'ready') resolve(); });
    const f = document.createElement('iframe'); f.id = 'spike'; f.src = base + '/frame.html';
    document.body.appendChild(f);
  });
  return true;
}"""

GO_JS = """async (base) => {
  const H = (from, init) => fetch(base + '/hit?from=' + from, Object.assign({mode: 'no-cors'}, init)).catch(() => {});
  const src = `fetch('${base}/hit?from=main-blob-worker-startup', {method: 'POST', body: 'bs', mode: 'no-cors'}).catch(() => {});
               onmessage = () => fetch('${base}/hit?from=main-blob-worker', {method: 'POST', body: 'bw', mode: 'no-cors'}).catch(() => {});`;
  const bw = new Worker(URL.createObjectURL(new Blob([src], {type: 'text/javascript'})));
  await new Promise((r) => setTimeout(r, 500));
  H('main-fetch', {method: 'POST', body: 'm'});
  navigator.sendBeacon(base + '/hit?from=main-beacon', 'mb');
  bw.postMessage('go');
  document.getElementById('spike').contentWindow.postMessage('go', '*');
  return true;
}"""


async def targets_of(browser_session_send) -> list:
    res = await browser_session_send("Target.getTargets", {})
    return sorted("{}:{}".format(t["type"], t["url"][:60]) for t in res["targetInfos"]
                  if t["type"] in ("iframe", "worker", "shared_worker", "service_worker"))


async def drive(page, base: str, after_iframe=None) -> None:
    await page.goto(STORE + "/", wait_until="domcontentloaded", timeout=60000)
    await page.evaluate(MAIN_JS, base)
    if after_iframe:
        await after_iframe()
    await page.evaluate(GO_JS, base)
    await page.wait_for_timeout(4000)


def report(mode: str, guard: OrderGuard, targets: list, extra: str = "") -> dict:
    hits = list(HITS)
    paused = {}
    for rec in guard.records:
        label = parse_qs(urlsplit(rec["url"]).query).get("from", [None])[0]
        if label:
            paused.setdefault(label, set()).add(rec["target"])
    out("\n== mode {} ==".format(mode))
    if extra:
        out("  " + extra)
    out("  sessions with Fetch on:", guard.sessions)
    out("  targets seen (Target.getTargets):", targets)
    row = {}
    for label in POST_LABELS:
        reached = [m for m, f in hits if f == label]
        where = sorted(paused.get(label, []))
        verdict = "LEAKED" if reached else ("blocked" if where else "not sent?")
        row[label] = verdict
        out("  {:<26} server got: {:<8} paused on: {:<28} -> {}".format(
            label, ",".join(reached) or "-", ",".join(where) or "-", verdict))
    gets = [f for m, f in hits if m == "GET"]
    out("  GET controls at the server:", sorted(set(gets)))
    return row


async def mode_page_session(p, with_frame_session: bool) -> dict:
    HITS.clear()
    browser = await launch(p, channel=CHANNEL)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    guard = OrderGuard()
    await guard.arm(await ctx.new_cdp_session(page), "page")
    extra = ""

    async def attach_frame():
        nonlocal extra
        frame = next(f for f in page.frames if "/frame.html" in f.url)
        try:
            await guard.arm(await ctx.new_cdp_session(frame), "pw-frame-session")
        except Exception as exc:
            extra = "new_cdp_session(frame) failed: {}".format(str(exc)[:200])
    await drive(page, BASE, attach_frame if with_frame_session else None)
    bs = await browser.new_browser_cdp_session()
    row = report("C pw-frame" if with_frame_session else "A page-session", guard,
                 await targets_of(bs.send), extra)
    await browser.close()
    return row


async def mode_autoattach(p, wait: bool) -> dict:
    HITS.clear()
    port = free_port()
    browser = await launch(p, debug_port=port, channel=CHANNEL)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    conn = RawCDP()
    root = await conn.connect(port)
    guard = OrderGuard()
    attached = []
    setup_notes = []  # dedicated workers have no Fetch domain: their requests go through the owning frame

    def watch(session) -> None:
        def on_attached(ev):
            info = ev["targetInfo"]
            child = conn.session(ev["sessionId"], "{}:{}".format(info["type"], info["url"][:40]))
            attached.append("{} (waiting={})".format(child.label, ev.get("waitingForDebugger")))
            watch(child)
            asyncio.ensure_future(setup(child, info["type"]))
        session.on("Target.attachedToTarget", on_attached)

    async def setup(session, ttype: str) -> None:
        try:
            await guard.arm(session, session.label)
            if ttype in ("page", "iframe", "worker"):
                await session.send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": wait, "flatten": True})
        except Exception as exc:
            setup_notes.append("{}: {}".format(session.label, str(exc)[:120]))
        try:
            await session.send("Runtime.runIfWaitingForDebugger")
        except Exception:
            pass

    infos = (await root.send("Target.getTargets"))["targetInfos"]
    page_target = next(t for t in infos if t["type"] == "page")
    sid = (await root.send("Target.attachToTarget", {"targetId": page_target["targetId"], "flatten": True}))["sessionId"]
    page_session = conn.session(sid, "page")
    watch(page_session)
    await setup(page_session, "page")
    watch(root)  # browser-level auto-attach: SharedWorkers are not a page's children
    shared_note = ""
    try:
        await root.send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": wait, "flatten": True,
                                                 "filter": [{"type": "shared_worker"}]})
    except Exception as exc:
        shared_note = "browser-level auto-attach for shared_worker failed: {}".format(str(exc)[:200])
    await drive(page, BASE)
    row = report("B autoattach" if wait else "B0 autoattach-nowait", guard,
                 await targets_of(root.send), shared_note)
    out("  attached:", attached)
    out("  Fetch.enable refused by:", setup_notes)
    await conn.close()
    await browser.close()
    return row


async def mode_pw_autoattach(p) -> None:
    """Can Playwright's own CDPSession drive flattened children?"""
    browser = await launch(p, channel=CHANNEL)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    cdp = await ctx.new_cdp_session(page)
    events = []
    cdp.on("Target.attachedToTarget", lambda ev: events.append((ev["targetInfo"]["type"], ev["sessionId"])))
    note = "ok"
    try:
        await cdp.send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True})
    except Exception as exc:
        note = "setAutoAttach failed: {}".format(str(exc)[:200])
    HITS.clear()
    await drive(page, BASE)
    out("\n== mode P pw-autoattach ==")
    out("  Target.setAutoAttach flatten on a Playwright CDPSession:", note)
    out("  Target.attachedToTarget events delivered to Python:", events)
    out("  Playwright's CDPSession.send(method, params) has no sessionId argument, so a flattened child "
        "cannot be sent Fetch.enable through it.")
    try:
        sig = cdp.send.__doc__.split("\n")[0] if cdp.send.__doc__ else ""
    except Exception:
        sig = ""
    out("  CDPSession.send doc:", repr(sig))
    await browser.close()


BASE = ""
CHANNEL = ""
CHANNELS = ("", "chromium", "chrome")  # headless shell (local default), full Chromium, Google Chrome


async def main() -> None:
    global BASE, CHANNEL
    port = free_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    BASE = "http://127.0.0.1:{}".format(port)
    out("third-origin server:", BASE, " top page:", STORE + "/")
    async with async_playwright() as p:
        for CHANNEL in CHANNELS:
            try:
                b = await launch(p, channel=CHANNEL)
            except Exception as exc:
                out("\n######## channel {!r}: launch failed: {}".format(CHANNEL, str(exc)[:200]))
                continue
            out("\n######## channel {!r}: browser {} (headless=True), engine CHROMIUM_ARGS, no proxy".format(
                CHANNEL or "default (chrome-headless-shell)", b.version))
            await b.close()
            rows = {}
            for key, factory in (("A", lambda: mode_page_session(p, with_frame_session=False)),
                                 ("C", lambda: mode_page_session(p, with_frame_session=True)),
                                 ("B", lambda: mode_autoattach(p, wait=True)),
                                 ("B0", lambda: mode_autoattach(p, wait=False))):
                try:
                    rows[key] = await factory()
                except Exception as exc:
                    out("\n== mode {} FAILED: {} ==".format(key, str(exc).splitlines()[0][:200]))
                    rows[key] = {label: "error" for label in POST_LABELS}
            await mode_pw_autoattach(p)
            out("\n== summary, channel {!r} (LEAKED = the third-origin server received the POST) ==".format(CHANNEL))
            out("  {:<26} {}".format("sender", "  ".join("{:<9}".format(k) for k in rows)))
            for label in POST_LABELS:
                out("  {:<26} {}".format(label, "  ".join("{:<9}".format(rows[k][label]) for k in rows)))
    server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
