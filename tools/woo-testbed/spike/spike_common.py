"""Shared helpers for the checkout spike (spec section 8). Throwaway-grade, testbed only.

Plain async Playwright plus raw CDP, not Mandacaru's engine (its egress guard refuses
localhost). Every docker command is scoped to the compose project mandacaru-woo-testbed.
Python 3.9: no `X | Y` types, no `match`.
"""
import asyncio
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

HERE = Path(__file__).resolve().parent
TESTBED = HERE.parent
OUT = HERE / "out"
STORE = "http://localhost:{}".format(os.environ.get("WOO_PORT", "8188"))
COLLECTOR = "http://127.0.0.1:{}".format(os.environ.get("COLLECTOR_PORT", "8199"))
COLLECTOR_LOG = TESTBED / "collector" / "requests.jsonl"
PROJECT = "mandacaru-woo-testbed"

# A published test number (Stripe's Visa debit), not 4111.../4242... (spec section 4.4).
TEST_CARD = "4000056655665556"
TEST_EXP = "12 / 34"
TEST_CVC = "123"

# The engine's launch flags (engine.CHROMIUM_ARGS), without the SOCKS proxy.
CHROMIUM_ARGS = [
    "--block-new-web-contents",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--force-webrtc-ip-handling-policy",
]

BODY_CAP = 2000  # bytes of a request body kept in a guard record


class Out:
    """print() to stdout and to out/<name>.log."""

    def __init__(self, name: str) -> None:
        OUT.mkdir(parents=True, exist_ok=True)
        self.path = OUT / (name + ".log")
        self._fh = self.path.open("w")
        self.t0 = time.monotonic()

    def __call__(self, *args: Any) -> None:
        line = " ".join(a if isinstance(a, str) else json.dumps(a, default=str) for a in args)
        print(line)
        self._fh.write(line + "\n")
        self._fh.flush()

    def t(self) -> str:
        return "{:7.2f}s".format(time.monotonic() - self.t0)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def launch(p, debug_port: Optional[int] = None, channel: str = ""):
    """The engine's launch (engine.launch_options) without the proxy. ``channel`` "" is
    Playwright's default for headless=True (chrome-headless-shell); "chromium" is the full
    Chromium build in new headless mode (the arm64 Docker image); "chrome" is Google Chrome
    stable (the amd64 Docker image's BROWSER_CHANNEL)."""
    args = list(CHROMIUM_ARGS)
    if debug_port:
        args.append("--remote-debugging-port={}".format(debug_port))
    opts = dict(headless=True, chromium_sandbox=True, args=args)
    if channel:
        opts["channel"] = channel
    return await p.chromium.launch(**opts)


# ---------------------------------------------------------------- docker / wp-cli / SQL

def _dc(*args: str, check: bool = True) -> str:
    cmd = ["docker", "compose", "-p", PROJECT] + list(args)
    out = subprocess.run(cmd, cwd=str(TESTBED), capture_output=True, text=True)
    if check and out.returncode != 0:
        raise RuntimeError("{} failed: {}".format(" ".join(cmd), out.stderr[-500:]))
    return out.stdout


def wp(*args: str) -> str:
    return _dc("run", "--rm", "-T", "wpcli", *args)


def sql(query: str) -> List[List[str]]:
    out = _dc("exec", "-T", "db", "mariadb", "-uwp", "-pwp-testbed", "wp", "-N", "-B", "-e", query)
    return [line.split("\t") for line in out.splitlines() if line.strip()]


def toggle(*args: str) -> str:
    out = subprocess.run(["./toggle.sh"] + list(args), cwd=str(TESTBED), capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError("toggle {} failed: {}".format(args, out.stderr[-500:]))
    return (out.stdout + out.stderr).strip().splitlines()[-1] if (out.stdout + out.stderr).strip() else ""


def orders_sql() -> List[Dict[str, str]]:
    """Every order row (HPOS is off on the testbed, so orders are wp_posts rows)."""
    rows = sql("select ID, post_status, post_modified_gmt, post_date_gmt from wp_posts "
               "where post_type like 'shop_order%' order by ID")
    return [{"id": r[0], "status": r[1], "modified": r[2], "created": r[3]} for r in rows]


def orders_wpcli() -> Dict[str, Any]:
    """The controller's count: wp-cli --status=any, and checkout-draft asked for explicitly."""
    res = {}
    for status in ("any", "checkout-draft"):
        raw = wp("wc", "shop_order", "list", "--status=" + status, "--format=json",
                 "--fields=id,status", "--user=admin")
        start = raw.find("[")
        res[status] = json.loads(raw[start:]) if start >= 0 else raw.strip()
    return res


def reserved_stock() -> List[List[str]]:
    return sql("select order_id, product_id, stock_quantity, timestamp, expires from wp_wc_reserved_stock")


def option(name: str) -> str:
    rows = sql("select option_value from wp_options where option_name='{}'".format(name))
    return rows[0][0] if rows else ""


# ---------------------------------------------------------------- store

# The Store API query question 3 settled on.
PRODUCT_QUERY = "/wp-json/wc/store/v1/products?type=simple&stock_status=instock&orderby=price&order=asc&per_page=20"


def cheapest_product() -> Dict[str, Any]:
    with urllib.request.urlopen(STORE + PRODUCT_QUERY) as r:
        for prod in json.load(r):
            if prod["type"] == "simple" and prod["is_in_stock"] and prod["is_purchasable"]:
                return prod
    raise SystemExit("no in-stock simple product")


def collector_lines() -> List[Dict[str, Any]]:
    if not COLLECTOR_LOG.exists():
        return []
    return [json.loads(line) for line in COLLECTOR_LOG.read_text().splitlines() if line.strip()]


async def fill_block(page, email: str) -> None:
    await page.locator("#email").fill(email)
    for sel, val in (("#shipping-first_name", "Check"), ("#shipping-last_name", "Spike"),
                     ("#shipping-address_1", "1 Test Street"), ("#shipping-city", "San Francisco"),
                     ("#shipping-postcode", "94103"), ("#shipping-phone", "4155550100")):
        await page.locator(sel).fill(val)
        await page.locator(sel).press("Tab")


async def fill_classic(page, email: str) -> None:
    for sel, val in (("#billing_first_name", "Check"), ("#billing_last_name", "Spike"),
                     ("#billing_address_1", "1 Test Street"), ("#billing_city", "San Francisco"),
                     ("#billing_postcode", "94103"), ("#billing_phone", "4155550100"),
                     ("#billing_email", email)):
        await page.locator(sel).fill(val)
        await page.locator(sel).press("Tab")


async def select_gateway(page, gateway: str) -> None:
    radio = page.locator('input[type=radio][value="{}"]'.format(gateway))
    await radio.first.check(force=True)


async def fill_card(page) -> None:
    for sel, val in (('input[autocomplete="cc-number"]', TEST_CARD),
                     ('input[autocomplete="cc-exp"]', TEST_EXP),
                     ('input[autocomplete="cc-csc"]', TEST_CVC)):
        field = page.locator(sel).first
        await field.click()
        await field.fill(val)
        await field.press("Tab")  # blur and change fire


PLACE_ORDER = "#place_order, .wc-block-components-checkout-place-order-button"


async def click_place_order(page):
    """A real mouse click at the centre of the button; returns the point."""
    button = page.locator(PLACE_ORDER).first
    await button.scroll_into_view_if_needed()
    box = await button.bounding_box()
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    await page.mouse.click(x, y)
    return (round(x), round(y))


async def settle(page, ms: int = 1500) -> None:
    try:
        await page.wait_for_load_state("networkidle", timeout=8000)
    except Exception:
        pass
    await page.wait_for_timeout(ms)


async def notices(page) -> List[str]:
    """Visible error/notice text on either checkout."""
    return await page.evaluate("""() => [...document.querySelectorAll(
        '.woocommerce-error, .woocommerce-NoticeGroup, .wc-block-components-notice-banner, .woocommerce-message, .woocommerce-info')]
        .map(e => e.innerText.trim().replace(/\\s+/g, ' ').slice(0, 200)).filter(Boolean)""")


# ---------------------------------------------------------------- the order guard

def _body_of(request: Dict[str, Any]) -> str:
    if isinstance(request.get("postData"), str):
        return request["postData"][:BODY_CAP]
    parts = []
    for entry in request.get("postDataEntries") or []:
        raw = entry.get("bytes")
        if isinstance(raw, str):
            try:
                parts.append(base64.b64decode(raw).decode("utf-8", "replace"))
            except Exception:
                parts.append("<undecodable>")
    return "".join(parts)[:BODY_CAP]


class OrderGuard:
    """CDP Fetch at the Request stage: every request is paused; non-GET/HEAD/OPTIONS ones are
    recorded (method, URL, bounded body) and failed with BlockedByClient, the rest continue.
    ``arm()`` takes anything with ``send(method, params)`` and ``on(event, handler)``: a
    Playwright CDPSession or a RawSession."""

    PASS = ("GET", "HEAD", "OPTIONS")

    def __init__(self, out: Optional[Callable[..., None]] = None) -> None:
        self.records: List[Dict[str, Any]] = []
        self.sessions: List[str] = []
        self.out = out
        self._tasks = set()
        self.t0 = time.monotonic()

    async def arm(self, session, name: str = "page") -> None:
        def handler(event: Dict[str, Any]) -> None:
            task = asyncio.ensure_future(self._paused(session, name, event))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        session.on("Fetch.requestPaused", handler)
        await session.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})
        self.sessions.append(name)

    async def _paused(self, session, name: str, event: Dict[str, Any]) -> None:
        req = event.get("request") or {}
        method = req.get("method", "")
        blocked = method not in self.PASS
        rec = {"t": round(time.monotonic() - self.t0, 2), "target": name, "method": method,
               "url": (req.get("url") or "")[:300], "type": event.get("resourceType"),
               "blocked": blocked, "body": _body_of(req) if blocked else ""}
        self.records.append(rec)
        if self.out:
            self.out("  [guard:{}] {} {} {}{}".format(name, "FAIL" if blocked else "pass", method, rec["url"][:150],
                                                      (" body=" + rec["body"][:160]) if blocked else ""))
        try:
            if blocked:
                await session.send("Fetch.failRequest", {"requestId": event["requestId"], "errorReason": "BlockedByClient"})
            else:
                await session.send("Fetch.continueRequest", {"requestId": event["requestId"]})
        except Exception as exc:
            rec["error"] = str(exc)[:200]

    @property
    def blocked(self) -> List[Dict[str, Any]]:
        return [r for r in self.records if r["blocked"]]


# ---------------------------------------------------------------- raw CDP over a WebSocket

class RawSession:
    """One flattened CDP session on a RawCDP connection (sessionId None = the browser)."""

    def __init__(self, conn: "RawCDP", session_id: Optional[str], label: str) -> None:
        self.conn, self.session_id, self.label = conn, session_id, label
        self.handlers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}

    def on(self, event: str, handler: Callable[[Dict[str, Any]], None]) -> None:
        self.handlers.setdefault(event, []).append(handler)

    async def send(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self.conn.send(method, params or {}, self.session_id)


class RawCDP:
    """A minimal CDP client on the browser's DevTools WebSocket (flatten mode)."""

    def __init__(self) -> None:
        self.ws = None
        self._id = 0
        self._pending: Dict[int, "asyncio.Future[Dict[str, Any]]"] = {}
        self.sessions: Dict[Optional[str], RawSession] = {}
        self._reader = None

    async def connect(self, debug_port: int) -> RawSession:
        import websockets
        with urllib.request.urlopen("http://127.0.0.1:{}/json/version".format(debug_port)) as r:
            url = json.load(r)["webSocketDebuggerUrl"]
        self.ws = await websockets.connect(url, max_size=None)
        self._reader = asyncio.ensure_future(self._read())
        browser = RawSession(self, None, "browser")
        self.sessions[None] = browser
        return browser

    def session(self, session_id: str, label: str) -> RawSession:
        if session_id not in self.sessions:
            self.sessions[session_id] = RawSession(self, session_id, label)
        return self.sessions[session_id]

    async def send(self, method: str, params: Dict[str, Any], session_id: Optional[str]) -> Dict[str, Any]:
        self._id += 1
        msg = {"id": self._id, "method": method, "params": params}
        if session_id:
            msg["sessionId"] = session_id
        fut = asyncio.get_event_loop().create_future()
        self._pending[self._id] = fut
        await self.ws.send(json.dumps(msg))
        return await asyncio.wait_for(fut, 10)

    async def _read(self) -> None:
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut and not fut.done():
                        if "error" in msg:
                            fut.set_exception(RuntimeError(json.dumps(msg["error"])))
                        else:
                            fut.set_result(msg.get("result", {}))
                    continue
                sess = self.sessions.get(msg.get("sessionId"))
                if sess is None:
                    continue
                for handler in sess.handlers.get(msg.get("method", ""), []):
                    try:
                        handler(msg.get("params", {}))
                    except Exception as exc:
                        print("[raw-cdp] handler error:", exc, file=sys.stderr)
        except Exception:
            pass

    async def close(self) -> None:
        if self._reader:
            self._reader.cancel()
        if self.ws:
            await self.ws.close()
