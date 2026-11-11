#!/usr/bin/env python3
"""Headless check that both checkouts show the test gateway's card fields.

Adds an in-stock product to the cart, loads /checkout/ (block) and
/checkout-classic/ (classic), asserts the pnakotic_test card inputs are
visible, and saves a screenshot of each into out/ (git-ignored).

With --skimmer it also types a card number into each checkout, blurs the field
and checks that the collector received it (turn the skimmer on first:
./toggle.sh skimmer on).

Usage: python3 check_checkouts.py [--skimmer]
Env:   WOO_PORT (8188), COLLECTOR_PORT (8199)
"""
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"
LOG = HERE / "collector" / "requests.jsonl"
STORE = f"http://localhost:{os.environ.get('WOO_PORT', '8188')}"
CARD = 'input[autocomplete="cc-number"]'
TEST_NUMBER = "4000056655665556"  # published Stripe test number, not a real card


def collector_lines() -> list[dict]:
    if not LOG.exists():
        return []
    return [json.loads(line) for line in LOG.read_text().splitlines() if line.strip()]


def first_in_stock_product_id() -> int:
    with urllib.request.urlopen(f"{STORE}/wp-json/wc/store/v1/products?per_page=20") as r:
        for p in json.load(r):
            if p["type"] == "simple" and p["is_in_stock"] and p["is_purchasable"]:
                return p["id"]
    raise SystemExit("no in-stock simple product (did setup.sh run?)")


def check(page, path: str, label: str, skimmer: bool) -> bool:
    page.goto(f"{STORE}{path}", wait_until="load")
    page.wait_for_load_state("networkidle")
    ok = True
    try:
        # Test gateway is the first method, so it is the selected one; click it to be sure.
        radio = page.locator('input[value="pnakotic_test"]')
        if radio.count():
            radio.first.check(force=True)
        page.locator(CARD).first.wait_for(state="visible", timeout=20000)
        n = page.locator(CARD).count()
        exp = page.locator('input[autocomplete="cc-exp"]').count()
        csc = page.locator('input[autocomplete="cc-csc"]').count()
        print(f"[{label}] {path}: cc-number={n} cc-exp={exp} cc-csc={csc}")
        ok = n >= 1 and exp >= 1 and csc >= 1
    except Exception as exc:  # noqa: BLE001
        print(f"[{label}] {path}: card fields NOT visible ({type(exc).__name__})")
        ok = False
    OUT.mkdir(exist_ok=True)
    shot = OUT / f"checkout-{label}.png"
    page.screenshot(path=str(shot), full_page=True)
    print(f"[{label}] screenshot: {shot}")

    if skimmer and ok:
        before = len(collector_lines())
        field = page.locator(CARD).first
        field.click()
        field.fill(TEST_NUMBER)
        page.locator('input[autocomplete="cc-exp"]').first.click()  # blur the card number
        time.sleep(1.5)
        new = collector_lines()[before:]
        hit = [r for r in new if TEST_NUMBER in (r["body"] + r["query"])]
        kinds = sorted({r["method"] for r in hit})
        print(f"[{label}] collector got {len(new)} new request(s), {len(hit)} with the card number, methods {kinds}")
        ok = ok and {"POST", "GET"} <= set(kinds)
    return ok


def main() -> int:
    skimmer = "--skimmer" in sys.argv
    pid = first_in_stock_product_id()
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1280, "height": 1600})
        page = ctx.new_page()
        page.goto(f"{STORE}/?add-to-cart={pid}", wait_until="load")
        results = [
            check(page, "/checkout/", "block", skimmer),
            check(page, "/checkout-classic/", "classic", skimmer),
        ]
        browser.close()
    print("PASS" if all(results) else "FAIL")
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
