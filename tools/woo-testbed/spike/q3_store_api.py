#!/usr/bin/env python3
"""Q3: which Store API product query returns an in-stock, purchasable, simple product, cheapest first?

Plain unauthenticated GETs, no cookies (what the checkout check would send before it touches
the cart). Lists the arguments the route itself declares, then tries candidate queries and
prints what each returns, in order.
"""
import json
import urllib.error
import urllib.request

from spike_common import STORE, Out

out = Out("q3_store_api")
BASE = "/wp-json/wc/store/v1/products"


def get(path: str, method: str = "GET"):
    req = urllib.request.Request(STORE + path, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), json.loads(e.read() or b"null")


def row(p) -> str:
    return "{id} {sku:<12} {type:<9} price={price:<5} in_stock={st!s:<5} purchasable={pu!s:<5} add_to_cart.url={url}".format(
        id=p["id"], sku=p.get("sku", ""), type=p["type"], price=p["prices"]["price"], st=p["is_in_stock"],
        pu=p["is_purchasable"], url=(p.get("add_to_cart") or {}).get("url", "").replace(STORE, ""))


def main() -> None:
    # Discovery: the REST root a page advertises (Link header), and the store namespace.
    req = urllib.request.Request(STORE + "/", method="HEAD")
    with urllib.request.urlopen(req) as r:
        out("homepage Link header:", r.headers.get("Link", ""))
    status, _, ns = get("/wp-json/wc/store/v1")
    out("GET /wp-json/wc/store/v1 ->", status, "routes:", len(ns.get("routes", {})))

    status, _, opts = get(BASE, method="OPTIONS")
    args = opts["endpoints"][0]["args"]
    out("OPTIONS {} -> {}; declared args:".format(BASE, status))
    for name in ("type", "stock_status", "orderby", "order", "per_page", "on_sale", "min_price", "catalog_visibility"):
        a = args.get(name, {})
        enum = a.get("enum") or (a.get("items") or {}).get("enum")
        out("  {:<18} type={} default={!r} enum={}".format(name, a.get("type"), a.get("default"), enum))
    out("  (no 'purchasable' argument declared: {})".format("purchasable" not in args))

    candidates = [
        BASE,
        BASE + "?orderby=price&order=asc",
        BASE + "?type=simple&orderby=price&order=asc",
        BASE + "?type=simple&stock_status=instock&orderby=price&order=asc&per_page=20",
        BASE + "?type=simple&stock_status[]=instock&orderby=price&order=asc&per_page=20",
        BASE + "?type=simple&stock_status=instock&orderby=price&order=asc&per_page=1",
    ]
    for path in candidates:
        status, headers, items = get(path)
        out("\nGET {} -> {} (X-WP-Total={})".format(path, status, headers.get("X-WP-Total")))
        if not isinstance(items, list):
            out("  ", items)
            continue
        for p in items:
            out("  " + row(p))

    status, _, items = get(BASE + "?type=simple&stock_status=instock&orderby=price&order=asc&per_page=20")
    picked = [p for p in items if p["type"] == "simple" and p["is_in_stock"] and p["is_purchasable"]]
    out("\nchosen (first of the winning query after the client-side filter):", row(picked[0]))
    ids = [p["id"] for p in items]
    out("sold-out (14) excluded: {}; variable (15) excluded: {}".format(14 not in ids, 15 not in ids))

    status, _, sold = get(BASE + "/14")
    out("\nGET {}/14 (sold out) -> {}: is_purchasable={} is_in_stock={} stock_availability={}".format(
        BASE, status, sold.get("is_purchasable"), sold.get("is_in_stock"), sold.get("stock_availability")))


if __name__ == "__main__":
    main()
