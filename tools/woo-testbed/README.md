# WooCommerce testbed

A local WordPress + WooCommerce store with a test card gateway, an opt-in test
skimmer and a collector server. It is for the checkout-check spike and phase 2's
live test. Throwaway-grade: weak passwords, no TLS, everything bound to `127.0.0.1`.

| Piece | Version / value |
|-------|-----------------|
| WordPress | `wordpress:7.1.4-php8.3-apache` (PHP 8.3) |
| WooCommerce | 11.2.2 (pinned in `setup.sh`, downloaded from wordpress.org at setup) |
| Database | `mariadb:11.4` |
| wp-cli | `wordpress:cli-2.12.0-php8.3` |
| Collector | `python:3.12-slim-bookworm`, standard library only |
| Store | `http://localhost:8188` (`WOO_PORT`) |
| Collector | `http://127.0.0.1:8199` (`COLLECTOR_PORT`) |
| Admin | `http://localhost:8188/wp-admin/`, user `admin`, password `mandacaru-testbed` (`WOO_ADMIN_PASSWORD`, first setup only) |

The compose project is named `mandacaru-woo-testbed`; it never touches other
containers, networks or volumes. Ports are 8188/8199 because 8088 belongs to
another stack on the dev machine.

## Start

```bash
cd tools/woo-testbed
./setup.sh          # starts the stack, then configures it; safe to run again
```

Renamed from `pnakotic-woo-testbed`: run `docker compose -p pnakotic-woo-testbed down -v` once to drop the old project, then `./setup.sh`.

First run takes a few minutes (image pulls, WooCommerce download). A re-run
takes about a minute and changes nothing: products are looked up by SKU, pages by
slug, the shipping method by id. Check with:

```bash
curl -s localhost:8188/wp-json/wc/store/v1/products | python3 -m json.tool | head
python3 check_checkouts.py            # both checkouts show the card fields (screenshots in out/)
python3 check_checkouts.py --skimmer  # same, and expects the collector to receive the typed card number
```

## What is in the store

- Products: `PNK-DOLLAR` Test Dollar Item (1.00), `PNK-WIDGET` (12.50), `PNK-GADGET` (24.00), all simple and in stock; `PNK-SOLDOUT` (simple, out of stock; note the Store API still reports `is_purchasable: true` for it, so filter on `is_in_stock`); `PNK-TEE` (variable, sizes S and M, 15.00).
- Pages: `/checkout/` has the block checkout (WooCommerce's default), `/checkout-classic/` has `[woocommerce_checkout]`.
- Shipping: a flat rate of 5.00 for every address. Currency USD, store address in California.
- Payment methods: only `mandacaru_test` is enabled, so order counts can only come from the always-failing gateway. It renders native `cc-number`, `cc-exp` and `cc-csc` inputs in the store's own page in both checkouts and always fails server-side (`process_payment` returns `failure`). A failed payment can still leave an order behind: a `pending` order in the classic checkout, a `checkout-draft` order in the block checkout. `./toggle.sh gateways extra on` enables Direct bank transfer and Cash on delivery as a positive control (they succeed and create real orders); `setup.sh` switches them off again.
- No outside requests while running: `WP_HTTP_BLOCK_EXTERNAL` is on in the store container (not in wpcli, which needs it for setup), WP-Cron and updates are off, mail is short-circuited, and WooCommerce's marketplace suggestions, tracking, onboarding and WC Admin are switched off (`mu-plugins/mandacaru-offline.php`).

## Toggles

```bash
./toggle.sh checkout classic    # the store's checkout page (woocommerce_checkout_page_id) becomes /checkout-classic/
./toggle.sh checkout block      # back to /checkout/
./toggle.sh gateways extra on|off # cod + bacs, default off (positive control that creates real orders)
./toggle.sh skimmer on          # option mandacaru_test_skimmer = 1
./toggle.sh skimmer off
```

Both pages stay reachable at their own URL whichever one is the "checkout page";
the toggle changes what WooCommerce links to (cart's Proceed to checkout, redirects).

## The test skimmer

`mu-plugins/test-skimmer.php`, adapted from
`woo-checkout-scanner/test-fixtures/test-skimmer.functions.php`. With the option
on, on the checkout (classic or block) it reads the card number field and, on
that field's blur and on a Place Order click, sends it once as a `fetch` POST
(`no-cors`, `text/plain`) and once as an image beacon (`GET /collect?t=<trigger>&c=<value>`)
to `http://127.0.0.1:8199/collect` (`MANDACARU_COLLECTOR_URL` in `docker-compose.yml`,
or the option `mandacaru_test_skimmer_url`). The store is at `localhost` and the collector at `127.0.0.1`: a different host string and origin, so it looks like third-party exfiltration (`registrable_domain('localhost')` is empty, so two `localhost` ports would not count as another site). From inside
a container, `localhost` is not the host: if a Mandacaru worker is to scan the store,
set the option to a name that both can reach.

## The collector

`collector/server.py` appends one JSON line per request (`ts`, `method`, `path`,
`query`, `body`, `origin`, `content_type`) to `collector/requests.jsonl`
(git-ignored) and answers 204 to anything.

Limits: a body over 1 MB gets 413, a bad or negative `Content-Length` 400, a chunked
body 411 (all closing the connection and not logged), slow clients are dropped after
10 s, and CORS headers go only to the store's own origins. `requests.jsonl` stops
growing at 50 MB (`COLLECTOR_MAX_LOG_BYTES`): later requests are still answered but
not written, and counted as `skipped_log_full`. `curl http://127.0.0.1:8199/__stats`
shows `logged`, `skipped_log_full`, `rejected` and the log size, so check it if a
spike run seems to be missing requests.

```bash
tail -f collector/requests.jsonl
: > collector/requests.jsonl        # clear it
```

## Orders and wp-cli

```bash
W="docker compose -p mandacaru-woo-testbed run --rm wpcli"   # entrypoint is `wp`
$W wc shop_order list --status=any --fields=id,status --user=admin
$W wc product list --user=admin --fields=id,sku,type,stock_status,price
$W option get woocommerce_checkout_page_id
```

The block checkout keeps its draft order in the status `checkout-draft`. Whether
`--status=any` lists drafts is not verified here (no draft existed when this was
written); query `--status=checkout-draft` as well when counting. This is one of the
spike's questions (spec section 8, question 4).

## Stop and reset

```bash
docker compose -p mandacaru-woo-testbed down        # stop, keep the data
docker compose -p mandacaru-woo-testbed down -v     # stop and delete this project's volumes (then ./setup.sh again)
```

Only ever run these with the `-p mandacaru-woo-testbed` project; other stacks on the
machine are not ours.
