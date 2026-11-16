# Checkout spike: findings

Date: 2026-11-10. Answers the five questions of the checkout-skimmer design's section 8
(`docs/superpowers/specs/2026-11-10-checkout-skimmer-check-design.md`, git-ignored), plus the
skimmer path and a card-field watch on real WooCommerce code.

**Setup.** Local testbed `tools/woo-testbed` (compose project `pnakotic-woo-testbed`):
WordPress 7.1.4, WooCommerce 11.2.2, HPOS off (orders are `wp_posts` rows). The store is at
`localhost:8188` and the collector at `127.0.0.1:8199`. Only the `pnakotic_test` gateway is
enabled; it puts native card inputs in the page and always declines.

**Scripts.** Scripts are in `tools/woo-testbed/spike/` and use plain async Playwright 1.60 plus
raw CDP, with the engine's `CHROMIUM_ARGS` and no proxy. Raw output goes to `spike/out/<script>.log`
(git-ignored). The browser is Playwright's default for `headless=True`, chrome-headless-shell
148.0.7778.96, unless a section says otherwise. Test card: `4000056655665556`, Stripe's published
Visa debit number.

## Q1. What `/checkout/` does with an empty cart

**Answer.** It depends on which page is the store's checkout page (`woocommerce_checkout_page_id`),
not on block versus classic:

- **The store's checkout page** answers `302` to `/cart/`. The cart says "Your cart is currently
  empty!" This holds for both kinds.
- **A block checkout page that isn't the store's checkout page** renders in place (`200`) with
  "Checkout is not available whilst your cart is empty".
- **A classic `[woocommerce_checkout]` page that isn't the store's checkout page** renders in place
  (`200`) with an empty body: no form and no message.

No card inputs appear in any of these cases.

**Observed with** `q1_empty_cart.py`: both pages under both toggle settings, each in a cookie-less
context.

```
== store checkout page = block (woocommerce_checkout_page_id=7) ==
  /checkout/           chain: 302 /checkout/ -> /cart/ | 200 /cart/
  /checkout-classic/   chain: 200 /checkout-classic/     dom: classic_form False, card_inputs 0, text: header/footer only
== store checkout page = classic (woocommerce_checkout_page_id=10) ==
  /checkout/           chain: 200 /checkout/   text: "... Your cart is currently empty! Checkout is not available whilst your cart is empty..."
  /checkout-classic/   chain: 302 /checkout-classic/ -> /cart/ | 200 /cart/
```

## Q2. Does `/?add-to-cart=<id>` fill the cart the block checkout reads?

**Answer.** Yes. A page load of `/?add-to-cart=11` and a page-less
`context.request.get('/?add-to-cart=11')` both fill the session cart. After either one, the Store
API cart shows the item. Both checkouts then render with the cart: no redirect, the card inputs
present, and the block summary showing `$6.00`.

- **The response.** The add-to-cart URL answers `200` on the homepage. It does not redirect.
- **Notices.** The page that loads shows no notice. The "has been added to your cart" notice appears
  later, on the block checkout (it is in every block run's notices in Q4, and in none of the classic
  runs').
- **Products that can't be added.** The sold-out product (14) and the variable product (15) add
  nothing and show no notice. So the cart must be checked through the Store API after the add.
- **Loading the URL twice** adds a second unit.

**Observed with** `q2_add_to_cart.py`.

```
(a) navigation: 200 /?add-to-cart=11  final: /?add-to-cart=11   notice: ''
    cookies set: sbjs_* (order attribution), woocommerce_cart_hash, woocommerce_items_in_cart, wp_woocommerce_session_<hash>
    Store API cart (same context): [[[11, "Test Dollar Item", 1]], "600"]
    /checkout/          200 -> final /checkout/          {'summary': 'Order summary$6.00 ...', 'card_inputs': 1}
    /checkout-classic/  200 -> final /checkout-classic/  {'summary': '... Test Dollar Item × 1 $1.00 ... Total $6.00', 'card_inputs': 1}
(b) APIRequestContext: status 200, cart [[11, "Test Dollar Item", 1]]; /checkout/ renders with card_inputs 1
(c) loaded twice: cart [[11, "Test Dollar Item", 2]]
(d) 14 (sold out) and 15 (variable): notice '', cart []
```

## Q3. Which Store API query returns an in-stock, purchasable, simple product, cheapest first?

**Answer.** Use this query, with no cookies and no authentication:

```
GET /wp-json/wc/store/v1/products?type=simple&stock_status=instock&orderby=price&order=asc&per_page=20
```

Then keep only items with `type == "simple" && is_in_stock && is_purchasable`.

- **What it returns.** Product 11 (1.00) first, then 12 and 13. The sold-out simple and the
  variable product are left out.
- **What the route accepts.** Its own `OPTIONS` lists `type`, `stock_status` (an array; a plain
  value works too), `orderby=price` and `order`. It has no `purchasable` argument.
- **`is_purchasable` misleads.** It is `true` for the sold-out product, so filter on `is_in_stock`.
- **Prices** are in minor units (`prices.price`).
- **Don't use the API's `add_to_cart.url`.** It is the API request's own URL plus `&add-to-cart=`,
  HTML-escaped (`&#038;`). Build `/?add-to-cart=<id>` instead.
- **Discovery.** The homepage advertises the REST root in a `Link: <…/wp-json/>; rel="https://api.w.org/"`
  header.

**Observed with** `q3_store_api.py`.

```
OPTIONS /wp-json/wc/store/v1/products -> 200; declared args:
  type  enum=['simple','grouped','external','variable','variation'] | stock_status type=array enum=['instock','outofstock','onbackorder']
  orderby enum=[... 'price' ...] | order enum=['asc','desc'] | (no 'purchasable' argument declared: True)
GET ...?type=simple&stock_status=instock&orderby=price&order=asc&per_page=20 -> 200 (X-WP-Total=3)
  11 PNK-DOLLAR simple price=100 | 12 PNK-WIDGET simple price=1250 | 13 PNK-GADGET simple price=2400
GET /wp-json/wc/store/v1/products/14 (sold out) -> 200: is_purchasable=True is_in_stock=False
```

## Q4. Which requests create an order, when is the draft made, how long is stock held, and does the guard hold?

**Answer.** In WooCommerce 11.2.2, only the Place Order request creates an order, in both checkouts.

**What the requests do.**

- **Block checkout.** Opening and filling the checkout creates no order. The requests before the
  click are `POST /wp-json/wc/store/v1/batch` (cart and customer updates). Choosing another payment
  method also sends `POST /wp-json/wc/store/v1/checkout?__experimental_calc_totals=true`. That one
  is a `PUT` that `wp.apiFetch` sends as `POST` with `X-HTTP-Method-Override`; see
  `wc-blocks-data.js` (`method:"PUT"`) and `api-fetch` (`X-HTTP-Method-Override`).

  **Observed:** the order appears only after the click's `POST /wp-json/wc/store/v1/checkout`.
  When the gateway declines, the order is left **`pending`**, not `checkout-draft` and not
  `failed`. The stock-hold table was empty right afterwards. No `checkout-draft` row was visible
  at any snapshot.

  **Read from the source, not observed** (`src/StoreApi/Routes/V1/Checkout.php`): inside that one
  POST, WooCommerce creates the `checkout-draft`, reserves stock, tries the payment, and releases
  the hold when it fails. The file says: "As of WooCommerce 10.8.0 the Store API defers draft order
  creation to place-order time … rather than on the first PATCH". That one comment is the only
  evidence about older versions: before 10.8.0 a draft was apparently created when the checkout
  was opened or filled (version-dependent, not tested here). Only 11.2.2 was tested.

  **Fresh session only.** The same file (`get_route_response` and `get_route_update_response`,
  around lines 227-231 and 409) reuses a `pending` or `failed` order already in the customer's
  session: the GET and the PUT then update that order. So "opening and filling creates no order"
  holds for a fresh session, which is what every spike run used. Since 9.2, "Stock is no longer held for all draft orders, nor on
  non-POST requests".
- **Classic checkout.** Load sends `POST /?wc-ajax=update_order_review`. The click sends
  `POST /?wc-ajax=checkout`, which creates the order. A declined payment leaves it `pending`,
  holding stock for `woocommerce_hold_stock_minutes` (60): `expires` = created + 60 min. The hold
  only exists for managed-stock products. That request's body includes the typed card fields,
  because the gateway's inputs are form fields.
- **The draft status.** No `checkout-draft` order ever existed. So whether wp-cli's `--status=any`
  lists drafts is still unverified. `--status=checkout-draft` was queried separately in every run
  and was always `[]`.

**The guard.** The guard is CDP `Fetch` at the Request stage on the page's session, armed after
the form settled. It fails every non-GET request with `BlockedByClient` and lets GETs through.

- **Order requests.** In all 10 runs (5 per checkout), the guard failed the order request:
  `POST /wp-json/wc/store/v1/checkout` on block, `POST /?wc-ajax=checkout` on classic.
- **Orders.** No order of any status was created, and no existing order changed. The
  `wp_posts` snapshots after fill, after the click plus 5 s, and after the context closed were
  identical. wp-cli counts were the same before and after every run.
- **Stock.** No new stock hold appeared.
- **What the page showed.** Block: "Something went wrong when placing the order. Check your email
  for order updates before retrying." Classic: "There was an error processing your order. Please
  check for any charges in your payment method …".
- **Positive control.** The guard-off runs show the click path really orders. Cash on delivery made
  a `processing` order on each checkout and led to `/checkout/order-received/<id>/`.
  `pnakotic_test` made a `pending` order with the decline message.

**Observed with** `q4_order_guard.py`. Product 11 had managed stock (100) for the run and was
restored afterwards. Order snapshots come from `wp_posts`; counts come from wp-cli.

```
[block] observe (guard off, pnakotic_test)
    orders after checkout load: no change | after fill: no change | after click +5s: #19 wc-pending
      -- fill --   2.83s POST /wp-json/wc/store/v1/batch?_locale=site -> HTTP 207 (x2)
      -- click --  6.35s POST /wp-json/wc/store/v1/checkout?_locale=site -> HTTP 400
    notices ['… The test card was declined (testbed gateway always fails).']   reserved stock now: []
[block] control (cod): after click +5s: #20 wc-processing; final URL /checkout/order-received/20/?key=…
[classic] observe: load 0.38s POST /?wc-ajax=update_order_review; click 6.33s POST /?wc-ajax=checkout -> HTTP 200 [body has the test card]
    after click +5s: #21 wc-pending   reserved stock now: [["21","11","1","2026-11-11 02:41:14","2026-11-11 03:41:14"]]
[classic] control (cod): #22 wc-processing; final URL /checkout/order-received/22/…

summary of the guard runs
  checkout run  order-request-failed-by-guard  orders: after fill -> after close   guard failed
  block    1-5  1                              no change                      ['POST /wp-json/wc/store/v1/checkout?_locale=site']
  classic  1-5  1                              no change                      ['POST /?wc-ajax=checkout']
  (every run) before == after: wp-cli --status=any: [(20,'processing'),(19,'pending')…] | --status=checkout-draft: []
```

**Block versus classic.** On block, the draft exists only inside the place-order POST, and a
declined payment ends `pending` with stock released. On classic, a declined payment ends `pending`
with stock held for 60 min. With the guard on, both create nothing.

## Q5. Does CDP Fetch on the page session reach a cross-site iframe and workers?

**Answer.** It depends on the build. The builds were tested on macOS (Google Chrome 157, Chromium
148), not inside the Linux Docker image; the Linux builds are expected to behave the same but were
not run.

- **In the builds Pnakotic ships, no.** That is Google Chrome stable (`BROWSER_CHANNEL=chrome`,
  amd64 image) and full Chromium (`chromium`, arm64 image). In both, the 127.0.0.1 iframe on the
  localhost store runs out of process (an `iframe` target exists). Page-session Fetch (mode A)
  misses everything that iframe sends, including its form submit and its dedicated worker, and it
  misses the SharedWorker. It catches the main frame and a `blob:` dedicated worker the main frame
  started.
- **Locally, it looks like yes.** In chrome-headless-shell (Playwright's local default) the iframe
  stays in process, so page-session Fetch catches it. Only the SharedWorker leaks. A spike run in
  the default local browser would therefore have given the wrong answer.

**What closes every gap (mode B).** Auto-attach on a raw CDP connection:

- On the page session: `Target.setAutoAttach {autoAttach: true, waitForDebuggerOnStart: true, flatten: true}`,
  plus `Fetch.enable` on every attached iframe target (recursively).
- At the browser level: `Target.setAutoAttach` with `filter: [{type: "shared_worker"}]`, plus
  `Fetch.enable` on the shared worker.
- Then `Runtime.runIfWaitingForDebugger`.

This blocked all 12 POST senders in all three builds, start-up requests included.

**Points that shape the design.**

1. **Dedicated workers have no Fetch domain.** `Fetch.enable` on a `worker` target fails with
   `'Fetch.enable' wasn't found`. Their requests are intercepted on the owning frame's session.
   So "Fetch confirmed on every target" can't be the fail-closed test; it has to be "on every page,
   iframe and shared_worker target".
2. **`waitForDebuggerOnStart` is required (mode B0).** Without it, the iframe's start-up POST
   leaked. Even its later `fetch` and `sendBeacon` leaked, in all three logged runs on both full
   builds.
3. **What was tried through Playwright's own API fell short.**
   - Its `CDPSession` accepts `Target.setAutoAttach` and delivers `attachedToTarget` events, but
     `send(method, params)` takes no `sessionId`, so the script had no way to send a flattened
     child `Fetch.enable` (mode P; an API reading, not a measured leak).
   - `context.new_cdp_session(frame)` works for an out-of-process iframe (mode C), but only once
     the frame exists. Its start-up POST leaked in every logged full-build run. Its dedicated
     worker's start-up POST leaked in 5 of 6 logged full-build runs (it is a race).
   - It has no handle on SharedWorkers.

   Mode B used a second CDP connection (`--remote-debugging-port` and a WebSocket). Not tried:
   `context.route()` (Playwright then auto-attaches to out-of-process iframes itself) and
   non-flattened auto-attach through `Target.sendMessageToTarget`. Neither would cover
   SharedWorkers.

**Observed with** `q5_fetch_reach.py`. A third-origin server on 127.0.0.1 is started by the script;
its own request log is the ground truth ("LEAKED" = the server received the POST). Each mode runs in
a fresh browser. Builds: chrome-headless-shell 148.0.7778.96, Chromium 148.0.7778.96, Google
Chrome 157.0.8103.50.

Logs on disk, three runs: `out/q5_fetch_reach-run0-superseded.log` (the second run before this
fix), and `-run1.log` and `-run2.log` (two runs in parallel, after it). The very first run's log
was overwritten and is lost; nothing below rests on it. The three logs agree except for the
mode C race noted above.

```
targets (chromium, mode A): ["iframe:http://127.0.0.1:…/frame.html", "shared_worker:…/shared.js", "worker:blob:http://localhost:8188/…", "worker:…/worker.js"]
mode C (headless shell): new_cdp_session(frame) failed: … This frame does not have a separate CDP session, it is a part of the parent frame's session

== summary, channel 'chrome' (157.0.8103.50), run0-superseded ==     A=page session  C=+frame session  B=auto-attach  B0=auto-attach, no wait
  main-fetch / main-beacon / main-blob-worker[-startup]   blocked    blocked    blocked    blocked
  iframe-startup             LEAKED     LEAKED     blocked    LEAKED
  iframe-fetch               LEAKED     blocked    blocked    LEAKED
  iframe-beacon              LEAKED     blocked    blocked    LEAKED
  iframe-form                LEAKED     blocked    blocked    blocked
  iframe-worker-startup      LEAKED     blocked*   blocked    blocked     (* LEAKED in the other five logged full-build runs)
  iframe-worker              LEAKED     blocked    blocked    blocked
  shared-startup / shared-worker   LEAKED  LEAKED  blocked    blocked
'chrome' in run1 and run2, and 'chromium' (148) in all three: identical, with iframe-worker-startup LEAKED under C.
default headless shell (148), all three: every row blocked under A, C, B and B0 except shared-* LEAKED under A and C.
mode P: Target.setAutoAttach flatten on a Playwright CDPSession: ok; attachedToTarget events delivered: [["worker",…],["iframe",…],["worker",…]]; no way to send to them.
```

## Skimmer path (brief step 2)

**Answer.** On both checkouts, the testbed skimmer sent the typed number to the collector on blur,
before the click: a GET beacon and a POST, both with the number. With the guard armed at the click:

- **The skimmer's POST** was failed. Its body is in the guard's record:
  `{"trigger":"click","card":"4000056655665556",…}`.
- **The order request** was failed too.
- **The skimmer's GET beacon** (`/collect?t=click&c=4000056655665556`) passed the guard, as
  designed, and reached the collector 0.02 s after the click.
- **Orders:** none were created.

**Where the skimmer renders.** The skimmer renders only where `is_checkout()` is true. After
`toggle.sh checkout classic`, `/checkout/` (the block page, no longer the store's checkout) has no
skimmer and sends nothing. `/checkout-classic/` fires.

**Observed with** `skimmer_path.py`.

```
== block checkout /checkout/ ==
  collector before the click (blur):  GET /collect t=blur&c=4000056655665556 | POST /collect {"trigger":"blur","card":"4000056655665556",…}
  collector after the click:          GET /collect (+0.02s vs click) t=click&c=4000056655665556
  guard: FAILED POST http://127.0.0.1:8199/collect body={"trigger":"click","card":"4000056655665556",…}
         passed GET  http://127.0.0.1:8199/collect?t=click&c=4000056655665556 card-in-url
         FAILED POST http://localhost:8188/wp-json/wc/store/v1/checkout?_locale=site
== classic: the same, with FAILED POST http://localhost:8188/?wc-ajax=checkout
== store checkout page switched to classic:
  /checkout/          skimmer script: False  collector hits with the card on blur: 0
  /checkout-classic/  skimmer script: True   collector hits with the card on blur: 2
```

## Card-field watch on real WooCommerce checkouts

**Answer.** No false alarm on these two checkouts. The gateway's own card fields read as the
**store's**: `owner=store`, `verified=True`, `unverifiable=None`. Every judged frame was a script
file (react-dom on block; jQuery and `checkout.min.js` on classic). No frame ran at the page URL,
so the inline-block trust rule was never exercised, and it has a gap (below).

- **Block.** One `appendChild` insertion, all of whose kept frames are
  `/wp-includes/js/dist/vendor/react-dom.min.js`. The stack is `cut` (React's stack is over 30
  frames), but the kept frames decide it. The served HTML has no card input, so this insertion is
  what makes the fields known.
- **Classic.** One `replaceChild` insertion: jQuery plus WooCommerce's `checkout.min.js`, which is
  the order-review refresh replacing the payment box. The inputs are also in the served HTML.
- **Count.** `present=3` on both (`cc-number`, `cc-exp`, `cc-csc`).

**With the skimmer on,** the result is the same: one store insertion. The test card was typed and
blurred, and the skimmer read and sent it. The watcher saw nothing of it, because the skimmer reads
values and inserts nothing. Catching it needs §4.6's exfiltration and read-by signals.

The skimmer's inline script contains the string `autocomplete="cc-number"` in a selector.
`html_has_card_input` correctly does not count that as a card input in the served HTML.

**Caveat.** On the testbed, every WordPress file is served from `localhost`, so it matches
`site_host` directly. On a real store, those files come from the site's own domain or from
`c0.wp.com`, which is `STORE_CDN_HOSTS`. The block result depends on `react-dom` being judged as
the store's.

**Inline-block gap ("parse record: 1 hashes at the page URL"), fixed in 0fa9372.** The classic
checkout serves 11 inline `<script>` blocks, and the parse record had one. The cause was not the
spike's wiring:

- 3 blocks aren't JavaScript (`importmap`, `speculationrules`, `application/json`).
- 7 carry a `//# sourceURL=` comment, which WordPress adds to the inline scripts it prints
  (`wc-checkout-js-extra` and the like). Chromium reports such a block's `Debugger.scriptParsed`
  with `url` set to the sourceURL name and `embedderName` set to the page URL. At the time,
  `EvalCapture._note_position` keyed by `url` and kept only `http(s)` URLs, so these blocks never
  entered `positions_at(page_url)`.
- Only 1 plain block was left, and it was recorded.

The card hook writes frames with `CallSite.getFileName()`, which is the page URL for these blocks.
So a card input inserted by code in such a block read `owner=unknown` with `verified=True`: a
Suspicious finding against the store's own code (a false alarm, not a miss).

Commit 0fa9372 closed it. `EvalCapture` now records a page-world script's start under its
`embedderName`, the same name its frames carry, so a served block ending in a sourceURL comment
is recorded at the page and its hash is trusted when every script with it started at a served
block. Runtime code that names itself with a sourceURL has no embedder; it is counted at every
document, so an `eval` of a served block's exact text still makes that hash untrusted.
`tests/test_site_load.py` covers it in a browser. `spike/engine_gap_sourceurl.py` is now a
regression check: the same insertion reads `store` with and without the comment (re-run
2026-11-11, both `owner: store verified: True`). The observation below predates the fix.

**Observed with** `card_watch_observe.py`. What was wired, and what wasn't:

- `CardWatcher.attach(ctx)` runs before `new_page`.
- `EvalCapture` is attached on the page's CDP session before `goto`. Its warm-up is one trivial
  `evaluate`; the engine's also runs `NEUTRAL_POINT_JS` and a behavior-binding round trip.
- Not attached: `behavior`, `ScriptTracer` and `EgressGuard`.
- The served body and charset are read with the engine's `_served_body` and `_document_charset`.
- `summarize` is called with `site_host="localhost"`, the checkout URL and
  `parsed=positions_at(url)`.
- The cart is filled through `context.request`, so the watcher sees only the checkout.

The gap above reproduces with the same minimal wiring and follows from `_note_position`'s URL
filter, so the missing pieces don't explain it.

```
== block checkout /checkout/ , skimmer OFF ==
  served: /checkout/ (196018 bytes, status 200), charset UTF-8, parse record: 1 hashes at the page URL, eval stages: 13
  present=3 dropped=0 unverifiable=None insertions=1
  #1 via=appendChild owner=store verified=True vendors=[] cut=True first_unknown=''   frames: react-dom.min.js ×10
  card inputs in the served HTML (card_watch.html_has_card_input): False
== classic checkout /checkout-classic/ , skimmer OFF ==
  present=3 dropped=0 unverifiable=None insertions=1
  #1 via=replaceChild owner=store verified=True vendors=[] cut=False first_unknown=''  frames: jquery.min.js, checkout.min.js?ver=11.2.2, …
  card inputs in the served HTML (card_watch.html_has_card_input): True
== skimmer ON, test card typed and blurred: block and classic identical to the above (watcher events seen: 1 each)
```

## Store state after the spike

- **Orders.** The guard-off runs made four orders: #19 (block, pending), #20 (block, cod,
  processing), #21 (classic, pending) and #22 (classic, cod, processing). All four were deleted
  (`cleanup.py`, `wp post delete --force`). Deleting #21 left its stock hold behind in
  `wp_wc_reserved_stock`; `cleanup.py` removed it.
- **Carts.** 45 carts from the runs stay in `wp_woocommerce_sessions` until they expire.
- **Settings.** The skimmer is off (`0`), cod and bacs are off, and the checkout page is the block
  page (id 7). Product 11 is back to unmanaged stock (`_stock` NULL). The two cod orders had raised
  its `total_sales` to 2; it was reset to 0 in the post meta and in `wp_wc_product_meta_lookup`.
- **Testbed.** Still running.

## What this changes in the design

Each item quotes the spec as written, then proposes a replacement.

1. **The draft that the anti-goal accepts doesn't exist.**

   > §2 (Anti-goals): "The block checkout's own `checkout-draft` order is accepted (the user's
   > decision): WooCommerce creates it whenever anyone opens the checkout with a cart, hides it from
   > the orders list, deletes it on its own, and holds stock for it only for a few minutes."

   In 11.2.2, opening and filling the checkout in a fresh session creates no draft (Q4). The draft
   exists only inside the place-order POST, which the guard fails. Stock is held only from that
   POST, for `woocommerce_hold_stock_minutes` (60 by default). A source comment says the deferral
   started in 10.8.0; what older versions do on opening or filling the checkout is
   version-dependent and was not tested here.

   Replacement: "No order may be created on someone's store beyond what WooCommerce itself makes
   before the click.
   - WooCommerce 10.8.0 and later (block and classic): the order is created only by the Place Order
     request, which the guard fails, so a guarded check leaves no order and no stock hold.
   - Older versions: a `checkout-draft` may be created by opening or filling the checkout
     (version-dependent, not tested here). It is accepted as before, and the guard must keep it
     in `checkout-draft`."

   The check can't count orders on someone else's store. So the guard's rule stays "fail the order
   request". The version split only changes what the report and the live test may expect.

   The user's decision in §9.7 ("The block checkout's automatic `checkout-draft` order is
   acceptable; no other order may be created") still holds for older stores. **For the user to
   confirm:** on 10.8.0 and later, expect no order at all.

2. **What the guard must prevent.**

   > §4.5: "Before the guard is armed, POST requests are allowed: WooCommerce posts to update the
   > order review, and the block checkout posts the customer details and keeps its draft order up to
   > date. … What the guard must prevent is the draft (or any order) moving past `checkout-draft`, or
   > a new non-draft order appearing."

   Replacement: "Before the guard is armed, the block checkout posts cart and customer updates
   (`/wc/store/v1/batch`), and a `PUT` to `/wc/store/v1/checkout?__experimental_calc_totals=true`
   (sent as POST with `X-HTTP-Method-Override`) when the payment method changes. The classic
   checkout posts `?wc-ajax=update_order_review`. In a fresh session none of these creates an
   order on 11.2.2 (with a `pending` or `failed` order already in the session, the PUT and the GET
   update that order). The guard must
   prevent any new order row, of any status, and any change to an existing one. The order requests
   it must fail are `POST /wc/store/v1/checkout` (block) and `POST /?wc-ajax=checkout` (classic).
   The check confirms it failed one of them; a click that sent neither is reported as 'Place Order
   didn't submit'."

   §6's live check changes to match:

   > §6: "After every run, WooCommerce has no new order outside `checkout-draft` status, and no draft
   > has moved on to pending, failed or any other status."

   Replacement, for a testbed on WooCommerce 10.8.0 or later: "After every run, WooCommerce has no
   new order of any status (query `--status=checkout-draft` separately), and no existing order
   changed." On an older testbed the current wording stays.

3. **Fetch on the page session doesn't cover cross-site iframes.**

   > §1: Pnakotic "sees every request with its body from the browser side, through CDP `Fetch`
   > interception (`EgressGuard` in `engine.py`)."

   > §3 (table): "CDP `Fetch` interception of every request, before it leaves the browser |
   > `EgressGuard`, `engine.py` | Reading request bodies (§4.6) and the order guard (§4.5)"

   In the shipped builds (Chrome stable, full Chromium), page-session Fetch misses out-of-process
   iframes, their dedicated workers and SharedWorkers (Q5). That matters for §4.6's "test card
   leaves for another website" signal as much as for the guard.

   **The SSRF guarantee survives.** It rests on the launch-level SOCKS proxy (`egress_proxy.py`),
   which every connection from every frame and worker goes through. Q5 ran without the proxy, so
   this holds by design and was not exercised. What is lost in those frames:
   - `EgressGuard`'s per-URL `ERR_BLOCKED_BY_CLIENT` and its blocked-host record (the proxy
     refuses the connection instead, and its own blocks are still merged into `blocked_hosts`);
   - §4.6's reading of request bodies.

   `EgressGuard`'s docstring and CLAUDE.md claimed page-session Fetch paused "iframe and worker
   requests"; both are corrected in this fix.

   Replacement: "CDP `Fetch` on the page session covers the main frame and the dedicated workers it
   starts. Cross-site iframes (out of process in Chrome and Chromium), their workers and
   SharedWorkers need more. What worked in the spike is auto-attach:
   - `Target.setAutoAttach {flatten, waitForDebuggerOnStart}` on the page and every iframe target;
   - browser-level auto-attach for `shared_worker`;
   - `Fetch.enable` on each page, iframe and shared-worker target before
     `Runtime.runIfWaitingForDebugger`.
   Request bodies for §4.6 are read through the same sessions from page load on, not only after
   arming."

   **The browser is shared.** A site survey runs up to 6 contexts in one browser, and
   browser-level auto-attach reports every context's targets. Only one context was tested. The
   proposal: scope by `targetInfo.browserContextId`. Arm Fetch only on targets whose
   `browserContextId` is the checkout context's. Resume every other target untouched
   (`Runtime.runIfWaitingForDebugger`, then detach), so the other loads see no difference beyond a
   brief start-up pause. Page-level auto-attach is already scoped to that page.

4. **SharedWorkers are visible to CDP.**

   > §4.5: "SharedWorkers and WebSockets are only visible to the egress proxy, which can't see a
   > request's method inside TLS, so after arming the proxy refuses every new connection that CDP
   > `Fetch` hasn't also seen (or, simpler, every new WebSocket and SharedWorker connection)"

   A browser-level `Target.setAutoAttach` filtered to `shared_worker`, with
   `waitForDebuggerOnStart`, plus `Fetch.enable` on that target, paused and failed both the
   SharedWorker's start-up POST and its later POST (Q5, mode B).

   Replacement: "SharedWorkers are guarded like iframes, through browser-level auto-attach (scoped
   to the checkout context by `browserContextId`, item 3) and Fetch on the shared-worker target.
   Only WebSockets (not tested in the spike) are left to the egress proxy."

5. **How the guard proves it covers every frame and worker.**

   > §4.5: "Fail closed. If the guard can't confirm it is in place for every frame and worker of the
   > page, the click doesn't happen."

   Replacement: "Confirmed means all of these hold:
   - Auto-attach was on, with `waitForDebuggerOnStart`, before the first navigation.
   - Every page, iframe and shared_worker target it reported arrived with
     `waitingForDebugger: true`.
   - `Fetch.enable` succeeded on each of those targets before it was let run.

   Arming then only switches the policy from record to fail. A success reply alone is not proof:
   in mode B0, `Fetch.enable` succeeded and requests still leaked. Dedicated `worker` targets have
   no Fetch domain (`'Fetch.enable' wasn't found`); their requests are paused on the owning frame's
   session, so they count as covered by it."

   One case was not tested: attaching over the raw connection to an iframe that already exists.

   §7 says "CDP auto-attach and per-target `Fetch.enable`, or something else" is left to the
   builder. What the spike measured:
   - A second CDP connection beside Playwright's (here `--remote-debugging-port` and a WebSocket)
     blocked everything (mode B).
   - `new_cdp_session(frame)` attaches too late; start-up requests leak (mode C).

   It did not measure the other options, which stay open:
   - Playwright's `context.route()`: with routing on, Playwright auto-attaches to out-of-process
     iframes itself and routes their requests. Untested here, and it gives no SharedWorker.
   - Non-flattened auto-attach (`flatten: false`) on a Playwright `CDPSession`, driving children
     through `Target.sendMessageToTarget`. Untested.
   - Mode P's "can't" is an API reading, not a measurement: Python's `CDPSession.send(method,
     params)` takes no `sessionId`, so the flattened children whose `attachedToTarget` events
     arrived could not be addressed.

   SharedWorkers would still need a browser-level session in every option. If the second
   connection is chosen, a pipe is safer than `--remote-debugging-port`: that port is open to any
   local process for the browser's lifetime, which matters in a shared worker container. **Builds:** test in the shipped build (Chrome or full Chromium), never
   in chrome-headless-shell alone, which keeps cross-site iframes in process and hides the gap.

6. **GETs still leave after the guard is armed.**

   > §4.5: "every request whose method isn't `GET` (or `HEAD`/`OPTIONS`) is recorded with its body
   > and then failed before it is sent."

   This is not contradicted, but the spike shows its consequence. A skimmer's click-time image
   beacon carried the test card to the other host after arming, and the blur-time exfiltration
   happened before arming. Both are acceptable for a published test number, and §4.6 can see them,
   because Fetch pauses every GET with its URL.

   Proposed addition to §4.6: "Card-number matching runs over every paused request from page load
   to the end of the context, GET URLs included, not only over the guard's failed requests."

7. **On an empty-cart store, the phase-1 checkout load lands on the cart.**

   > §4.1: "When the homepage shows WooCommerce markers (§4.3 step 1) and the store's checkout URL
   > renders without redirecting (an empty-cart checkout may redirect to the cart; to confirm in the
   > spike, §8), the normal survey loads it once … Many skimmers only run when the URL contains
   > "checkout", so this catches some of them for free."

   The store's checkout page answers `302` to `/cart/` with an empty cart, on both block and
   classic (Q1). So the normal survey's checkout load lands on the cart page, where a skimmer keyed
   on the checkout URL or on `is_checkout()` doesn't run. The testbed skimmer was absent wherever
   `is_checkout()` was false. Phase 1 as built (Task 6) loads the page and reports it wherever it
   landed.

   Replacement: "On most stores the normal survey's checkout load lands on the cart, because an
   empty cart redirects. It is kept, since cart-page skimmers exist and the load is cheap, but it
   doesn't reach the checkout. Only the opt-in check, which adds to the cart, sees the checkout
   page."

8. **Reaching the checkout: details to add.**

   > §4.3 step 2: "Ask the public Store API (`/wp-json/wc/store/v1/products`) for an in-stock,
   > purchasable, simple product, cheapest first."

   > §4.3 step 3: "Load `/?add-to-cart=<id>` in the checkout check's browser context."

   These are not contradicted. Add the following:

   - The query is `?type=simple&stock_status=instock&orderby=price&order=asc`, filtered client-side
     on `is_in_stock`, because `is_purchasable` is true for a sold-out product.
   - Build the add-to-cart URL; don't use the API's `add_to_cart.url`.
   - The add can run through `context.request` with no page.
   - A product that can't be added fails silently, so read `GET /wp-json/wc/store/v1/cart` after the
     add and stop with "no purchasable product" if the cart is empty.
   - Load the add-to-cart URL only once; a second load adds a second unit.

What the spike did **not** cover: WebSockets; Stripe or WooPayments provider frames (no test
accounts); the cart's "Proceed to checkout" link (§4.3 step 4); a store with HPOS on.
