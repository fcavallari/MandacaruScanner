"""Helpers shared by the browser and YARA test modules.

Test modules import from here as ``from _support import ...`` (pytest's default import
mode puts ``tests/`` on ``sys.path``). A fixture is made available to a module with
``from _support import <fixture>  # noqa: F401``.
"""
import json

import pytest


def _browser_available() -> bool:
    """Skip live-browser tests when Chromium isn't installed (e.g. CI without `playwright install`)."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


requires_browser = pytest.mark.skipif(
    not _browser_available(),
    reason="Chromium not installed (run: playwright install chromium)",
)


# ---------- YARA: synthetic rules only (the real rule sets are private) ----------

def _yara_available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


requires_yara = pytest.mark.skipif(not _yara_available(), reason="yara-python not installed")

_RULE = """rule {name} : {tag} {{
  meta:
    signatureId = {sid}
    production = {production}
    severity = {severity}
    description = "{description}"
    targetLanguage = "raw"
  strings:
    $a = "{marker}"
  condition:
    $a and filename != "ignore-me"
}}
"""


def _rules_dir(tmp_path):
    """A rules tree split by target: html/ and raw/js_* are used, raw/php_* and php/ are not."""
    root = tmp_path / "YARA"
    for sub in ("html", "raw", "php"):
        (root / sub).mkdir(parents=True)

    def rule(path, name, marker, severity, production=True):
        tag = "production" if production else "exploratory"
        path.write_text(_RULE.format(name=name, tag=tag, sid=42000000 + len(name), severity=severity,
                                     production=str(production).lower(), marker=marker,
                                     description=f"Synthetic {name}"))

    rule(root / "raw" / "js_skimmer_test_001.yara", "js_skimmer_test_001", "PNAKOTIC_TEST_SKIMMER", 5)
    rule(root / "html" / "html_adframe_test_001.yara", "html_adframe_test_001", "PNAKOTIC_TEST_ADFRAME", 4,
         production=False)
    rule(root / "raw" / "php_ignored_test_001.yara", "php_ignored_test_001", "shop", 5)
    rule(root / "php" / "php_backdoor_test_001.yara", "php_backdoor_test_001", "news", 5)
    # By hand, not through _RULE: it conditions on the extension, so it matches runtime-built code
    # only when the scanner names those buffers like scripts (page.html would not match).
    (root / "raw" / "js_runtime_test_001.yara").write_text(
        'rule js_runtime_test_001 : production {\n  meta:\n    signatureId = 42000100\n    production = true\n'
        '    severity = 5\n    description = "Synthetic js_runtime_test_001"\n    targetLanguage = "raw"\n'
        '  strings:\n    $a = "PNAKOTIC_TEST_EVAL"\n  condition:\n    $a and filename matches /\\.js$/\n}\n')
    (root / "raw" / "js_broken_test_001.yara").write_text("rule js_broken_test_001 { condition: nope(")
    return root


@pytest.fixture
def yara_rules_dir(tmp_path, monkeypatch):
    root = _rules_dir(tmp_path)
    monkeypatch.setenv("YARA_RULES_DIR", str(root))
    return root


# ---------- site-mode loads against a local server ----------

def _site_engine(tmp_path):
    """Engine whose egress policy allows only 127.0.0.1 and localhost (two hosts, so a
    script on `localhost` is on another site than a page on `127.0.0.1`)."""
    from pnakotic.src.scanner.artifacts import ArtifactManager
    from pnakotic.src.scanner.engine import PnakoticEngine

    async def loopback_names(host):
        return host in ("127.0.0.1", "localhost")

    engine = PnakoticEngine(task_id="site-job", timeout_ms=10000, host_allowed=loopback_names)
    engine.artifacts = ArtifactManager(base_dir=str(tmp_path))
    return engine


# Task 6: homepages that may or may not look like WooCommerce, and the clean pages they link to.
# path -> (body class, the checkout link or None). /nowoo-linked/ is /woo-linked/ without the marker.
WOO_HOMES = {
    "/woo/": ("woocommerce-js", None),
    "/woo-linked/": ("woocommerce-js", "/woo-linked/checkout/"),
    "/nowoo-linked/": ("blog", "/nowoo-linked/checkout/"),
    "/woo-redirect/": ("woocommerce-js", "/woo-redirect/checkout/"),
    "/plainshop/": ("blog", "/plainshop/checkout/"),
}
WOO_CLEAN_PAGES = ("/woo-linked/checkout/", "/nowoo-linked/checkout/", "/woo-redirect/cart/", "/plainshop/checkout/")

DYNAMIC_PAGES = {}  # path -> HTML for pages a test builds itself (served by site_server)


# ---------- checkout pages for the card-input watch (card_watch.py) ----------
# "{port}" is the server's port; scripts at http://localhost:{port}/ are on another site than
# the pages at 127.0.0.1. Adapted from woo-checkout-scanner's fake-stripe-form-skimmer fixture.

def _checkout(script, extra=""):
    return ("<html><head><title>Checkout</title></head><body><h1>Checkout</h1>"
            "<form class='checkout woocommerce-checkout' action='#' onsubmit='return false'>"
            "<label>Email <input id='billing_email' name='billing_email'></label>"
            "<label>Postcode <input id='billing_postcode' name='billing_postcode'></label>"
            "<label>Coupon <input id='coupon_code' name='coupon_code'></label>"
            "<label>Password <input id='account_password' name='account_password' type='password'></label>"
            "<div class='payment_box payment_method_woocommerce_payments'>"
            "<div class='wcpay-upe-element'><em>Genuine processor element (placeholder)</em></div></div>"
            "<button id='place_order' type='submit'>Place order</button></form>"
            f"{extra}{script}</body></html>")


def _load_script(url):  # an inline loader for a script on another site
    return ("<script>var s = document.createElement('script'); "
            f"s.src = '{url}'; document.head.appendChild(s);</script>")


_CARD_FORM = ("'<label>Card number <input id=\"payment-numberInput\" name=\"number\" autocomplete=\"cc-number\"></label>'"
              " + '<label>Expiry <input id=\"payment-expiryInput\" name=\"expiry\" autocomplete=\"cc-exp\"></label>'"
              " + '<label>CVC <input id=\"payment-cvcInput\" name=\"cvc\" autocomplete=\"cc-csc\"></label>'")
_INLINE_FILLER = "\n".join(f"var storeSetting{i} = {i};" for i in range(38))  # served lines 2-40

# a stock async loader, served inline; a cross-site script then sets an onerror handler with
# exactly this text (or its windows-1252 reading) on an element whose expandos stand in for
# `document`, so the copy inserts a card form from the page URL with a served block's hash
_STOCK_LOADER = ("\n// Caf\u00e9 loader\n(function(){var s=document.createElement('script');s.async=true;"
                 "s.src='/js/empty.js';var t=document.getElementsByTagName('script')[0];"
                 "t.parentNode.insertBefore(s,t);})();\n")
_STOCK_LOADER_1252 = _STOCK_LOADER.encode("utf-8").decode("cp1252")


def _handler_copy(text):
    return ("setTimeout(function () { var im = document.createElement('img');\n"
            "  var form = document.createElement('form'); form.innerHTML = '<input autocomplete=\"cc-number\">';\n"
            "  im.document = {createElement: function () { return form; },\n"
            "    getElementsByTagName: function () { return [document.querySelector('h1')]; }};\n"
            f"  im.setAttribute('onerror', {json.dumps(text)});\n"
            "  im.src = 'data:,x'; document.body.appendChild(im); }, 50);\n")


_SERVED_INLINE = ("<script>\r\n// Caf\u00e9 \u20ac checkout \u2013 store code\r\n"
                  "var f = document.createElement('form');\r\n"
                  "f.innerHTML = '<input autocomplete=\"cc-number\">';\r\n"
                  "document.body.appendChild(f);\r\n</script>")

# WordPress ends each inline script it prints with a sourceURL comment naming it (`*-js-extra`);
# Chromium then reports the served block with that name as its URL, and its frames at the page URL.
_WC_SOURCE_URL = "\n//# sourceURL=wc-checkout-js-extra\n"
_SERVED_SX = ("var f = document.createElement('form');\n"
              "f.innerHTML = '<input autocomplete=\"cc-number\">';\n"
              "document.body.appendChild(f);" + _WC_SOURCE_URL)
_STOCK_LOADER_SX = _STOCK_LOADER + "//# sourceURL=wc-checkout-js-extra\n"
_EVAL_CARD = ("var f = document.createElement(\"form\"); f.innerHTML = \"<input autocomplete=cc-number>\";\n"
              "document.body.appendChild(f);\n//# sourceURL=")


def _js_extra(name, params):
    return f"<script id='{name}-js-extra'>\nvar {name.replace('-', '_')}_params = {params};\n//# sourceURL={name}-js-extra\n</script>\n"


# a WooCommerce classic checkout's inline scripts, as WordPress prints them (shapes from the testbed)
WP_PAGES = {
    "/wp-extras": ("<!DOCTYPE html>\n<html lang='en-US'><head><meta charset='UTF-8'><title>Checkout</title>\n"
                   + _js_extra("wc-add-to-cart", '{"ajax_url":"/wp-admin/admin-ajax.php","i18n_view_cart":"View cart"}')
                   + _js_extra("woocommerce", '{"ajax_url":"/wp-admin/admin-ajax.php"}')
                   + _js_extra("wc-country-select", '{"countries":"{\\"AF\\":[]}","i18n_searching":"Searching\\u2026"}')
                   + _js_extra("wc-address-i18n", '{"locale":"{}","i18n_optional_text":"optional"}')
                   + _js_extra("wc-checkout", '{"ajax_url":"/wp-admin/admin-ajax.php","option_guest_checkout":"yes"}')
                   + "<script id='wp-importmap' type='importmap'>\n{\"imports\":{\"@wordpress/interactivity\":"
                     "\"/js/empty.js\"}}\n</script>\n"
                   + "<script type='speculationrules'>\n{\"prefetch\":[{\"source\":\"document\",\"where\":"
                     "{\"href_matches\":\"/*\"},\"eagerness\":\"conservative\"}]}\n</script>\n"
                   + "</head><body class='woocommerce-checkout woocommerce-no-js'><h1>Checkout</h1>\n"
                   + "<script>\n\t\t(function () {\n\t\t\tvar c = document.body.className;\n"
                     "\t\t\tc = c.replace(/woocommerce-no-js/, 'woocommerce-js');\n"
                     "\t\t\tdocument.body.className = c;\n\t\t})();\n\t</script>\n"
                   + _js_extra("wc-order-attribution", '{"params":{"lifetime":1.0e-5,"session":30}}')
                   + "<script id='wp-emoji-settings' type='application/json'>\n{\"baseUrl\":\"/emoji/\",\"ext\":\".png\"}"
                     "\n</script>\n"
                   + "<script type='module'>\n/*! This file is auto-generated */\n"
                     "var t=document.querySelector('script#wp-emoji-settings');window._wpemojiSettings=JSON.parse(t.text);\n"
                     "//# sourceURL=http://127.0.0.1:{port}/wp-includes/js/wp-emoji-loader.min.js\n</script>\n"
                   + "</body></html>"),
}

CARD_PAGES = {
    # the store's own script builds a card form (detached, then attached: one insertion)
    "/card-store": _checkout("<script src='/js/form.js'></script>"),
    # a cross-site script hides the real field and writes its own card form with innerHTML
    "/card-skim": _checkout(_load_script("http://localhost:{port}/skim.js")),
    # card inputs in the served HTML, no script
    "/card-served": _checkout("", extra="<input name='cardnumber' autocomplete='cc-number'>"),
    # the cross-site script hides its stack before inserting
    "/card-hidden-stack": _checkout(_load_script("http://localhost:{port}/hidden.js")),
    # ... or makes prepareStackTrace read-only and forges a store stack
    "/card-forged-stack": _checkout(_load_script("http://localhost:{port}/forged.js")),
    # ... or makes stackTraceLimit read-only 1 and inserts through a store helper
    "/card-short-stack": _checkout("<script src='/js/helper.js'></script>"
                                   + _load_script("http://localhost:{port}/short.js")),
    # a 5 MB innerHTML write without a card input, then a small one with
    "/card-big-html": _checkout("<script src='/js/big.js'></script>"),
    # a bare input inserted, then renamed into a card field
    "/card-renamed": _checkout(_load_script("http://localhost:{port}/renamed.js")),
    # a served inline block on lines 2-40, then the store's script inserts an inline script that
    # adds a card form (its own lines count from 1, inside the served block's range)
    "/card-inline-runtime": ("<html><head><title>Checkout</title><script>\n" + _INLINE_FILLER + "\n</script></head>"
                             "<body><h1>Checkout</h1><script src='/js/inline-ins.js'></script></body></html>"),
    # the store's script inserts from 40 frames deep: more than code_origin reads
    "/card-deep": _checkout("<script src='/js/deep.js'></script>"),
    # a cross-site script that names itself after a store file with //# sourceURL
    "/card-sourceurl": _checkout(_load_script("http://localhost:{port}/renamed-source.js")),
    # the store's custom element builds its card form when it is attached (appendChild, then
    # innerHTML): the store's code runs inside our hooked call, under our wrapper's frame
    "/card-custom-element": _checkout("<script src='/js/element.js'></script>"),
    # after load, a cross-site script sets an onerror handler whose text starts with 5 newlines,
    # so the handler (at the page URL) runs at line 6, inside the served block on lines 2-33
    "/card-onerror-shift": ("<!doctype html>\n<html><head><title>Checkout</title><script>\n"
                            + "\n".join(f"var storeSetting{i} = {i};" for i in range(31))
                            + "\n</script></head>\n<body><h1>Checkout</h1>"
                            + _load_script("http://localhost:{port}/onerror-shift.js") + "</body></html>"),
    # the same on a one-line (minified) page: the handler's line 1 is the served block's line
    "/card-onerror-min": ("<html><head><title>Checkout</title><script>var storeCfg=1;</script></head><body>"
                          "<h1>Checkout</h1>" + _load_script("http://localhost:{port}/onerror-min.js")
                          + "</body></html>"),
    # the store's own served inline script inserts card fields (CRLF line ends, non-ASCII text):
    # proven the store's by its script hash
    "/card-served-inline": _checkout(_SERVED_INLINE).replace("<head>", "<head><meta charset='utf-8'>"),
    # the same page without a declared charset (Chromium reads it as windows-1252)
    "/card-served-inline-1252": _checkout(_SERVED_INLINE),
    # the same page declared Shift_JIS: its non-ASCII block can't be hashed as the browser read it
    "/card-served-inline-sjis": _checkout(_SERVED_INLINE).replace("<head>", "<head><meta charset='shift_jis'>"),
    # an event handler that is a byte-identical copy of a served block (and its mojibake reading)
    "/card-handler-copy": ("<html><head><meta charset='utf-8'><title>Checkout</title></head><body><h1>Checkout</h1>"
                           f"<script>{_STOCK_LOADER}</script>"
                           + _load_script("http://localhost:{port}/handler-copy.js") + "</body></html>"),
    "/card-handler-moji": ("<html><head><meta charset='utf-8'><title>Checkout</title></head><body><h1>Checkout</h1>"
                           f"<script>{_STOCK_LOADER}</script>"
                           + _load_script("http://localhost:{port}/handler-moji.js") + "</body></html>"),
    # a cross-site script whose URL holds "(" and a store URL after it
    "/card-paren-url": _checkout("<script src='http://localhost:{port}/paren.js?(http://127.0.0.1:{port}/js/form.js'>"
                                 "</script>"),
    # a cross-site script that runs data: URL scripts ending in a comment naming a store file (raw
    # text: the space before it stays in the URL, where V8's file name keeps it)
    "/card-data-url": _checkout(_load_script("http://localhost:{port}/data-url.js")),
    # HTML handed over as objects, which the hook must not convert (a cross-site script)
    "/card-object-html": _checkout(_load_script("http://localhost:{port}/object-html.js")),
    # the store's script inserts from inside forEach and a Promise executor (builtin frames)
    "/card-builtins-store": _checkout("<script src='/js/builtins.js'></script>"),
    # the same code from another site
    "/card-builtins-skim": _checkout(_load_script("http://localhost:{port}/builtins.js")),
    # the store's served inline block, ending in a WordPress sourceURL comment, inserts card fields
    "/card-served-sourceurl": _checkout(f"<script id='wc-checkout-js-extra'>{_SERVED_SX}</script>")
                              .replace("<head>", "<head><meta charset='utf-8'>"),
    # the same block, then after load a cross-site script evals a byte-identical copy of its text
    "/card-sourceurl-eval-copy": _checkout(f"<script id='wc-checkout-js-extra'>{_SERVED_SX}</script>"
                                           + _load_script("http://localhost:{port}/eval-copy.js"))
                                 .replace("<head>", "<head><meta charset='utf-8'>"),
    # a served inline block evals code that names itself after the page and inserts card fields
    "/card-eval-pageurl": _checkout(f"<script>eval({json.dumps(_EVAL_CARD)} + location.href);</script>")
                          .replace("<head>", "<head><meta charset='utf-8'>"),
    # a served sourceURL'd loader, and a cross-site script setting a handler with its exact text
    "/card-handler-copy-sx": ("<html><head><meta charset='utf-8'><title>Checkout</title></head><body><h1>Checkout</h1>"
                              f"<script>{_STOCK_LOADER_SX}</script>"
                              + _load_script("http://localhost:{port}/handler-copy-sx.js") + "</body></html>"),
}
CARD_SCRIPTS = {
    "/eval-copy.js": f"setTimeout(function () {{ eval({json.dumps(_SERVED_SX)}); }}, 50);\n",
    "/handler-copy-sx.js": _handler_copy(_STOCK_LOADER_SX),
    "/js/form.js": ("var f = document.createElement('form'); var i = document.createElement('input');\n"
                    "i.name = 'number'; i.setAttribute('autocomplete', 'cc-number'); f.appendChild(i);\n"
                    "document.body.appendChild(f);\n"),
    "/skim.js": ("var box = document.querySelector('.payment_box.payment_method_woocommerce_payments');\n"
                 "var real = box.querySelector('.wcpay-upe-element'); real.style.display = 'none';\n"
                 "var host = document.createElement('div'); host.id = 'fx-payment-container';\n"
                 "box.appendChild(host);\n"
                 f"host.innerHTML = {_CARD_FORM};\n"),
    "/hidden.js": ("Error.prepareStackTrace = function () { return ''; }; Error.stackTraceLimit = 0;\n"
                   "var f = document.createElement('form');\n"
                   f"f.innerHTML = {_CARD_FORM};\n"
                   "document.body.appendChild(f);\n"),
    "/forged.js": ("Object.defineProperty(Error, 'prepareStackTrace', {writable: false, configurable: false,\n"
                   "  value: function () { return 'Error\\n    at http://127.0.0.1:{port}/js/form.js:1:1'; }});\n"
                   "var f = document.createElement('form');\n"
                   f"f.innerHTML = {_CARD_FORM};\n"
                   "document.body.appendChild(f);\n"),
    "/js/helper.js": "window.storeInsert = function (node) { document.body.appendChild(node); };\n",
    "/short.js": ("Object.defineProperty(Error, 'stackTraceLimit', {value: 1, writable: false, configurable: false});\n"
                  "var f = document.createElement('form');\n"
                  f"f.innerHTML = {_CARD_FORM};\n"
                  "window.storeInsert(f);\n"),
    "/js/big.js": ("var a = document.createElement('div'); document.body.appendChild(a);\n"
                   "a.innerHTML = '<p>' + 'x'.repeat(5 * 1024 * 1024) + '</p>';\n"
                   "var b = document.createElement('div'); document.body.appendChild(b);\n"
                   "b.innerHTML = '<input name=\"cardnumber\" autocomplete=\"cc-number\">';\n"),
    "/renamed.js": ("var i = document.createElement('input'); document.body.appendChild(i);\n"
                    "i.setAttribute('name', 'cardnumber'); i.setAttribute('autocomplete', 'cc-number');\n"),
    "/js/inline-ins.js": ("var s = document.createElement('script');\n"
                          "s.text = 'var f = document.createElement(\"form\");\\n'\n"
                          "  + 'f.innerHTML = \"<input name=cardnumber>\";\\n'\n"
                          "  + 'document.body.appendChild(f);\\n'\n"
                          "  + 'setTimeout(function () { var g = document.createElement(\"form\");\\n'\n"
                          "  + 'g.innerHTML = \"<input name=cvc>\"; document.body.appendChild(g); }, 0);\\n';\n"
                          "document.body.appendChild(s);\n"),
    "/renamed-source.js": ("var f = document.createElement('form');\n"
                           f"f.innerHTML = {_CARD_FORM};\n"
                           "document.body.appendChild(f);\n"
                           "//# sourceURL=http://127.0.0.1:{port}/js/form.js\n"),
    "/js/element.js": ("class PayForm extends HTMLElement { connectedCallback() {\n"
                       "  if (this.firstChild) return; var f = document.createElement('form');\n"
                       "  f.innerHTML = '<input autocomplete=\"cc-number\">'; this.appendChild(f); } }\n"
                       "customElements.define('pay-form', PayForm);\n"
                       "document.body.appendChild(document.createElement('pay-form'));\n"
                       "var holder = document.createElement('div'); document.body.appendChild(holder);\n"
                       "holder.innerHTML = '<pay-form></pay-form>';\n"),
    "/onerror-shift.js": ("setTimeout(function () { var im = document.createElement('img');\n"
                          "  im.setAttribute('onerror', '\\n\\n\\n\\n\\n' + 'var f = document.createElement(\"form\"); '\n"
                          "    + 'f.innerHTML = \"<input name=cardnumber>\"; document.body.appendChild(f);');\n"
                          "  im.src = 'data:,x'; document.body.appendChild(im); }, 50);\n"),
    "/onerror-min.js": ("setTimeout(function () { var im = document.createElement('img');\n"
                        "  im.setAttribute('onerror', 'var f = document.createElement(\"form\"); '\n"
                        "    + 'f.innerHTML = \"<input name=cardnumber>\"; document.body.appendChild(f);');\n"
                        "  im.src = 'data:,x'; document.body.appendChild(im); }, 50);\n"),
    "/object-html.js": ("var a = document.createElement('div'); document.body.appendChild(a);\n"
                        "a.innerHTML = new String('<input autocomplete=\"cc-number\">');\n"
                        "var b = document.createElement('div'); document.body.appendChild(b);\n"
                        "b.insertAdjacentHTML('beforeend', ['<input name=\"cvc\">']);\n"
                        "var c = document.createElement('div'); document.body.appendChild(c);\n"
                        "c.outerHTML = new String('<p><input name=\"card_exp\"></p>');\n"),
    "/js/builtins.js": ("[1].forEach(function () { var f = document.createElement('form');\n"
                        "  f.innerHTML = '<input autocomplete=\"cc-number\">'; document.body.appendChild(f); });\n"
                        "new Promise(function () { var g = document.createElement('form');\n"
                        "  g.innerHTML = '<input name=\"cvc\">'; document.body.appendChild(g); });\n"),
    "/js/empty.js": "",
    "/handler-copy.js": _handler_copy(_STOCK_LOADER),
    "/handler-moji.js": _handler_copy(_STOCK_LOADER_1252),
    "/paren.js": ("var f = document.createElement('form'); f.innerHTML = '<input autocomplete=\"cc-number\">';\n"
                  "document.body.appendChild(f);\n"),
    "/data-url.js": ("var code = function (n) { return 'var f = document.createElement(\"form\"); '\n"
                     "  + 'f.innerHTML = \"<input name=' + n + '>\"; document.body.appendChild(f);'\n"
                     "  + '// http://127.0.0.1:{port}/js/form.js'; };\n"
                     "var s = document.createElement('script');\n"
                     "s.src = 'data:text/javascript,' + code('cardnumber');\n"
                     "document.head.appendChild(s);\n"
                     "import('data:text/javascript,' + code('cvc'));\n"),
    "/js/deep.js": ("function down(n) { if (n > 0) return down(n - 1);\n"
                    "  var f = document.createElement('form'); f.innerHTML = '<input autocomplete=\"cc-number\">';\n"
                    "  document.body.appendChild(f); }\n"
                    "down(40);\n"),
}
CARD_SCRIPTS["/builtins.js"] = CARD_SCRIPTS["/js/builtins.js"]  # the same code from another site


@pytest.fixture(scope="module")
def site_server():
    """127.0.0.1 server for site-mode loads. Yields its base URL."""
    import json
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Server(ThreadingHTTPServer):
        daemon_threads = True

    # The same footer on several pages: the filler on both sides is longer than the YARA
    # snippet window (240 bytes), so the snippet, and with it the finding, is identical.
    filler = "<p>" + "Thanks for reading. " * 15 + "</p>"
    footer = f"<footer>{filler}<script>/*PNAKOTIC_TEST_SKIMMER*/</script>{filler}</footer></body></html>"
    obf = ("function _0x34e5(){var _0x18b8=['a','b'];_0x34e5=function(){return _0x18b8;};return _0x34e5();}"
           "(function(_0x44e7,_0x5d16){var _0x7eb7=_0x44e7();while(!![]){try{break;}catch(_0x1){"
           "_0x7eb7['push'](_0x7eb7['shift']());}}}(_0x34e5,0x1));")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # chunked /stream needs it

        def log_message(self, *args):
            pass

        def _send(self, status, content_type, body):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            port = self.server.server_address[1]

            def loader(name):  # the Task 5 LOADER shape, to a script on localhost
                return (";;(function(f,i,u,w,s){w=f.createElement(i);s=f.getElementsByTagName(i)[0];"
                        "w.async=1;w.src=u;s.parentNode.insertBefore(w,s);})"
                        f"(document,'script','http://localhost:{port}/{name}');")
            if self.path == "/":  # the Task 5 loader shape, injecting a script from another site
                self._send(200, "text/html", (
                    "<html><head><title>Shop</title></head><body><a href='/about'>About</a>"
                    "<a href='/2024/05/post/'>Post</a><a href='/about/'>About us</a>"
                    "<a href='/category/x/'>Category</a>"
                    f"<script>{loader('payload.js')}</script>{footer}").encode())
            elif self.path in ("/about", "/about/", "/2024/05/post/", "/category/x/"):
                self._send(200, "text/html", (
                    f"<html><head><title>Page {self.path}</title></head><body><h1>{self.path}</h1>"
                    f"{footer}").encode())
            elif self.path == "/g/":  # the footer only for Googlebot
                bot = "Googlebot" in (self.headers.get("User-Agent") or "")
                self._send(200, "text/html", ("<html><head><title>G</title></head><body><h1>G</h1>"
                                              + (footer if bot else "</body></html>")).encode())
            elif self.path == "/hang/":
                time.sleep(20)
                try:
                    self._send(200, "text/html", b"<html><body>late</body></html>")
                except OSError:
                    pass  # the browser went away
            elif self.path == "/plain/":  # a plain GA-shaped loader
                self._send(200, "text/html", ("<html><head><title>Plain</title></head><body><h1>Plain</h1>"
                                              f"<script>{loader('clean.js')}</script></body></html>").encode())
            elif self.path in WOO_HOMES:  # a WooCommerce store's homepage (Task 6: the checkout page)
                marker, link = WOO_HOMES[self.path]
                body = ("<html><head><title>Store</title></head><body class='home " + marker + "'><h1>Store</h1>"
                        + (f"<a href='{link}'>Checkout</a>" if link else "") + "</body></html>")
                self._send(200, "text/html", body.encode())
            elif self.path == "/checkout/":  # the cross-host card skimmer of /card-skim, on the root checkout
                self._send(200, "text/html", CARD_PAGES["/card-skim"].replace("{port}", str(port)).encode())
            elif self.path in WOO_CLEAN_PAGES:
                self._send(200, "text/html", (f"<html><head><title>Page</title></head><body><h1>{self.path}</h1>"
                                              "</body></html>").encode())
            elif self.path == "/woo-redirect/checkout/":  # a store whose checkout goes to the cart
                self.send_response(302)
                self.send_header("Location", "/woo-redirect/cart/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/obf/":  # obfuscator.io code injecting a script from another site
                self._send(200, "text/html", (
                    "<html><head><title>Obf</title></head><body><h1>Obf</h1>"
                    f"<script>{obf}{loader('clean.js')}</script></body></html>").encode())
            elif self.path == "/m/" and "iPhone" in (self.headers.get("User-Agent") or ""):
                self.send_response(302)  # only phones are sent to another site (a plain page there)
                self.send_header("Location", f"http://localhost:{port}/plain/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path == "/m/":
                self._send(200, "text/html", b"<html><head><title>M</title></head><body><h1>M</h1></body></html>")
            elif self.path == "/to-other/":
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{port}/about/")
                self.send_header("Content-Length", "0")
                self.end_headers()
            elif self.path in ("/eval-stage", "/eval-sourceurl", "/eval-template", "/eval-flood", "/eval-debugger",
                           "/eval-stackless", "/eval-string-hook", "/eval-dataurl", "/eval-crowd",
                           "/hooks-only"):
                scripts = {  # code the page builds at runtime (Task 2: eval_capture)
                    "/eval-stage": 'new Function("/*PNAKOTIC_TEST_EVAL*/ return 1")(); eval(' + json.dumps(obf) + ');',
                    "/eval-sourceurl": 'eval("/*PNAKOTIC_TEST_EVAL*/\\n//# sourceURL=https://example.com/jquery.js");',
                    "/eval-template": 'for (var i = 0; i < 3; i++) { new Function("obj", "return obj.a")({a: i}); }',
                    "/eval-flood": 'for (var i = 0; i < 500; i++) { new Function("return " + i); }',
                    # built from a timer or a promise: no JS frame on the stack, so no caller
                    "/eval-stackless": 'setTimeout("/*PNAKOTIC_TEST_EVAL*/ 1", 0); setTimeout(eval, 0, "2 + 2"); '
                                       'Promise.resolve("3 + 3").then(eval);',
                    # a page that only trips the behavior hooks (each report is a binding call into Playwright)
                    "/hooks-only": 'document.execCommand("copy"); '
                                   'document.body.requestFullscreen && document.body.requestFullscreen();',
                    # a page that points String at eval and lets the behavior hooks call it (execCommand)
                    "/eval-string-hook": 'String = eval; document.execCommand("/*PNAKOTIC_TEST_EVAL*/ 1 + 1");',
                    # scripts made from a data: and a blob: URL: a URL, no sourceURL, no stack
                    "/eval-dataurl": ('var s = document.createElement("script"); '
                                      's.src = "data:text/javascript,/*PNAKOTIC_TEST_EVAL_DATA*/ var a = 1;"; '
                                      'document.head.appendChild(s); '
                                      'var u = URL.createObjectURL(new Blob(["/*PNAKOTIC_TEST_EVAL_BLOB*/ var b = 2;"], '
                                      '{type: "text/javascript"})); var t = document.createElement("script"); '
                                      't.src = u; document.head.appendChild(t);'),
                    # 25 distinct throwaway stages, a 26th repeated ten times, then the one that matters
                    "/eval-crowd": ('for (var i = 0; i < 25; i++) { new Function("return " + i); } '
                                    'for (var j = 0; j < 10; j++) { new Function("return 99"); } '
                                    'eval("/*PNAKOTIC_TEST_EVAL*/" + ' + json.dumps(obf) + ');'),
                    "/eval-debugger": 'setInterval(function () { debugger; }, 10); '
                                      'new Function("/*PNAKOTIC_TEST_EVAL*/")();',
                }
                self._send(200, "text/html", (f"<html><head><title>Eval</title></head><body><h1>Eval</h1><iframe srcdoc='<p>hi</p>'></iframe>"
                                              f"<script>{scripts[self.path]}</script></body></html>").encode())
            elif self.path in WP_PAGES:  # served inline blocks with WordPress's sourceURL comments
                self._send(200, "text/html; charset=UTF-8", WP_PAGES[self.path].replace("{port}", str(port)).encode())
            elif self.path in CARD_PAGES:  # card inputs inserted into a checkout (Task 4: card_watch)
                self._send(200, "text/html", CARD_PAGES[self.path].replace("{port}", str(port)).encode())
            elif self.path.split("?")[0] in CARD_SCRIPTS:
                body = CARD_SCRIPTS[self.path.split("?")[0]].replace("{port}", str(port))
                self._send(200, "text/javascript", body.encode())
            elif self.path in DYNAMIC_PAGES:
                self._send(200, "text/html", DYNAMIC_PAGES[self.path].encode())
            elif self.path == "/payload.js":
                self._send(200, "text/javascript", b"var PNAKOTIC_TEST_SKIMMER = 1;")
            elif self.path == "/challenge":
                self._send(403, "text/html", b"<html><head><title>One more step</title></head><body>"
                                             b"<script src=\"/cdn-cgi/challenge-platform/h/b\"></script>"
                                             b"</body></html>")
            elif self.path == "/stream":  # a main document that never finishes (chunked, no length)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                chunk = b"<html><body><p>still loading</p>"
                try:
                    for _ in range(300):  # 30 s at most, then the thread gives up
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass  # the browser went away
            elif self.path == "/clean.js":
                self._send(200, "text/javascript", b"var clean = 1;")
            elif self.path == "/plainobf/":  # a plain loader fetching obfuscator.io output from another site
                self._send(200, "text/html", ("<html><head><title>PlainObf</title></head><body><h1>PlainObf</h1>"
                                              f"<script>{loader('obf.js')}</script></body></html>").encode())
            elif self.path == "/obf.js":
                self._send(200, "text/javascript", obf.encode())
            elif self.path == "/flagged/":  # a page whose cross-site script the CDN blocks as malware
                self._send(200, "text/html", ("<html><head><title>Flagged</title></head><body><h1>Flagged</h1>"
                                              f"<script src='http://localhost:{port}/blocked.js'></script>"
                                              "</body></html>").encode())
            elif self.path == "/blocked.js":  # Cloudflare's "Suspected Malware" interstitial, as r1.fo served it
                self._send(403, "text/html", b"<!DOCTYPE html><html><head><title>Suspected Malware | Cloudflare</title>"
                                             b"</head><body><h1>Warning</h1><h2>Suspected Malware</h2><p>This website "
                                             b"has been reported for potentially distributing malware.</p></body></html>")
            else:
                self._send(404, "text/html", b"<html><body>Not found</body></html>")

    srv = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


# ---------- site-check loads built by hand (no browser) ----------

def _yara_hop(source, url, rule, sev, production, offset, text):
    """A per-buffer `yara_match` hop as a site-mode load records it."""
    import json

    from pnakotic.src.scanner.models import RedirectHop
    from pnakotic.src.scanner.yara_scan import YARA_MECHANISM

    return RedirectHop(url=url, mechanism=YARA_MECHANISM, evidence=json.dumps({
        "id": "yara_match", "rule": rule, "signature_id": 1, "severity": sev, "production": production,
        "description": f"Synthetic {rule}", "source": source, "url": url, "offset": offset,
        "buffer_index": 0, "hits": 1,
        "context": {"text": text, "match_start": 0, "match_end": len(text), "line": 1},
    }))


def _eval_stage(text="OBFUSCATED", caller="", markers=("string_array_rotation",), yara_matched=False, oversized=False):
    """One `metadata["eval_stages"]` entry as the engine records it."""
    return {"caller": caller, "caller_line": None, "length": len(text), "markers": list(markers),
            "context": {"text": text, "match_start": 0, "match_end": len(text), "line": 1},
            "yara_matched": yara_matched, "oversized": oversized}


def _load(page_index, page_url, profile, hops=(), injections=(), state="checked", reason=None, final_url=None,
          script_requests=(), score=0.0, eval_stages=(), card_inputs=None):
    """A site-check Load around a hand-built ScanResult."""
    from pnakotic.src.scanner.models import ScanResult
    from pnakotic.src.scanner.site_findings import Load

    result = ScanResult(target_url=page_url, final_url=final_url or page_url, hops=list(hops), malicious_score=score)
    result.metadata = {
        "injections": list(injections), "script_requests": list(script_requests),
        "scoring_findings": [], "decisive_findings": [], "cloaking": None,
        "eval_stages": list(eval_stages),
    }
    if card_inputs is not None:
        result.metadata["card_inputs"] = card_inputs
    return Load(page_index=page_index, page_url=page_url, profile=profile, state=state, reason=reason,
                result=result, shot=None)


def _card(owner="unknown", frames=(), via="appendChild", verified=True, vendors=(), first_unknown=None):
    """One `metadata["card_inputs"]["inserted"]` entry as card_watch.summarize records it."""
    frames = list(frames)
    if first_unknown is None:
        first_unknown = frames[0] if owner == "unknown" and frames else ""
    return {"via": via, "owner": owner, "vendors": list(vendors), "frames": frames, "cut": False,
            "verified": verified, "first_unknown": first_unknown}


def _cards(*inserted, present=None):
    """A `metadata["card_inputs"]` dict; `present` defaults to the number of insertions."""
    return {"present": len(inserted) if present is None else present, "inserted": list(inserted), "dropped": 0,
            "unverifiable": None}


def _result(**metadata):
    """A ScanResult carrying just the given metadata (plus a page title, default "x")."""
    from pnakotic.src.scanner.models import ScanResult

    signals = {"title": metadata.pop("title", "x")}
    return ScanResult(target_url="https://s.com/", final_url="https://s.com/",
                      metadata={"page_signals": signals, **metadata})
