"""WooCommerce detection and checkout-page choice (pure, no browser)."""
import time

import pytest


@pytest.mark.parametrize("html", [
    "<script src='/wp-content/plugins/woocommerce/assets/js/frontend/add-to-cart.min.js'></script>",
    "<script>var woocommerce_params = {\"ajax_url\":\"/wp-admin/admin-ajax.php\"};</script>",
    "<script>var wc_add_to_cart_params = {};</script>",
    "<div class='wc-block-components-sidebar-layout'></div>",
    "<body class=\"home page-template woocommerce-js\">",
    "<body class='woocommerce'>",
    "<body class=\"x   WooCommerce-page y\">",
], ids=["plugin-path", "woocommerce_params", "wc_add_to_cart_params", "wc-block", "woocommerce-js", "single-quoted", "mixed-case"])
def test_each_marker_is_detected(html):
    from pnakotic.src.scanner.woo import looks_like_woocommerce

    assert looks_like_woocommerce("<html><head></head>" + html + "</html>") is True


def test_a_blog_with_a_checkout_link_and_no_marker_is_not_woocommerce():
    from pnakotic.src.scanner.woo import looks_like_woocommerce

    html = ("<html><body class='home blog'><a href='/checkout/'>Checkout</a>"
            "<p>We talk about woocommerce plugins here, in plain text.</p>"
            "<a href='/tag/woocommerce/'>tag</a></body></html>")
    assert looks_like_woocommerce(html) is False
    assert looks_like_woocommerce("") is False
    assert looks_like_woocommerce(None) is False  # type: ignore[arg-type]


def test_only_the_first_two_million_characters_are_read():
    from pnakotic.src.scanner.woo import looks_like_woocommerce

    marker = "<body class='woocommerce'>"
    assert looks_like_woocommerce("x" * 1_999_000 + marker) is True
    assert looks_like_woocommerce("x" * 2_000_000 + marker) is False


@pytest.mark.parametrize("html", [
    "class=\"" * 300_000,
    "class='" + "a " * 600_000,
    "class=" + " " * 1_900_000 + "\"woocommerce",
    "<div class=\"" + "a" * 1_990_000,
], ids=["quote-flood", "unterminated-single", "spaces-then-value", "unterminated-double"])
def test_adversarial_input_stays_fast(html):
    from pnakotic.src.scanner.woo import looks_like_woocommerce

    started = time.monotonic()
    looks_like_woocommerce(html)
    assert time.monotonic() - started < 1.0


def test_checkout_url_prefers_a_linked_checkout_wherever_it_lives():
    from pnakotic.src.scanner.woo import checkout_url

    links = ["https://shop.com/about/", "https://shop.com/kassa/checkout/?x=1#top", "https://shop.com/checkout/"]
    assert checkout_url(links, "shop.com", "https://shop.com/") == "https://shop.com/kassa/checkout/"


def test_checkout_url_ignores_other_hosts_and_non_final_segments():
    from pnakotic.src.scanner.woo import checkout_url

    links = ["https://evil.example/checkout/", "https://shop.com/checkout/order-pay/12/",
             "https://shop.com/checkouts/", "javascript:void(0)", "https://[bad/checkout/"]
    assert checkout_url(links, "shop.com", "https://shop.com/") == "https://shop.com/checkout/"
    assert checkout_url(links, "shop.com", "http://127.0.0.1:8000/") == "http://127.0.0.1:8000/checkout/"
    assert checkout_url([], "shop.com", "https://shop.com/") == "https://shop.com/checkout/"


def test_checkout_url_takes_the_www_twin_as_on_site_and_a_slashless_path():
    from pnakotic.src.scanner.woo import checkout_url

    assert checkout_url(["https://www.shop.com/checkout"], "shop.com", "https://shop.com/") == "https://shop.com/checkout"
