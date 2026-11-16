#!/usr/bin/env python3
"""Put the testbed back after the spike: delete every order the runs made (the store had none
before; only orders whose billing email is a spike address are deleted) and stock holds left
by deleted orders, switch the skimmer
and the extra gateways off, make the block checkout the store's checkout page, and print the
end state."""
from spike_common import Out, option, orders_sql, reserved_stock, sql, toggle, wp

out = Out("cleanup")


def main() -> None:
    rows = sql("select p.ID, p.post_status, m.meta_value from wp_posts p left join wp_postmeta m "
               "on m.post_id = p.ID and m.meta_key = '_billing_email' where p.post_type like 'shop_order%' order by p.ID")
    out("orders before cleanup:", rows)
    spike = [r[0] for r in rows if len(r) > 2 and r[2].endswith("@checkout-check.invalid")]
    other = [r for r in rows if r[0] not in spike]
    if other:
        out("NOT deleted (no spike billing email):", other)
    if spike:
        out(wp("post", "delete", *spike, "--force").strip().replace("\n", " | "))
    # Deleting an order leaves its stock hold behind (seen after the classic failed payment).
    orphans = sql("select order_id from wp_wc_reserved_stock where order_id not in "
                  "(select ID from wp_posts where post_type like 'shop_order%')")
    if orphans:
        out("removing stock holds of deleted orders:", orphans)
        sql("delete from wp_wc_reserved_stock where order_id not in "
            "(select ID from wp_posts where post_type like 'shop_order%')")
    out("carts left in wp_woocommerce_sessions (expire on their own):",
        sql("select count(*) from wp_woocommerce_sessions")[0][0])
    toggle("skimmer", "off")
    toggle("gateways", "extra", "off")
    toggle("checkout", "block")
    out("orders now:", orders_sql())
    out("reserved stock:", reserved_stock())
    out("skimmer:", option("mandacaru_test_skimmer"), "| checkout page id:", option("woocommerce_checkout_page_id"))
    out("gateways:", wp("wc", "payment_gateway", "list", "--fields=id,enabled", "--format=csv", "--user=admin").replace("\n", " "))
    out("product stock meta:", sql("select post_id, meta_key, meta_value from wp_postmeta where post_id in (11,12,13) "
                                    "and meta_key in ('_manage_stock','_stock') order by post_id, meta_key"))


if __name__ == "__main__":
    main()
