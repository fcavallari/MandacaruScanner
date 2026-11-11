#!/usr/bin/env bash
# Idempotent setup of the Pnakotic WooCommerce testbed. Safe to run twice.
# Usage: ./setup.sh        (starts the stack if needed, then configures it)
set -euo pipefail
cd "$(dirname "$0")"

export WOO_PORT="${WOO_PORT:-8188}"
export COLLECTOR_PORT="${COLLECTOR_PORT:-8199}"
WOO_URL="http://localhost:${WOO_PORT}"
WOO_VERSION="11.2.2"
ADMIN_USER="admin"
ADMIN_PASSWORD="${WOO_ADMIN_PASSWORD:-pnakotic-testbed}"

# Every compose command targets the testbed's own project.
dc() { docker compose -p pnakotic-woo-testbed "$@"; }
wp() { dc run --rm -T wpcli "$@"; }
log() { printf '==> %s\n' "$*"; }

log "Starting the stack"
dc up -d --wait

log "Waiting for WordPress files"
for _ in $(seq 1 60); do
  if dc exec -T wordpress test -f /var/www/html/wp-includes/version.php \
     && dc exec -T wordpress test -f /var/www/html/wp-config.php; then break; fi
  sleep 2
done

log "WordPress core"
if ! wp core is-installed >/dev/null 2>&1; then
  wp core install --url="$WOO_URL" --title="Pnakotic Test Store" \
    --admin_user="$ADMIN_USER" --admin_password="$ADMIN_PASSWORD" \
    --admin_email="admin@checkout-check.invalid" --skip-email
fi
wp rewrite structure '/%postname%/' >/dev/null
# wp-cli can't see Apache's mod_rewrite, so write .htaccess ourselves.
wp eval 'add_filter("got_mod_rewrite", "__return_true"); require_once ABSPATH . "wp-admin/includes/file.php"; require_once ABSPATH . "wp-admin/includes/misc.php"; $GLOBALS["wp_rewrite"]->flush_rules(true);' >/dev/null
wp option update blog_public 0 >/dev/null

log "WooCommerce $WOO_VERSION and the test gateway"
if ! wp plugin is-installed woocommerce >/dev/null 2>&1; then
  wp plugin install woocommerce --version="$WOO_VERSION"
fi
wp plugin activate woocommerce pnakotic-test-gateway

log "Store settings"
wp option update woocommerce_store_address "1 Test Street" >/dev/null
wp option update woocommerce_store_city "Testville" >/dev/null
wp option update woocommerce_store_postcode "90210" >/dev/null
wp option update woocommerce_default_country "US:CA" >/dev/null
wp option update woocommerce_currency "USD" >/dev/null
wp option update woocommerce_calc_taxes "no" >/dev/null
wp option update woocommerce_enable_guest_checkout "yes" >/dev/null
wp option update woocommerce_enable_signup_and_login_from_checkout "no" >/dev/null
wp option update woocommerce_coming_soon "no" >/dev/null
wp option update woocommerce_store_pages_only "no" >/dev/null
wp option update woocommerce_onboarding_opt_in "no" >/dev/null
wp option update woocommerce_allow_tracking "no" >/dev/null
wp option update woocommerce_show_marketplace_suggestions "no" >/dev/null
wp option update woocommerce_admin_install_timestamp "$(date +%s)" >/dev/null

log "Emails off"
for id in new_order cancelled_order failed_order customer_on_hold_order \
          customer_processing_order customer_completed_order customer_refunded_order \
          customer_invoice customer_note customer_reset_password customer_new_account; do
  wp option update "woocommerce_email_${id}_enabled" no >/dev/null
  wp option patch insert "woocommerce_${id}_settings" enabled no >/dev/null 2>&1 \
    || wp option patch update "woocommerce_${id}_settings" enabled no >/dev/null 2>&1 || true
done

log "Pages"
# WooCommerce creates shop, cart, checkout (block) and my-account on activation.
if [ -z "$(wp post list --post_type=page --name=checkout --field=ID)" ]; then
  wp wc tool run install_pages --user="$ADMIN_USER" >/dev/null
fi
if [ -z "$(wp post list --post_type=page --name=checkout-classic --field=ID)" ]; then
  wp post create --post_type=page --post_status=publish --post_title="Checkout (classic)" \
    --post_name=checkout-classic --post_content='[woocommerce_checkout]' >/dev/null
fi
# Default checkout page: the block one, unless one was already chosen.
if [ "$(wp option get woocommerce_checkout_page_id)" = "" ]; then
  wp option update woocommerce_checkout_page_id "$(wp post list --post_type=page --name=checkout --field=ID)" >/dev/null
fi

log "Payment gateways"
wp wc payment_gateway update pnakotic_test --enabled=true --user="$ADMIN_USER" >/dev/null
wp wc payment_gateway update cod --enabled=true --user="$ADMIN_USER" >/dev/null
wp wc payment_gateway update bacs --enabled=true --user="$ADMIN_USER" >/dev/null
wp option update woocommerce_gateway_order '{"pnakotic_test":0,"bacs":1,"cod":2}' --format=json >/dev/null

log "Shipping (flat rate for every address)"
# Zone 0 ("locations not covered") through PHP: its REST update/delete routes 404.
wp eval '
$zone = new WC_Shipping_Zone( 0 );
$flat = array_values( array_filter( $zone->get_shipping_methods(), function ( $m ) { return $m->id === "flat_rate"; } ) );
if ( ! $flat ) {
	$zone->add_shipping_method( "flat_rate" );
	$flat = array_values( array_filter( $zone->get_shipping_methods(), function ( $m ) { return $m->id === "flat_rate"; } ) );
}
foreach ( $flat as $i => $m ) {
	if ( $i > 0 ) { $zone->delete_shipping_method( $m->instance_id ); continue; }
	update_option( "woocommerce_flat_rate_" . $m->instance_id . "_settings", array( "title" => "Flat rate", "tax_status" => "none", "cost" => "5.00" ) );
}
' >/dev/null

log "Products"
product_id() { wp wc product list --sku="$1" --user="$ADMIN_USER" --field=id | head -1 | tr -d '\r'; }
ensure_simple() { # sku name price in_stock
  if [ -z "$(product_id "$1")" ]; then
    wp wc product create --user="$ADMIN_USER" --sku="$1" --name="$2" --type=simple \
      --regular_price="$3" --in_stock="$4" --status=publish >/dev/null
  fi
}
ensure_simple PNK-DOLLAR  "Test Dollar Item"  1.00  true
ensure_simple PNK-WIDGET  "Test Widget"       12.50 true
ensure_simple PNK-GADGET  "Test Gadget"       24.00 true
ensure_simple PNK-SOLDOUT "Test Sold Out"     9.00  false
if [ -z "$(product_id PNK-TEE)" ]; then
  tee="$(wp wc product create --user="$ADMIN_USER" --sku=PNK-TEE --name="Test Variable Tee" --type=variable \
    --status=publish \
    --attributes='[{"name":"Size","visible":true,"variation":true,"options":["S","M"]}]' \
    --porcelain | tr -d '\r')"
  for size in S M; do
    wp wc product_variation create "$tee" --user="$ADMIN_USER" --regular_price=15.00 \
      --in_stock=true --attributes="[{\"name\":\"Size\",\"option\":\"$size\"}]" >/dev/null
  done
fi

wp cache flush >/dev/null 2>&1 || true
wp eval 'add_filter("got_mod_rewrite", "__return_true"); require_once ABSPATH . "wp-admin/includes/file.php"; require_once ABSPATH . "wp-admin/includes/misc.php"; $GLOBALS["wp_rewrite"]->flush_rules(true);' >/dev/null

log "Done. Store: $WOO_URL   Collector: http://localhost:${COLLECTOR_PORT}   Admin: $ADMIN_USER / (WOO_ADMIN_PASSWORD, default in setup.sh)"
