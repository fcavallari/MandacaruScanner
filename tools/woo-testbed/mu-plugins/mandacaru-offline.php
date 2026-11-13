<?php
/**
 * Testbed only: keep the running store quiet and offline.
 * No mail, no WooCommerce marketplace/tracking/onboarding prompts, no WC Admin.
 */

add_filter( 'pre_wp_mail', '__return_true' );
add_filter( 'woocommerce_admin_disabled', '__return_true' );
add_filter( 'woocommerce_allow_marketplace_suggestions', '__return_false' );
add_filter( 'woocommerce_helper_suppress_admin_notices', '__return_true' );
add_filter( 'pre_option_woocommerce_allow_tracking', function () { return 'no'; } );
add_filter( 'pre_option_woocommerce_show_marketplace_suggestions', function () { return 'no'; } );
add_filter( 'woocommerce_enable_nocache_headers', '__return_true' );
