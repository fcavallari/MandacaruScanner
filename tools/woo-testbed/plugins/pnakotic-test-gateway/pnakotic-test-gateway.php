<?php
/**
 * Plugin Name: Pnakotic Test Gateway
 * Description: Testbed only. A card gateway (id pnakotic_test) that renders native card inputs in the store's own page, in the classic and the block checkout, and always fails payment server-side.
 * Version: 0.1.0
 */

defined( 'ABSPATH' ) || exit;

add_action( 'before_woocommerce_init', function () {
	if ( class_exists( '\Automattic\WooCommerce\Utilities\FeaturesUtil' ) ) {
		\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'cart_checkout_blocks', __FILE__, true );
		\Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility( 'custom_order_tables', __FILE__, true );
	}
} );

add_action( 'plugins_loaded', function () {
	if ( ! class_exists( 'WC_Payment_Gateway' ) ) {
		return;
	}

	class Pnakotic_Test_Gateway extends WC_Payment_Gateway {

		public function __construct() {
			$this->id                 = 'pnakotic_test';
			$this->method_title       = 'Pnakotic test card';
			$this->method_description = 'Testbed gateway: native card inputs, always declines.';
			$this->has_fields         = true;
			$this->supports           = array( 'products' );
			$this->init_form_fields();
			$this->init_settings();
			$this->title   = 'Test card (always declines)';
			$this->enabled = $this->get_option( 'enabled', 'no' );
		}

		public function init_form_fields() {
			$this->form_fields = array(
				'enabled' => array(
					'title'   => 'Enable',
					'type'    => 'checkbox',
					'label'   => 'Enable the test card gateway',
					'default' => 'no',
				),
			);
		}

		/** Classic checkout: native inputs in the payment box. */
		public function payment_fields() {
			echo pnakotic_test_card_markup(); // phpcs:ignore WordPress.Security.EscapeOutput
		}

		/** Always fails. */
		public function process_payment( $order_id ) {
			wc_add_notice( 'The test card was declined (testbed gateway always fails).', 'error' );
			return array( 'result' => 'failure' );
		}
	}

	add_filter( 'woocommerce_payment_gateways', function ( $gateways ) {
		$gateways[] = 'Pnakotic_Test_Gateway';
		return $gateways;
	} );
}, 11 );

/** Card fields markup, shared by the classic checkout (the block one builds the same in blocks.js). */
function pnakotic_test_card_markup() {
	return '<div class="pnakotic-test-card" style="display:grid;gap:8px;max-width:420px">'
		. '<input type="text" id="pnakotic-card-number" name="pnakotic_card_number" autocomplete="cc-number" inputmode="numeric" placeholder="Card number" />'
		. '<input type="text" id="pnakotic-card-exp" name="pnakotic_card_exp" autocomplete="cc-exp" inputmode="numeric" placeholder="MM / YY" />'
		. '<input type="text" id="pnakotic-card-csc" name="pnakotic_card_csc" autocomplete="cc-csc" inputmode="numeric" placeholder="CVC" />'
		. '</div>';
}

/** Block checkout integration. */
add_action( 'woocommerce_blocks_loaded', function () {
	if ( ! class_exists( '\Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType' ) ) {
		return;
	}

	class Pnakotic_Test_Blocks_Method extends \Automattic\WooCommerce\Blocks\Payments\Integrations\AbstractPaymentMethodType {

		protected $name = 'pnakotic_test';

		public function initialize() {
			$this->settings = get_option( 'woocommerce_pnakotic_test_settings', array() );
		}

		public function is_active() {
			return ! empty( $this->settings['enabled'] ) && 'yes' === $this->settings['enabled'];
		}

		public function get_payment_method_script_handles() {
			wp_register_script(
				'pnakotic-test-gateway-blocks',
				plugins_url( 'blocks.js', __FILE__ ),
				array( 'wc-blocks-registry', 'wp-element' ),
				'0.1.0',
				true
			);
			return array( 'pnakotic-test-gateway-blocks' );
		}

		public function get_payment_method_data() {
			return array(
				'title'    => 'Test card (always declines)',
				'supports' => array( 'products' ),
			);
		}
	}

	add_action( 'woocommerce_blocks_payment_method_type_registration', function ( $registry ) {
		$registry->register( new Pnakotic_Test_Blocks_Method() );
	} );
} );
