/* Block checkout side of the Pnakotic test gateway. No build step. */
( function () {
	var registry = window.wc && window.wc.wcBlocksRegistry;
	var el = window.wp && window.wp.element && window.wp.element.createElement;
	if ( ! registry || ! el ) {
		return;
	}

	var title = 'Test card (always declines)';

	function input( id, name, ac, placeholder ) {
		return el( 'input', {
			type: 'text',
			id: id,
			name: name,
			autoComplete: ac,
			inputMode: 'numeric',
			placeholder: placeholder,
		} );
	}

	function Content() {
		return el(
			'div',
			{ className: 'pnakotic-test-card', style: { display: 'grid', gap: '8px', maxWidth: '420px' } },
			input( 'pnakotic-card-number', 'pnakotic_card_number', 'cc-number', 'Card number' ),
			input( 'pnakotic-card-exp', 'pnakotic_card_exp', 'cc-exp', 'MM / YY' ),
			input( 'pnakotic-card-csc', 'pnakotic_card_csc', 'cc-csc', 'CVC' )
		);
	}

	registry.registerPaymentMethod( {
		name: 'pnakotic_test',
		label: el( 'span', null, title ),
		ariaLabel: title,
		content: el( Content, null ),
		edit: el( Content, null ),
		canMakePayment: function () {
			return true;
		},
		supports: { features: [ 'products' ] },
	} );
} )();
