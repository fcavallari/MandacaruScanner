/* Block checkout side of the Mandacaru test gateway. No build step. */
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
			{ className: 'mandacaru-test-card', style: { display: 'grid', gap: '8px', maxWidth: '420px' } },
			input( 'mandacaru-card-number', 'mandacaru_card_number', 'cc-number', 'Card number' ),
			input( 'mandacaru-card-exp', 'mandacaru_card_exp', 'cc-exp', 'MM / YY' ),
			input( 'mandacaru-card-csc', 'mandacaru_card_csc', 'cc-csc', 'CVC' )
		);
	}

	registry.registerPaymentMethod( {
		name: 'mandacaru_test',
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
