/**
 * Settings screen behaviour.
 *
 * Password generation, the strength meter, the show/hide toggle and the
 * weak-password confirmation all come from core's `user-profile` script, which
 * binds to the `.user-pass1-wrap` and `.pw-weak` rows. Do not reimplement any of
 * them here — doing so double-binds the handlers.
 *
 * @package SimplePasswordProtection
 */

( function ( $ ) {
	'use strict';

	var l10n = window.sppAdmin || {};

	$( function () {
		var frame;

		// Swap the status line for the storage caveat while a password is
		// actually on screen. Core owns the generate/cancel buttons themselves;
		// these handlers run alongside its own.
		var $status = $( '#spp-password-status' );
		var $note = $( '#spp-password-note' );

		$( '.wp-generate-pw' ).on( 'click', function () {
			$status.hide();
			$note.removeClass( 'hide-if-js' ).show();
		} );

		$( '.wp-cancel-pw' ).on( 'click', function () {
			$note.hide();
			$status.show();
		} );

		var $id = $( '#spp-logo-id' );
		var $preview = $( '#spp-logo-preview' );
		var $remove = $( '#spp-logo-remove' );

		$( '#spp-logo-select' ).on( 'click', function ( event ) {
			event.preventDefault();

			if ( frame ) {
				frame.open();
				return;
			}

			frame = window.wp.media( {
				title: l10n.mediaTitle,
				button: { text: l10n.mediaButton },
				library: { type: 'image' },
				multiple: false,
			} );

			frame.on( 'select', function () {
				var attachment = frame.state().get( 'selection' ).first().toJSON();
				var url = attachment.url;

				// Prefer a scaled size for the preview when one exists.
				if ( attachment.sizes && attachment.sizes.medium ) {
					url = attachment.sizes.medium.url;
				}

				$id.val( attachment.id );
				$preview.find( 'img' ).attr( 'src', url );
				$preview.prop( 'hidden', false );
				$remove.prop( 'hidden', false );
			} );

			frame.open();
		} );

		$remove.on( 'click', function ( event ) {
			event.preventDefault();

			$id.val( 0 );
			$preview.prop( 'hidden', true );
			$preview.find( 'img' ).attr( 'src', '' );
			$remove.prop( 'hidden', true );
		} );

		// The generated password is readable exactly once, so copying must be
		// a single click.
		if ( typeof window.ClipboardJS === 'function' ) {
			var clipboard = new window.ClipboardJS( '#spp-copy-pw', {
				text: function () {
					var field = document.getElementById( 'pass1' );
					return field ? field.value : '';
				},
			} );

			clipboard.on( 'success', function ( event ) {
				var $label = $( '#spp-copy-pw' ).find( '.text' );
				var original = l10n.copy || $label.text();

				event.clearSelection();
				$label.text( l10n.copied );

				if ( window.wp && window.wp.a11y ) {
					window.wp.a11y.speak( l10n.copied );
				}

				window.setTimeout( function () {
					$label.text( original );
				}, 2000 );
			} );
		}
	} );
} )( jQuery );
