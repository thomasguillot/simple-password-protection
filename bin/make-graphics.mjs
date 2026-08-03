#!/usr/bin/env node
/**
 * Renders the WordPress.org plugin icons and banners from .wordpress-org/icon.svg.
 *
 * Every asset is rendered at its own exact pixel dimensions with
 * deviceScaleFactor: 1. Nothing is rendered once and scaled -- an upscaled
 * banner shows as a soft image on a retina display in the plugin directory.
 * Instead the layout is expressed in one set of base units and multiplied
 * through a --scale custom property, so the 1544x500 banner is a genuine
 * re-render rather than a resample of the 772x250 one.
 *
 * Usage: node bin/make-graphics.mjs
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve( fileURLToPath( new URL( '..', import.meta.url ) ) );
const OUT_DIR = path.join( ROOT, '.wordpress-org' );

/** Dark neutral ground. Reads as a solid tile in the wp.org plugin grid. */
const BG = '#1b1d22';

/** Mark and wordmark. */
const FG = '#ffffff';

/** Tagline. Enough contrast to read, quiet enough not to compete. */
const MUTED = '#9aa1ad';

/** Subtle tile behind the mark on banners. Flat -- no gradient, no shadow. */
const TILE = 'rgba(255, 255, 255, 0.07)';

const FONT =
	"-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Helvetica, Arial, sans-serif";

const TITLE = 'Simple Password Protection';
const TAGLINE = 'A single shared password in front of your site.';

/** Banner layout, in base units at 772x250. Multiplied by --scale. */
const BANNER_BASE_WIDTH = 772;
const BANNER_BASE_HEIGHT = 250;

/** Icon layout, in base units at 128x128. Multiplied by --scale. */
const ICON_BASE_SIZE = 128;

const TARGETS = [
	{ kind: 'icon', file: 'icon-128x128.png', width: 128, height: 128 },
	{ kind: 'icon', file: 'icon-256x256.png', width: 256, height: 256 },
	{ kind: 'banner', file: 'banner-772x250.png', width: 772, height: 250 },
	{ kind: 'banner', file: 'banner-1544x500.png', width: 1544, height: 500 },
];

/** Shared page chrome. `u()` turns a base unit into a scaled CSS length. */
const baseStyles = ( scale ) => `
	*{margin:0;padding:0;box-sizing:border-box}
	html,body{width:100%;height:100%;overflow:hidden;background:${ BG }}
	body{
		--scale:${ scale };
		font-family:${ FONT };
		-webkit-font-smoothing:antialiased;
		text-rendering:geometricPrecision;
	}
`;

/** Converts a base unit into a scaled CSS length. */
const u = ( n ) => `calc(${ n } * var(--scale) * 1px)`;

/**
 * The icon centred on a solid ground.
 *
 * The mark's own artwork occupies 16 of the 24 viewBox units, so a 118-unit SVG
 * box on a 128-unit canvas yields a ~79-unit mark with ~25 units of clear space
 * on every side.
 *
 * @param {string} icon  Inline SVG markup.
 * @param {number} scale Multiplier against the 128px base.
 * @return {string} Full HTML document.
 */
function iconHtml( icon, scale ) {
	return `<!doctype html><meta charset="utf-8"><style>
		${ baseStyles( scale ) }
		.icon{
			width:100%;height:100%;
			display:flex;align-items:center;justify-content:center;
			color:${ FG };
		}
		.icon svg{width:${ u( 118 ) };height:${ u( 118 ) };display:block}
	</style><div class="icon">${ icon }</div>`;
}

/**
 * Mark, wordmark and tagline on a solid ground.
 *
 * @param {string} icon  Inline SVG markup.
 * @param {number} scale Multiplier against the 772x250 base.
 * @return {string} Full HTML document.
 */
function bannerHtml( icon, scale ) {
	return `<!doctype html><meta charset="utf-8"><style>
		${ baseStyles( scale ) }
		.banner{
			width:100%;height:100%;
			display:flex;align-items:center;
			padding:0 ${ u( 46 ) };
			gap:${ u( 30 ) };
		}
		.mark{
			flex:none;
			width:${ u( 106 ) };height:${ u( 106 ) };
			border-radius:${ u( 24 ) };
			background:${ TILE };
			display:flex;align-items:center;justify-content:center;
			color:${ FG };
		}
		.mark svg{width:${ u( 98 ) };height:${ u( 98 ) };display:block}
		.text{min-width:0}
		.title{
			font-size:${ u( 42 ) };
			font-weight:600;
			letter-spacing:${ u( -0.9 ) };
			line-height:1.1;
			color:${ FG };
			white-space:nowrap;
		}
		.tagline{
			margin-top:${ u( 12 ) };
			font-size:${ u( 17.5 ) };
			font-weight:400;
			line-height:1.4;
			color:${ MUTED };
			white-space:nowrap;
		}
	</style><div class="banner">
		<div class="mark">${ icon }</div>
		<div class="text">
			<div class="title">${ TITLE }</div>
			<div class="tagline">${ TAGLINE }</div>
		</div>
	</div>`;
}

/**
 * Measures the banner text so an overflow fails the build instead of silently
 * shipping a clipped wordmark.
 *
 * @param {import('playwright').Page} page Rendered banner page.
 * @return {Promise<object|null>} Measurements, or null when there is no text.
 */
async function measureBanner( page ) {
	return page.evaluate( () => {
		const banner = document.querySelector( '.banner' );
		const text = document.querySelector( '.text' );

		if ( ! banner || ! text ) {
			return null;
		}

		const styles = getComputedStyle( banner );
		const mark = document.querySelector( '.mark' );
		const available =
			banner.clientWidth -
			parseFloat( styles.paddingLeft ) -
			parseFloat( styles.paddingRight ) -
			mark.getBoundingClientRect().width -
			parseFloat( styles.columnGap || 0 );

		const widest = Math.max(
			document.querySelector( '.title' ).scrollWidth,
			document.querySelector( '.tagline' ).scrollWidth
		);

		const box = text.getBoundingClientRect();

		return {
			available: Math.round( available ),
			widest: Math.round( widest ),
			slack: Math.round( available - widest ),
			textHeight: Math.round( box.height ),
			bannerHeight: banner.clientHeight,
			docOverflowX: document.documentElement.scrollWidth > document.documentElement.clientWidth,
		};
	} );
}

async function loadPlaywright() {
	try {
		return await import( 'playwright' );
	} catch ( error ) {
		console.error( 'Could not load playwright. Install it with:' );
		console.error( '  npm install --no-save playwright' );
		throw error;
	}
}

async function main() {
	const icon = ( await readFile( path.join( OUT_DIR, 'icon.svg' ), 'utf8' ) ).trim();

	await mkdir( OUT_DIR, { recursive: true } );

	const { chromium } = await loadPlaywright();
	const browser = await chromium.launch();

	try {
		for ( const target of TARGETS ) {
			const page = await browser.newPage( {
				viewport: { width: target.width, height: target.height },
				deviceScaleFactor: 1,
			} );

			const isBanner = 'banner' === target.kind;
			const scale = isBanner
				? target.width / BANNER_BASE_WIDTH
				: target.width / ICON_BASE_SIZE;

			await page.setContent(
				isBanner ? bannerHtml( icon, scale ) : iconHtml( icon, scale ),
				{ waitUntil: 'load' }
			);

			await page.evaluate( () => document.fonts.ready );

			if ( isBanner ) {
				const m = await measureBanner( page );

				if ( ! m ) {
					throw new Error( `${ target.file }: banner markup did not render` );
				}

				console.log(
					`  text ${ m.widest }px in ${ m.available }px (slack ${ m.slack }px), ` +
						`block ${ m.textHeight }px in ${ m.bannerHeight }px`
				);

				if ( m.slack < 0 ) {
					throw new Error(
						`${ target.file }: text overflows by ${ -m.slack }px. Reduce the type size or padding.`
					);
				}

				if ( m.textHeight > m.bannerHeight ) {
					throw new Error( `${ target.file }: text block is taller than the banner.` );
				}

				if ( m.docOverflowX ) {
					throw new Error( `${ target.file }: document scrolls horizontally, content is clipped.` );
				}
			}

			const buffer = await page.screenshot( { type: 'png' } );
			await writeFile( path.join( OUT_DIR, target.file ), buffer );

			// Confirm the encoded PNG really carries the requested dimensions,
			// read straight from the IHDR chunk rather than trusted from config.
			const encodedWidth = buffer.readUInt32BE( 16 );
			const encodedHeight = buffer.readUInt32BE( 20 );

			if ( encodedWidth !== target.width || encodedHeight !== target.height ) {
				throw new Error(
					`${ target.file }: wrote ${ encodedWidth }x${ encodedHeight }, expected ` +
						`${ target.width }x${ target.height }`
				);
			}

			console.log( `${ target.file } ${ encodedWidth }x${ encodedHeight }` );

			await page.close();
		}
	} finally {
		await browser.close();
	}
}

main().catch( ( error ) => {
	console.error( error.message || error );
	process.exitCode = 1;
} );
