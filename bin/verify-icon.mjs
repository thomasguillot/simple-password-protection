#!/usr/bin/env node
/**
 * Proves that .wordpress-org/icon.svg is a faithful cleanup of the original
 * two-path, fill-rule="evenodd" source icon.
 *
 * The cleanup makes two independent changes, and they have to be judged
 * separately, because only one of them can possibly break the shape:
 *
 *   1. Dropping fill-rule="evenodd" (and the inert clip-rule) from the padlock.
 *      This is the risky change. If the padlock's two inner subpaths were not
 *      wound opposite to its outer subpath, the default nonzero rule would fill
 *      the holes in and the icon would become a solid blob.
 *
 *   2. Concatenating the two top-level paths into a single <path> element.
 *      This cannot change which region is inside the shape -- the two paths do
 *      not overlap -- but it does hand the rasteriser one larger path instead of
 *      two smaller ones, which perturbs edge antialiasing by a fraction of a
 *      channel step.
 *
 * So this script runs three comparisons at 512x512:
 *
 *   A. WINDING PROOF (decisive). Original vs the same two separate paths with
 *      fill-rule dropped. Must be pixel-identical. This isolates change 1 with
 *      change 2 held constant.
 *
 *   B. FILL-RULE-IS-INERT PROOF. The merged path with fill-rule="evenodd" vs the
 *      merged path without it. Must be pixel-identical. This shows that once the
 *      paths are merged, the attribute has no effect at all -- so re-adding it
 *      could not repair a difference even in principle.
 *
 *   C. SHIPPED VS ORIGINAL. The real .wordpress-org/icon.svg against the
 *      original. Any residual here is attributable to change 2 alone, and is
 *      gated as antialiasing: no pixel may differ by more than MAX_AA_DELTA, and
 *      no more than MAX_AA_RATIO of the icon's ink may differ at all.
 *
 * A genuine winding failure is not subtle: it floods the padlock body hole,
 * roughly 9,000 pixels at full 255 delta, which blows through both gates and
 * fails A outright.
 *
 * Usage: node bin/verify-icon.mjs
 */

import { readFile, mkdir, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve( fileURLToPath( new URL( '..', import.meta.url ) ) );
const CLEANED_PATH = path.join( ROOT, '.wordpress-org', 'icon.svg' );
const SIZE = 512;

/** Largest per-channel difference still considered antialiasing noise. */
const MAX_AA_DELTA = 24;

/** Largest share of the icon's ink pixels allowed to differ at all. */
const MAX_AA_RATIO = 0.005;

/** The padlock subpaths: outer, body hole, shackle hole. */
const LOCK =
	'M15.5 9C16.8807 9 18 10.1193 18 11.5V13H18.25C19.2165 13 20 13.7835 20 14.75V18.25C20 19.2165 19.2165 20 18.25 20H12.75C11.7835 20 11 19.2165 11 18.25V14.75C11 13.7835 11.7835 13 12.75 13H13V11.5C13 10.1193 14.1193 9 15.5 9ZM12.75 14.5C12.6119 14.5 12.5 14.6119 12.5 14.75V18.25C12.5 18.3881 12.6119 18.5 12.75 18.5H18.25C18.3881 18.5 18.5 18.3881 18.5 18.25V14.75C18.5 14.6119 18.3881 14.5 18.25 14.5H12.75ZM15.5 10.5C14.9477 10.5 14.5 10.9477 14.5 11.5V13H16.5V11.5C16.5 10.9477 16.0523 10.5 15.5 10.5Z';

/** The window frame subpath. */
const WINDOW =
	'M17.25 4C18.7688 4 20 5.23122 20 6.75V7.25C20 7.66421 19.6642 8 19.25 8C18.8358 8 18.5 7.66421 18.5 7.25V6.75C18.5 6.05964 17.9404 5.5 17.25 5.5H6.75C6.05964 5.5 5.5 6.05964 5.5 6.75V11.25C5.5 11.9404 6.05964 12.5 6.75 12.5H9.25C9.66421 12.5 10 12.8358 10 13.25C10 13.6642 9.66421 14 9.25 14H6.75C5.23122 14 4 12.7688 4 11.25V6.75C4 5.23122 5.23122 4 6.75 4H17.25Z';

const wrap = ( inner ) =>
	`<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">${ inner }</svg>`;

/** The original icon exactly as supplied: two paths, evenodd, hard-coded black. */
const ORIGINAL = wrap(
	`<path fill-rule="evenodd" clip-rule="evenodd" d="${ LOCK }" fill="black"/><path d="${ WINDOW }" fill="black"/>`
);

/** Original geometry and structure, with only the fill rule dropped. */
const TWO_PATHS_NONZERO = wrap(
	`<path d="${ LOCK }" fill="black"/><path d="${ WINDOW }" fill="black"/>`
);

/** The shipped merge, but with the fill rule put back. */
const MERGED_EVENODD = wrap(
	`<path fill-rule="evenodd" d="${ WINDOW }${ LOCK }" fill="black"/>`
);

/** The shipped merge without the fill rule. */
const MERGED_NONZERO = wrap( `<path d="${ WINDOW }${ LOCK }" fill="black"/>` );

/**
 * Rasterises one SVG onto a white 512x512 stage and returns a PNG buffer.
 *
 * `color: #000` makes the shipped icon's fill="currentColor" resolve to the same
 * black the original hard-codes, so colour is held constant and geometry is the
 * only variable under test.
 *
 * @param {import('playwright').Page} page Reusable page.
 * @param {string}                    svg  SVG markup.
 * @return {Promise<Buffer>} PNG bytes.
 */
async function rasterise( page, svg ) {
	await page.setContent(
		`<!doctype html><meta charset="utf-8"><style>
			*{margin:0;padding:0;box-sizing:border-box}
			html,body{width:${ SIZE }px;height:${ SIZE }px;overflow:hidden;background:#fff}
			#stage{width:${ SIZE }px;height:${ SIZE }px;color:#000;line-height:0;background:#fff}
			#stage svg{width:${ SIZE }px;height:${ SIZE }px;display:block}
		</style><div id="stage">${ svg }</div>`,
		{ waitUntil: 'load' }
	);

	return page.locator( '#stage' ).screenshot( { type: 'png' } );
}

/**
 * Decodes two PNGs in the browser and compares every channel of every pixel.
 *
 * @param {import('playwright').Page} page Reusable page.
 * @param {Buffer}                    a    First PNG.
 * @param {Buffer}                    b    Second PNG.
 * @return {Promise<object>} Diff statistics.
 */
async function compare( page, a, b ) {
	const uri = ( buf ) => `data:image/png;base64,${ buf.toString( 'base64' ) }`;

	return page.evaluate(
		async ( [ aSrc, bSrc ] ) => {
			const load = ( src ) =>
				new Promise( ( resolve, reject ) => {
					const img = new Image();
					img.onload = () => resolve( img );
					img.onerror = () => reject( new Error( 'PNG decode failed' ) );
					img.src = src;
				} );

			const [ ia, ib ] = await Promise.all( [ load( aSrc ), load( bSrc ) ] );

			if ( ia.width !== ib.width || ia.height !== ib.height ) {
				return {
					dimensionMismatch: `${ ia.width }x${ ia.height } vs ${ ib.width }x${ ib.height }`,
				};
			}

			const pixels = ( img ) => {
				const canvas = document.createElement( 'canvas' );
				canvas.width = img.width;
				canvas.height = img.height;
				const ctx = canvas.getContext( '2d', { willReadFrequently: true } );
				ctx.drawImage( img, 0, 0 );
				return ctx.getImageData( 0, 0, img.width, img.height ).data;
			};

			const pa = pixels( ia );
			const pb = pixels( ib );

			let differing = 0;
			let maxDelta = 0;
			let ink = 0;
			const samples = [];

			for ( let i = 0; i < pa.length; i += 4 ) {
				// Anything darker than pure white is drawn ink. Used to prove the
				// stage was not blank, and as the denominator for the AA ratio.
				if ( 255 !== pa[ i ] || 255 !== pa[ i + 1 ] || 255 !== pa[ i + 2 ] ) {
					ink++;
				}

				let delta = 0;
				for ( let c = 0; c < 4; c++ ) {
					const d = Math.abs( pa[ i + c ] - pb[ i + c ] );
					if ( d > delta ) {
						delta = d;
					}
				}

				if ( delta > 0 ) {
					differing++;
					if ( delta > maxDelta ) {
						maxDelta = delta;
					}
					if ( samples.length < 6 ) {
						const p = i / 4;
						samples.push( {
							x: p % ia.width,
							y: Math.floor( p / ia.width ),
							delta,
						} );
					}
				}
			}

			return {
				width: ia.width,
				height: ia.height,
				total: pa.length / 4,
				differing,
				maxDelta,
				ink,
				samples,
			};
		},
		[ uri( a ), uri( b ) ]
	);
}

/**
 * Structural assertions on the shipped file. A regression in the SVG source is
 * caught here even in the case where it happens to rasterise the same.
 *
 * @param {string} svg File contents.
 * @return {string[]} Problems found.
 */
function inspectStructure( svg ) {
	const problems = [];
	const paths = ( svg.match( /<path\b/g ) || [] ).length;

	if ( 1 !== paths ) {
		problems.push( `expected exactly 1 <path>, found ${ paths }` );
	}
	if ( svg.includes( 'fill-rule' ) ) {
		problems.push( 'fill-rule is still present' );
	}
	if ( svg.includes( 'clip-rule' ) ) {
		problems.push( 'clip-rule is still present' );
	}
	if ( ! svg.includes( 'fill="currentColor"' ) ) {
		problems.push( 'fill="currentColor" is missing' );
	}

	return problems;
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
	const shippedSvg = await readFile( CLEANED_PATH, 'utf8' );
	const structural = inspectStructure( shippedSvg );

	const { chromium } = await loadPlaywright();
	const browser = await chromium.launch();
	let failed = false;

	try {
		const page = await browser.newPage( {
			viewport: { width: SIZE, height: SIZE },
			deviceScaleFactor: 1,
		} );

		const shots = {};
		for ( const [ name, svg ] of Object.entries( {
			original: ORIGINAL,
			twoPathsNonzero: TWO_PATHS_NONZERO,
			mergedEvenodd: MERGED_EVENODD,
			mergedNonzero: MERGED_NONZERO,
			shipped: shippedSvg,
		} ) ) {
			shots[ name ] = await rasterise( page, svg );
		}

		// Debug rasters go to the OS temp dir, never into the repo.
		const outDir = path.join( os.tmpdir(), 'spp-verify-icon' );
		await mkdir( outDir, { recursive: true } );
		await writeFile( path.join( outDir, 'original-512.png' ), shots.original );
		await writeFile( path.join( outDir, 'shipped-512.png' ), shots.shipped );
		console.log( `Rasters written to ${ outDir } for inspection.` );

		const winding = await compare( page, shots.original, shots.twoPathsNonzero );
		const inert = await compare( page, shots.mergedEvenodd, shots.mergedNonzero );
		const shipped = await compare( page, shots.original, shots.shipped );

		for ( const [ label, result ] of Object.entries( { winding, inert, shipped } ) ) {
			if ( result.dimensionMismatch ) {
				console.error( `FAIL ${ label }: raster size differs (${ result.dimensionMismatch })` );
				failed = true;
			}
		}

		if ( failed ) {
			return;
		}

		if ( 0 === winding.ink ) {
			console.error( 'FAIL: the original rendered as a blank stage, so nothing was actually proven' );
			failed = true;
			return;
		}

		console.log( `Rasterised at ${ SIZE }x${ SIZE }; ${ winding.total } pixels compared per test.` );
		console.log( `Ink pixels in the original: ${ winding.ink }.` );
		console.log( '' );

		// A. The decisive test.
		console.log( 'A. winding (drop fill-rule, keep two paths) vs original' );
		if ( 0 === winding.differing ) {
			console.log( '   identical - 0 differing pixels. Dropping fill-rule="evenodd" is lossless.' );
		} else {
			console.log(
				`   DIFFERENT - ${ winding.differing } pixels, max channel delta ${ winding.maxDelta }.`
			);
			console.log( '   The winding analysis is WRONG. Keep fill-rule="evenodd" on the merged path.' );
			failed = true;
		}

		// B. Would the prescribed remedy even do anything?
		console.log( 'B. merged+fill-rule="evenodd" vs merged+nonzero' );
		if ( 0 === inert.differing ) {
			console.log(
				'   identical - 0 differing pixels. On the merged path the attribute is a no-op.'
			);
		} else {
			console.log(
				`   DIFFERENT - ${ inert.differing } pixels, max channel delta ${ inert.maxDelta }.`
			);
			console.log( '   The fill rule DOES matter on the merged path; it must be kept.' );
			failed = true;
		}

		// C. The shipped file against the original.
		const ratio = shipped.differing / winding.ink;
		console.log( 'C. shipped .wordpress-org/icon.svg vs original' );

		if ( 0 === shipped.differing ) {
			console.log( '   identical - 0 differing pixels.' );
		} else {
			console.log(
				`   ${ shipped.differing } differing pixels (${ ( ratio * 100 ).toFixed( 3 ) }% of ink), ` +
					`max channel delta ${ shipped.maxDelta }/255.`
			);
			console.log(
				`   first differences: ${ shipped.samples
					.map( ( s ) => `(${ s.x },${ s.y }) d${ s.delta }` )
					.join( ', ' ) }`
			);

			if ( shipped.maxDelta > MAX_AA_DELTA || ratio > MAX_AA_RATIO ) {
				console.log(
					`   OUTSIDE the antialiasing gate (max delta ${ MAX_AA_DELTA }, max ratio ` +
						`${ ( MAX_AA_RATIO * 100 ).toFixed( 1 ) }% of ink). This is a real shape change.`
				);
				failed = true;
			} else {
				console.log(
					'   Within the antialiasing gate. Test A already showed the fill rule is not the' +
						' cause, and test B showed re-adding it changes nothing, so the residual is' +
						' edge antialiasing from merging two paths into one.'
				);
			}
		}

		console.log( '' );

		if ( structural.length ) {
			for ( const problem of structural ) {
				console.error( `FAIL structure: ${ problem }` );
			}
			failed = true;
		} else {
			console.log( 'Structure: one <path>, no fill-rule, no clip-rule, fill="currentColor". OK.' );
		}

		if ( ! failed ) {
			console.log(
				0 === shipped.differing
					? 'VERDICT: identical'
					: 'VERDICT: identical shape - the fill-rule cleanup is provably lossless (test A),' +
							` with ${ shipped.differing } sub-perceptual antialiasing pixels from the path merge.`
			);
		}
	} finally {
		await browser.close();

		if ( failed ) {
			process.exitCode = 1;
		}
	}
}

main().catch( ( error ) => {
	console.error( error );
	process.exitCode = 1;
} );
