#!/usr/bin/env node
/**
 * Release build.
 *
 * 1. Parses the YAML frontmatter in readme.md.
 * 2. Reads Version: from the plugin header, the single source of truth.
 * 3. Fails hard when stable_tag and the plugin version disagree.
 * 4. Writes readme.txt in wp.org format.
 * 5. Writes dist/simple-password-protection-<version>.zip.
 *
 * Pure Node 22 plus the system `zip` binary. No npm dependencies.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve( fileURLToPath( new URL( '..', import.meta.url ) ) );
const SLUG = 'simple-password-protection';

const README_MD = path.join( ROOT, 'readme.md' );
const README_TXT = path.join( ROOT, 'readme.txt' );
const PLUGIN_FILE = path.join( ROOT, `${ SLUG }.php` );
const DIST = path.join( ROOT, 'dist' );
const STAGE = path.join( DIST, '.stage' );

const REQUIRED_KEYS = [ 'contributors', 'tags', 'requires', 'tested', 'requires_php', 'stable_tag' ];

const LICENSE = 'GPLv2 or later';
const LICENSE_URI = 'https://www.gnu.org/licenses/gpl-2.0.html';

/**
 * Names never copied into the release zip, matched at any depth.
 * Anything starting with a dot is excluded as well, which covers
 * .git, .github, .wordpress-org, .gitignore and .DS_Store.
 */
const EXCLUDE = new Set( [
	'.git',
	'.github',
	'node_modules',
	'vendor',
	'tests',
	'bin',
	'docs',
	'.wordpress-org',
	'dist',
	'readme.md',
	'composer.json',
	'composer.lock',
	'package.json',
	'package-lock.json',
	'phpunit.xml.dist',
	'.gitignore',
	'.DS_Store',
] );

/**
 * Prints an error and exits non-zero.
 *
 * @param {string} message Reason for the failure.
 */
function fail( message ) {
	process.stderr.write( `build: ${ message }\n` );
	process.exit( 1 );
}

/**
 * Splits a document into its YAML frontmatter and the remaining body.
 *
 * @param {string} source Full readme.md contents.
 * @return {{data: Object<string,string>, body: string}} Parsed frontmatter and body.
 */
function parseFrontmatter( source ) {
	const match = /^---\r?\n([\s\S]*?)\r?\n---[ \t]*\r?\n?/.exec( source );

	if ( ! match ) {
		fail( 'readme.md does not start with a YAML frontmatter block.' );
	}

	const data = {};

	for ( const rawLine of match[ 1 ].split( /\r?\n/ ) ) {
		const line = rawLine.trim();

		if ( '' === line || line.startsWith( '#' ) ) {
			continue;
		}

		const separator = line.indexOf( ':' );

		if ( -1 === separator ) {
			fail( `unparseable frontmatter line: ${ line }` );
		}

		const key = line.slice( 0, separator ).trim();
		let value = line.slice( separator + 1 ).trim();

		if (
			( value.startsWith( '"' ) && value.endsWith( '"' ) && value.length > 1 ) ||
			( value.startsWith( "'" ) && value.endsWith( "'" ) && value.length > 1 )
		) {
			value = value.slice( 1, -1 );
		}

		data[ key ] = value;
	}

	return { data, body: source.slice( match[ 0 ].length ) };
}

/**
 * Reads the Version: field from the plugin header.
 *
 * @param {string} source Plugin bootstrap file contents.
 * @return {string} Version string.
 */
function readPluginVersion( source ) {
	const match = /^[ \t]*\*?[ \t]*Version:[ \t]*(.+?)[ \t]*$/m.exec( source );

	if ( ! match ) {
		fail( `no "Version:" line found in ${ path.relative( ROOT, PLUGIN_FILE ) }.` );
	}

	return match[ 1 ];
}

/**
 * Converts the markdown body to the wp.org readme dialect.
 *
 * Headings become = wrapped = sections and fenced code blocks become
 * four-space indented blocks. Heading syntax inside a fence is left alone.
 *
 * @param {string[]} lines Body lines, excluding the title heading.
 * @return {string[]} Converted lines.
 */
function convertBody( lines ) {
	const out = [];
	let inFence = false;

	for ( const line of lines ) {
		if ( /^[ \t]*(```|~~~)/.test( line ) ) {
			if ( ! inFence ) {
				// A code block needs a blank line above it to be recognised.
				while ( out.length && '' === out[ out.length - 1 ] ) {
					out.pop();
				}

				if ( out.length ) {
					out.push( '' );
				}

				inFence = true;
			} else {
				inFence = false;
				out.push( '' );
			}

			continue;
		}

		if ( inFence ) {
			out.push( '' === line.trim() ? '' : `    ${ line }` );
			continue;
		}

		if ( /^###[ \t]+/.test( line ) ) {
			out.push( `= ${ line.replace( /^###[ \t]+/, '' ).trim() } =` );
		} else if ( /^##[ \t]+/.test( line ) ) {
			out.push( `== ${ line.replace( /^##[ \t]+/, '' ).trim() } ==` );
		} else if ( /^#[ \t]+/.test( line ) ) {
			out.push( `=== ${ line.replace( /^#[ \t]+/, '' ).trim() } ===` );
		} else {
			out.push( line );
		}
	}

	if ( inFence ) {
		fail( 'readme.md has an unclosed fenced code block.' );
	}

	// Collapse runs of blank lines and trim the ends.
	const collapsed = [];

	for ( const line of out ) {
		if ( '' === line && '' === collapsed[ collapsed.length - 1 ] ) {
			continue;
		}

		collapsed.push( line );
	}

	while ( collapsed.length && '' === collapsed[ 0 ] ) {
		collapsed.shift();
	}

	while ( collapsed.length && '' === collapsed[ collapsed.length - 1 ] ) {
		collapsed.pop();
	}

	return collapsed;
}

/**
 * Renders the full readme.txt.
 *
 * @param {Object<string,string>} front   Frontmatter values.
 * @param {string}                body    Markdown body.
 * @return {string} readme.txt contents.
 */
function renderReadmeTxt( front, body ) {
	const lines = body.split( /\r?\n/ );
	const titleIndex = lines.findIndex( ( line ) => /^#[ \t]+/.test( line ) );

	if ( -1 === titleIndex ) {
		fail( 'readme.md has no top-level "# " heading to use as the plugin name.' );
	}

	const title = lines[ titleIndex ].replace( /^#[ \t]+/, '' ).trim();

	const header = [
		`=== ${ title } ===`,
		`Contributors: ${ front.contributors }`,
		`Tags: ${ front.tags }`,
		`Requires at least: ${ front.requires }`,
		`Tested up to: ${ front.tested }`,
		`Requires PHP: ${ front.requires_php }`,
		`Stable tag: ${ front.stable_tag }`,
		`License: ${ LICENSE }`,
		`License URI: ${ LICENSE_URI }`,
		'',
	];

	return `${ header.concat( convertBody( lines.slice( titleIndex + 1 ) ) ).join( '\n' ) }\n`;
}

/**
 * Whether a directory entry is kept out of the release zip.
 *
 * @param {string} name Entry basename.
 * @return {boolean} True when the entry must be skipped.
 */
function isExcluded( name ) {
	return EXCLUDE.has( name ) || name.startsWith( '.' );
}

/**
 * Recursively copies a directory, honouring the exclusion list.
 *
 * @param {string}   from    Source directory.
 * @param {string}   to      Destination directory.
 * @param {string[]} copied  Accumulator of copied relative paths.
 * @return {string[]} The accumulator.
 */
function copyTree( from, to, copied ) {
	fs.mkdirSync( to, { recursive: true } );

	for ( const entry of fs.readdirSync( from, { withFileTypes: true } ) ) {
		if ( isExcluded( entry.name ) ) {
			continue;
		}

		const source = path.join( from, entry.name );
		const target = path.join( to, entry.name );

		if ( entry.isDirectory() ) {
			copyTree( source, target, copied );
		} else if ( entry.isFile() ) {
			fs.copyFileSync( source, target );
			copied.push( path.relative( ROOT, source ) );
		}
	}

	return copied;
}

/**
 * Stages the plugin under a single top-level directory and zips it.
 *
 * @param {string} version Plugin version, used in the archive name.
 * @return {string} Path to the archive.
 */
function buildZip( version ) {
	const zipPath = path.join( DIST, `${ SLUG }-${ version }.zip` );

	fs.rmSync( STAGE, { recursive: true, force: true } );
	fs.rmSync( zipPath, { force: true } );
	fs.mkdirSync( DIST, { recursive: true } );

	const copied = copyTree( ROOT, path.join( STAGE, SLUG ), [] );

	if ( ! copied.length ) {
		fail( 'nothing to package: every file was excluded.' );
	}

	try {
		execFileSync( 'zip', [ '-r', '-q', '-X', zipPath, SLUG ], { cwd: STAGE } );
	} catch ( error ) {
		fail( `zip failed: ${ error.message }` );
	} finally {
		fs.rmSync( STAGE, { recursive: true, force: true } );
	}

	return zipPath;
}

function main() {
	if ( ! fs.existsSync( README_MD ) ) {
		fail( 'readme.md not found.' );
	}

	if ( ! fs.existsSync( PLUGIN_FILE ) ) {
		fail( `${ SLUG }.php not found.` );
	}

	const { data: front, body } = parseFrontmatter( fs.readFileSync( README_MD, 'utf8' ) );

	const missing = REQUIRED_KEYS.filter( ( key ) => ! ( key in front ) || '' === String( front[ key ] ).trim() );

	if ( missing.length ) {
		fail( `readme.md frontmatter is missing required key(s): ${ missing.join( ', ' ) }` );
	}

	const version = readPluginVersion( fs.readFileSync( PLUGIN_FILE, 'utf8' ) );

	if ( front.stable_tag !== version ) {
		fail(
			`stable_tag "${ front.stable_tag }" in readme.md does not match Version "${ version }" ` +
				`in ${ SLUG }.php. Make them the same and build again.`
		);
	}

	fs.writeFileSync( README_TXT, renderReadmeTxt( front, body ), 'utf8' );
	process.stdout.write( `build: wrote ${ path.relative( ROOT, README_TXT ) }\n` );

	const zipPath = buildZip( version );
	const size = ( fs.statSync( zipPath ).size / 1024 ).toFixed( 1 );
	process.stdout.write( `build: wrote ${ path.relative( ROOT, zipPath ) } (${ size } KB)\n` );
}

main();
