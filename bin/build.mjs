#!/usr/bin/env node
/**
 * Release build.
 *
 * 1. Reads Version, Requires at least and Requires PHP from the plugin header.
 * 2. Writes readme.txt in wp.org format, adding the header block that file needs.
 * 3. Writes dist/simple-password-protection-<version>.zip.
 *
 * The wp.org header block is assembled here rather than kept in readme.md.
 * readme.md is what people read on GitHub, and a YAML frontmatter block renders
 * there as a stray table of release metadata above the actual description.
 *
 * Everything that also exists in the plugin header is read from it, so there is
 * one place to change a version or a minimum requirement and no second copy to
 * drift. Only the three fields wp.org asks for that have nowhere else to live
 * are declared below.
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

/**
 * wp.org readme fields with no counterpart in the plugin header.
 *
 * `tested` is the WordPress version the plugin has actually been exercised
 * against, which is a claim about testing rather than a requirement, so it has
 * no business in the plugin header.
 */
const WPORG = {
	contributors: 'thomasguillot',
	tags: 'password, password protect, private, maintenance, coming soon',
	tested: '7.0',
};

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
 * Reads one field from the plugin header block.
 *
 * @param {string} source Plugin bootstrap file contents.
 * @param {string} label  Header label, e.g. "Version" or "Requires PHP".
 * @return {string} Field value.
 */
function readHeaderField( source, label ) {
	const pattern = new RegExp(
		`^[ \\t]*\\*?[ \\t]*${ label.replace( /[.*+?^${}()|[\]\\]/g, '\\$&' ) }:[ \\t]*(.+?)[ \\t]*$`,
		'm'
	);
	const match = pattern.exec( source );

	if ( ! match ) {
		fail( `no "${ label }:" line found in ${ path.relative( ROOT, PLUGIN_FILE ) }.` );
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
 * @param {Object<string,string>} meta Header values for the wp.org block.
 * @param {string}                body Markdown body, verbatim from readme.md.
 * @return {string} readme.txt contents.
 */
function renderReadmeTxt( meta, body ) {
	const lines = body.split( /\r?\n/ );
	const titleIndex = lines.findIndex( ( line ) => /^#[ \t]+/.test( line ) );

	if ( -1 === titleIndex ) {
		fail( 'readme.md has no top-level "# " heading to use as the plugin name.' );
	}

	const title = lines[ titleIndex ].replace( /^#[ \t]+/, '' ).trim();

	const header = [
		`=== ${ title } ===`,
		`Contributors: ${ WPORG.contributors }`,
		`Tags: ${ WPORG.tags }`,
		`Requires at least: ${ meta.requires }`,
		`Tested up to: ${ WPORG.tested }`,
		`Requires PHP: ${ meta.requires_php }`,
		`Stable tag: ${ meta.version }`,
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

	const body = fs.readFileSync( README_MD, 'utf8' );
	const pluginSource = fs.readFileSync( PLUGIN_FILE, 'utf8' );

	const meta = {
		version: readHeaderField( pluginSource, 'Version' ),
		requires: readHeaderField( pluginSource, 'Requires at least' ),
		requires_php: readHeaderField( pluginSource, 'Requires PHP' ),
	};

	const version = meta.version;

	fs.writeFileSync( README_TXT, renderReadmeTxt( meta, body ), 'utf8' );
	process.stdout.write( `build: wrote ${ path.relative( ROOT, README_TXT ) }\n` );

	const zipPath = buildZip( version );
	const size = ( fs.statSync( zipPath ).size / 1024 ).toFixed( 1 );
	process.stdout.write( `build: wrote ${ path.relative( ROOT, zipPath ) } (${ size } KB)\n` );
}

main();
