#!/usr/bin/env node
/**
 * Fail if any text file starts with a UTF-8 byte order mark.
 *
 * A BOM in front of the shebang stops the kernel recognising bin/mailward.js
 * as a script, so an installed CLI fails to run on Linux and macOS with a
 * confusing error. `node --check` rejects the file outright. Windows editors
 * and PowerShell's default UTF8 encoding both add one without being asked.
 *
 * This checks the first three bytes only. A U+FEFF elsewhere in a file can be
 * entirely legitimate, for instance inside a regular expression that strips
 * one from input.
 */

import { readdir, open } from 'node:fs/promises';
import { join, extname } from 'node:path';

const CHECKED = new Set(['.js', '.json', '.md', '.yml', '.yaml', '.xml', '.txt']);
const SKIP = new Set(['.git', 'node_modules', 'coverage']);

async function* walk(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) yield* walk(full);
    else if (CHECKED.has(extname(entry.name).toLowerCase())) yield full;
  }
}

async function startsWithBom(path) {
  const handle = await open(path, 'r');
  try {
    const { buffer, bytesRead } = await handle.read(Buffer.alloc(3), 0, 3, 0);
    return bytesRead === 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf;
  } finally {
    await handle.close();
  }
}

const root = process.argv[2] ?? '.';
const offenders = [];

for await (const file of walk(root)) {
  if (await startsWithBom(file)) offenders.push(file);
}

if (offenders.length > 0) {
  console.error('These files start with a UTF-8 byte order mark:');
  for (const file of offenders) console.error(`  ${file}`);
  console.error('\nRe-save them as UTF-8 without a BOM.');
  process.exit(1);
}

console.log('No byte order marks.');
