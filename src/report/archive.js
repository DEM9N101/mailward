/**
 * Reading the containers DMARC reports arrive in.
 *
 * Report senders use one of three shapes: bare XML, gzip, or a zip archive.
 * Node ships gzip in zlib but has no zip reader, so this walks the archive
 * structure directly. It is about a hundred lines, and it is the difference
 * between "drop the files in" and "first unzip them all by hand".
 */

import { gunzipSync, inflateRawSync, inflateSync } from 'node:zlib';

const EOCD_SIGNATURE = 0x06054b50;
const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_HEADER_SIGNATURE = 0x02014b50;

/**
 * @typedef {object} ArchiveEntry
 * @property {string} name
 * @property {Buffer} data
 */

/** True when the buffer starts with the gzip magic number. */
export function isGzip(buffer) {
  return buffer.length > 2 && buffer[0] === 0x1f && buffer[1] === 0x8b;
}

/** True when the buffer starts with a zip local file header. */
export function isZip(buffer) {
  return buffer.length > 4 && buffer.readUInt32LE(0) === LOCAL_HEADER_SIGNATURE;
}

/**
 * Extract every stored file from a zip archive.
 * @param {Buffer} buffer
 * @returns {ArchiveEntry[]}
 */
export function readZip(buffer) {
  const eocd = findEndOfCentralDirectory(buffer);
  if (eocd === -1) throw new Error('not a valid zip archive (no end-of-central-directory record)');

  const entryCount = buffer.readUInt16LE(eocd + 10);
  let offset = buffer.readUInt32LE(eocd + 16);

  /** @type {ArchiveEntry[]} */
  const entries = [];

  for (let i = 0; i < entryCount; i++) {
    if (offset + 46 > buffer.length) break;
    if (buffer.readUInt32LE(offset) !== CENTRAL_HEADER_SIGNATURE) break;

    const method = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const name = buffer.toString('utf8', offset + 46, offset + 46 + nameLength);

    offset += 46 + nameLength + extraLength + commentLength;

    // Directory entries and anything that escapes the archive root.
    if (name.endsWith('/') || name.includes('..')) continue;
    if (buffer.readUInt32LE(localOffset) !== LOCAL_HEADER_SIGNATURE) continue;

    // The local header repeats the name and extra field, and its lengths are
    // the authoritative ones for locating the data.
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLength + localExtraLength;
    const raw = buffer.subarray(dataStart, dataStart + compressedSize);

    try {
      if (method === 0) entries.push({ name, data: Buffer.from(raw) });
      else if (method === 8) entries.push({ name, data: inflateRawSync(raw) });
      // Any other method (bzip2, lzma) is vanishingly rare for DMARC and is
      // skipped rather than failing the whole archive.
    } catch {
      // A single corrupt member should not discard the rest of the archive.
    }
  }

  return entries;
}

function findEndOfCentralDirectory(buffer) {
  // The record is at the very end unless there is a trailing comment, which is
  // capped at 65535 bytes.
  const start = Math.max(0, buffer.length - 22 - 0xffff);
  for (let i = buffer.length - 22; i >= start; i--) {
    if (buffer.readUInt32LE(i) === EOCD_SIGNATURE) return i;
  }
  return -1;
}

/**
 * Decompress whatever container a report arrived in and return the XML
 * documents inside it.
 *
 * @param {Buffer} buffer
 * @param {string} [name] Original filename, used only for error messages.
 * @returns {Array<{name: string, xml: string}>}
 */
export function extractXmlDocuments(buffer, name = 'report') {
  if (isGzip(buffer)) {
    return [{ name: name.replace(/\.gz$/i, ''), xml: gunzipSync(buffer).toString('utf8') }];
  }

  if (isZip(buffer)) {
    return readZip(buffer)
      .filter((entry) => /\.xml$/i.test(entry.name) || looksLikeXml(entry.data))
      .map((entry) => ({ name: entry.name, xml: entry.data.toString('utf8') }));
  }

  // Some senders zlib-deflate without the gzip wrapper.
  if (buffer.length > 2 && buffer[0] === 0x78) {
    try {
      return [{ name, xml: inflateSync(buffer).toString('utf8') }];
    } catch {
      // fall through and treat it as plain text
    }
  }

  return [{ name, xml: buffer.toString('utf8') }];
}

function looksLikeXml(buffer) {
  const head = buffer.subarray(0, 200).toString('utf8').trimStart();
  return head.startsWith('<?xml') || head.startsWith('<feedback');
}
