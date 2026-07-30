/**
 * A small XML reader, sized for DMARC aggregate reports.
 *
 * Pulling in a general XML library would mean a dependency tree larger than
 * this entire project, for a document format that is a few nested elements
 * with no namespaces, no DTDs and no mixed content. So we parse it directly.
 *
 * This is deliberately not a general purpose XML parser and does not pretend
 * to be one. It handles the subset that report generators actually emit.
 */

/**
 * @typedef {object} XmlNode
 * @property {string} name
 * @property {Record<string,string>} attrs
 * @property {XmlNode[]} children
 * @property {string} text
 */

/**
 * @param {string} source
 * @returns {XmlNode} the root element
 */
export function parseXml(source) {
  // Written as an escape rather than a literal U+FEFF so the character does
  // not sit invisibly in the source and trip byte order mark checks.
  const input = String(source).replace(/^\uFEFF/, '');
  let index = 0;

  /** @type {XmlNode[]} */
  const stack = [];
  /** @type {XmlNode|null} */
  let root = null;

  const makeNode = (name, attrs) => ({ name, attrs, children: [], text: '' });

  while (index < input.length) {
    const lt = input.indexOf('<', index);
    if (lt === -1) break;

    // Text content belonging to the currently open element.
    if (lt > index && stack.length > 0) {
      stack[stack.length - 1].text += decodeEntities(input.slice(index, lt));
    }

    // Comments, declarations, doctypes and processing instructions.
    if (input.startsWith('<!--', lt)) {
      const end = input.indexOf('-->', lt);
      index = end === -1 ? input.length : end + 3;
      continue;
    }
    if (input.startsWith('<![CDATA[', lt)) {
      const end = input.indexOf(']]>', lt);
      const content = input.slice(lt + 9, end === -1 ? input.length : end);
      if (stack.length > 0) stack[stack.length - 1].text += content;
      index = end === -1 ? input.length : end + 3;
      continue;
    }
    if (input.startsWith('<?', lt) || input.startsWith('<!', lt)) {
      const end = input.indexOf('>', lt);
      index = end === -1 ? input.length : end + 1;
      continue;
    }

    const gt = findTagEnd(input, lt);
    if (gt === -1) break;
    const raw = input.slice(lt + 1, gt).trim();

    if (raw.startsWith('/')) {
      const name = raw.slice(1).trim();
      // Tolerate mismatched closing tags rather than throwing: a truncated
      // report is still worth reading as far as it goes.
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].name === name) {
          stack.length = i;
          break;
        }
      }
      index = gt + 1;
      continue;
    }

    const selfClosing = raw.endsWith('/');
    const body = selfClosing ? raw.slice(0, -1).trim() : raw;
    const spaceAt = body.search(/\s/);
    const name = spaceAt === -1 ? body : body.slice(0, spaceAt);
    const attrs = spaceAt === -1 ? {} : parseAttributes(body.slice(spaceAt + 1));

    const node = makeNode(name, attrs);
    if (stack.length > 0) stack[stack.length - 1].children.push(node);
    else if (root === null) root = node;

    if (!selfClosing) stack.push(node);
    index = gt + 1;
  }

  if (!root) throw new Error('no XML element found');
  return root;
}

/** Find the ">" that closes a tag, skipping any inside quoted attributes. */
function findTagEnd(input, start) {
  let quote = null;
  for (let i = start + 1; i < input.length; i++) {
    const ch = input[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '>') return i;
  }
  return -1;
}

function parseAttributes(source) {
  /** @type {Record<string,string>} */
  const attrs = {};
  const pattern = /([^\s=]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s]+))/g;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    attrs[match[1]] = decodeEntities(match[3] ?? match[4] ?? match[5] ?? '');
  }
  return attrs;
}

function decodeEntities(text) {
  return text.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (whole, entity) => {
    const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
    const lower = entity.toLowerCase();
    if (lower in named) return named[lower];
    if (lower.startsWith('#x')) return safeCodePoint(parseInt(entity.slice(2), 16));
    if (lower.startsWith('#')) return safeCodePoint(parseInt(entity.slice(1), 10));
    return whole;
  });
}

function safeCodePoint(value) {
  if (!Number.isFinite(value) || value < 0 || value > 0x10ffff) return '';
  try {
    return String.fromCodePoint(value);
  } catch {
    return '';
  }
}

/* ------------------------------------------------------------- Accessors */

/** First direct child with the given name. */
export function child(node, name) {
  return node?.children.find((c) => c.name === name) ?? null;
}

/** All direct children with the given name. */
export function children(node, name) {
  return node?.children.filter((c) => c.name === name) ?? [];
}

/** Trimmed text of a descendant addressed by a path, e.g. text(root, 'a', 'b'). */
export function text(node, ...path) {
  let current = node;
  for (const name of path) {
    current = child(current, name);
    if (!current) return '';
  }
  return current.text.trim();
}
