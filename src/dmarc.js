/**
 * DMARC record parsing and validation (RFC 7489).
 *
 * Two checks here are missing from most free tools and are exactly the ones
 * that cause silent failure:
 *
 *  1. Organizational domain fallback. A subdomain with no record of its own
 *     inherits the parent policy, and `sp=` on the parent overrides `p=` for
 *     it. People frequently publish a strict parent policy and then wonder why
 *     a subdomain still gets spoofed, or the reverse.
 *
 *  2. External destination authorization. If `rua=` points at a mailbox on a
 *     different domain, that domain has to publish an authorisation record
 *     (`<you>._report._dmarc.<them>`) or conforming receivers will not send
 *     reports at all. This is the usual reason someone deploys DMARC, waits a
 *     month, and receives nothing.
 */

import { organizationalDomain } from './publicsuffix.js';

const VALID_POLICIES = new Set(['none', 'quarantine', 'reject']);
const VALID_ALIGNMENT = new Set(['r', 's']);
const KNOWN_TAGS = new Set(['v', 'p', 'sp', 'rua', 'ruf', 'pct', 'adkim', 'aspf', 'fo', 'rf', 'ri', 'np']);

/**
 * Parse a DMARC record string into tags plus syntax problems.
 * @param {string} record
 */
export function parseDmarcRecord(record) {
  /** @type {Record<string, string>} */
  const tags = {};
  const errors = [];
  const order = [];

  const parts = String(record)
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean);

  for (const part of parts) {
    const match = /^([a-z][a-z0-9]*)\s*=\s*(.*)$/i.exec(part);
    if (!match) {
      errors.push(`"${part}" is not a valid tag=value pair`);
      continue;
    }
    const name = match[1].toLowerCase();
    const value = match[2].trim();
    if (name in tags) {
      errors.push(`tag "${name}" appears more than once`);
      continue;
    }
    tags[name] = value;
    order.push(name);
    if (!KNOWN_TAGS.has(name)) errors.push(`unknown tag "${name}" (receivers ignore it)`);
  }

  if (order[0] !== 'v') errors.push('the "v=DMARC1" tag must come first');
  if (tags.v !== undefined && tags.v.toUpperCase() !== 'DMARC1') {
    errors.push(`version must be "DMARC1", found "${tags.v}"`);
  }

  if (tags.p === undefined) {
    errors.push('required tag "p" is missing; the whole record is ignored without it');
  } else if (!VALID_POLICIES.has(tags.p.toLowerCase())) {
    errors.push(`policy "p=${tags.p}" is invalid; use none, quarantine or reject`);
  }

  if (tags.sp !== undefined && !VALID_POLICIES.has(tags.sp.toLowerCase())) {
    errors.push(`subdomain policy "sp=${tags.sp}" is invalid`);
  }

  if (tags.pct !== undefined) {
    const pct = Number(tags.pct);
    if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
      errors.push(`"pct=${tags.pct}" must be a whole number between 0 and 100`);
    }
  }

  for (const tag of ['adkim', 'aspf']) {
    if (tags[tag] !== undefined && !VALID_ALIGNMENT.has(tags[tag].toLowerCase())) {
      errors.push(`"${tag}=${tags[tag]}" must be r (relaxed) or s (strict)`);
    }
  }

  if (tags.ri !== undefined && !/^\d+$/.test(tags.ri)) {
    errors.push(`"ri=${tags.ri}" must be a number of seconds`);
  }

  const rua = parseUriList(tags.rua, errors, 'rua');
  const ruf = parseUriList(tags.ruf, errors, 'ruf');

  return {
    tags,
    errors,
    policy: tags.p?.toLowerCase() ?? null,
    subdomainPolicy: tags.sp?.toLowerCase() ?? null,
    pct: tags.pct !== undefined ? Number(tags.pct) : 100,
    adkim: tags.adkim?.toLowerCase() ?? 'r',
    aspf: tags.aspf?.toLowerCase() ?? 'r',
    interval: tags.ri !== undefined ? Number(tags.ri) : 86400,
    rua,
    ruf,
  };
}

function parseUriList(value, errors, tagName) {
  if (!value) return [];
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      // Optional size limit suffix, e.g. mailto:a@b.com!10m
      const [uri, limit] = entry.split('!');
      if (!/^mailto:/i.test(uri)) {
        errors.push(`"${tagName}" entry "${entry}" is not a mailto: URI`);
        return { uri: entry, address: null, domain: null, limit: limit ?? null };
      }
      const address = uri.slice(uri.indexOf(':') + 1).trim();
      const at = address.lastIndexOf('@');
      if (at < 1) {
        errors.push(`"${tagName}" entry "${entry}" has no valid email address`);
        return { uri, address, domain: null, limit: limit ?? null };
      }
      return {
        uri,
        address,
        domain: address.slice(at + 1).toLowerCase().replace(/\.$/, ''),
        limit: limit ?? null,
      };
    });
}

/**
 * Look up and analyse DMARC for a domain.
 * @param {string} domain
 * @param {import('./resolver.js').Resolver} resolver
 */
export async function auditDmarc(domain, resolver) {
  const result = {
    domain,
    recordName: `_dmarc.${domain}`,
    found: false,
    inheritedFrom: null,
    record: null,
    records: [],
    parsed: null,
    errors: [],
    externalDestinations: [],
    effectivePolicy: null,
    dnsError: null,
  };

  const direct = await resolver.txt(`_dmarc.${domain}`);
  result.dnsError = direct.error;
  let records = direct.values.filter((v) => /^v=DMARC1\s*;/i.test(v.trim()));

  // Subdomain with no record of its own: receivers fall back to the
  // organizational domain and apply its sp= (or p=) to us.
  const org = organizationalDomain(domain);
  if (records.length === 0 && org.domain && org.domain !== domain) {
    const parent = await resolver.txt(`_dmarc.${org.domain}`);
    const parentRecords = parent.values.filter((v) => /^v=DMARC1\s*;/i.test(v.trim()));
    if (parentRecords.length > 0) {
      records = parentRecords;
      result.inheritedFrom = org.domain;
      result.recordName = `_dmarc.${org.domain}`;
    }
  }

  result.records = records;
  result.found = records.length > 0;
  if (!result.found) return result;

  result.record = records[0];
  result.parsed = parseDmarcRecord(result.record);
  result.errors = [...result.parsed.errors];

  if (records.length > 1) {
    result.errors.push(
      `${records.length} DMARC records published at ${result.recordName}; receivers treat this as no policy at all`,
    );
  }

  // When inherited, the subdomain policy tag is what actually applies to us.
  result.effectivePolicy = result.inheritedFrom
    ? result.parsed.subdomainPolicy ?? result.parsed.policy
    : result.parsed.policy;

  result.externalDestinations = await verifyExternalDestinations(domain, result.parsed, resolver);

  return result;
}

/**
 * For every rua/ruf address hosted on another domain, check that the receiving
 * domain has authorised us. Without it, RFC 7489 section 7.1 says reports must
 * not be sent.
 */
async function verifyExternalDestinations(domain, parsed, resolver) {
  const destinations = [...parsed.rua.map((u) => ({ ...u, tag: 'rua' })), ...parsed.ruf.map((u) => ({ ...u, tag: 'ruf' }))];
  const org = organizationalDomain(domain).domain;
  const checked = [];

  for (const destination of destinations) {
    if (!destination.domain) continue;

    const destOrg = organizationalDomain(destination.domain).domain;
    if (destOrg === org) {
      checked.push({ ...destination, external: false, authorized: true, checkedName: null });
      continue;
    }

    const checkedName = `${domain}._report._dmarc.${destination.domain}`;
    const txt = await resolver.txt(checkedName);
    const authorized = txt.values.some((v) => /^v=DMARC1/i.test(v.trim()));

    // Some providers authorise the organizational domain instead of the exact
    // subdomain, which conforming receivers also accept.
    let fallbackName = null;
    let fallbackOk = false;
    if (!authorized && org !== domain) {
      fallbackName = `${org}._report._dmarc.${destination.domain}`;
      const fallback = await resolver.txt(fallbackName);
      fallbackOk = fallback.values.some((v) => /^v=DMARC1/i.test(v.trim()));
    }

    checked.push({
      ...destination,
      external: true,
      authorized: authorized || fallbackOk,
      checkedName: authorized ? checkedName : fallbackName ?? checkedName,
      dnsError: txt.error,
    });
  }

  return checked;
}
