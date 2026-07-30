/**
 * DKIM key discovery and inspection (RFC 6376).
 *
 * DNS gives no way to enumerate the selectors under `_domainkey`, so no tool
 * can promise to find every key. What we can do is probe the selectors that
 * real providers actually use, and be honest that a miss means "not found",
 * never "not configured". Curating this list is the boring part that keeps a
 * tool like this useful, so it lives in one obvious place and takes patches.
 */

import { createPublicKey } from 'node:crypto';

/**
 * Selectors used by widely deployed mail providers, plus the generic names
 * people pick by hand. Sorted roughly by how often they appear in the wild.
 */
export const COMMON_SELECTORS = [
  // Big platforms
  'google', 'selector1', 'selector2', 'default', 'dkim', 'mail', 'email', 'k1', 'k2', 'k3',
  's1', 's2', 's3', 'key1', 'key2', 'smtp', 'mx',
  // Marketing and transactional providers
  'mandrill', 'mailchimp', 'sendgrid', 'smtpapi', 'amazonses', 'ses', 'sparkpost', 'scph0620',
  'postmark', 'pm', 'pm1', 'pm2', 'mailgun', 'mg', 'mailjet', 'klaviyo', 'sailthru',
  'hubspot', 'hs1', 'hs2', 'intercom', 'customerio', 'braze', 'iterable',
  // Hosted mail
  'zoho', 'zmail', 'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3',
  'yandex', 'titan1', 'titan2', 'zixvpm',
  // Support desks, commerce, CRM
  'zendesk1', 'zendesk2', 'freshdesk', 'shopify', 'shopifyemail', 'squarespace',
  'salesforce', 'pardot', 'dynamics', 'everlytickey1', 'everlytickey2',
  // Common hand-rolled patterns
  'selector', 'dkim1', 'dkim2', 'main', 'mailer', 'server', 'private',
];

/** Parse a DKIM public-key TXT record into tags. */
export function parseDkimRecord(record) {
  /** @type {Record<string, string>} */
  const tags = {};
  for (const part of String(record).split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 1) continue;
    tags[trimmed.slice(0, eq).trim().toLowerCase()] = trimmed.slice(eq + 1).trim();
  }
  return tags;
}

/**
 * Work out the key strength. RSA moduli below 1024 bits are rejected outright
 * by several large receivers, and 1024 is on the way out, so the number
 * matters more than a simple present/absent check.
 */
export function inspectKey(tags) {
  const keyType = (tags.k ?? 'rsa').toLowerCase();
  const p = (tags.p ?? '').replace(/\s+/g, '');

  if (p === '') {
    return { keyType, bits: null, revoked: true, error: null };
  }

  if (keyType === 'ed25519') {
    // Ed25519 keys are a fixed 32 bytes; treat a correct length as valid.
    const bytes = Buffer.from(p, 'base64').length;
    return { keyType, bits: 256, revoked: false, error: bytes === 32 ? null : `expected 32 key bytes, found ${bytes}` };
  }

  const der = Buffer.from(p, 'base64');
  for (const type of ['spki', 'pkcs1']) {
    try {
      const key = createPublicKey({ key: der, format: 'der', type });
      return {
        keyType,
        bits: key.asymmetricKeyDetails?.modulusLength ?? null,
        revoked: false,
        error: null,
      };
    } catch {
      // try the next encoding
    }
  }

  return { keyType, bits: null, revoked: false, error: 'public key is not valid base64 DER' };
}

/**
 * Probe selectors under `<selector>._domainkey.<domain>`.
 *
 * @param {string} domain
 * @param {import('./resolver.js').Resolver} resolver
 * @param {object} [options]
 * @param {string[]} [options.selectors] Extra selectors to try first.
 * @param {boolean} [options.deep] Probe the full built-in list rather than a fast subset.
 */
export async function auditDkim(domain, resolver, options = {}) {
  const extra = (options.selectors ?? []).map((s) => s.trim()).filter(Boolean);
  const builtin = options.deep === false ? COMMON_SELECTORS.slice(0, 24) : COMMON_SELECTORS;
  const candidates = [...new Set([...extra, ...builtin])];

  const found = [];
  const concurrency = 8;

  for (let i = 0; i < candidates.length; i += concurrency) {
    const batch = candidates.slice(i, i + concurrency);
    const results = await Promise.all(
      batch.map(async (selector) => {
        const txt = await resolver.txt(`${selector}._domainkey.${domain}`);
        const record = txt.values.find((v) => /(^|;)\s*p\s*=/.test(v) || /^v\s*=\s*DKIM1/i.test(v.trim()));
        if (!record) return null;

        const tags = parseDkimRecord(record);
        const key = inspectKey(tags);
        return {
          selector,
          record,
          tags,
          ...key,
          testing: (tags.t ?? '').split(':').map((f) => f.trim()).includes('y'),
        };
      }),
    );
    found.push(...results.filter(Boolean));
  }

  return {
    domain,
    selectorsProbed: candidates.length,
    userSupplied: extra,
    keys: found,
    found: found.length > 0,
  };
}
