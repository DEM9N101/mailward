/**
 * Orchestrates a full domain audit.
 */

import { Resolver } from './resolver.js';
import { auditSpf } from './spf.js';
import { auditDmarc } from './dmarc.js';
import { auditDkim } from './dkim.js';
import { auditMx } from './mx.js';
import { auditMtaSts, auditTlsRpt, auditBimi, auditDnssec } from './policies.js';
import { buildFindings, scoreFindings } from './findings.js';

/**
 * @typedef {object} DomainAudit
 * @property {string} domain
 * @property {object} spf
 * @property {object} dmarc
 * @property {object} dkim
 * @property {object} mx
 * @property {object} mtaSts
 * @property {object} tlsRpt
 * @property {object} bimi
 * @property {object} dnssec
 */

/**
 * @param {string} domain
 * @param {object} [options]
 * @param {string[]} [options.selectors] Extra DKIM selectors to probe.
 * @param {boolean} [options.deepDkim]   Probe the full selector list.
 * @param {boolean} [options.skipDkim]
 * @param {boolean} [options.systemDns]
 * @param {number}  [options.timeoutMs]
 * @param {Resolver} [options.resolver]
 */
export async function auditDomain(domain, options = {}) {
  const name = String(domain).trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/\.$/, '').toLowerCase();
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(name)) {
    throw new Error(`"${domain}" does not look like a domain name`);
  }

  const resolver =
    options.resolver ?? new Resolver({ systemDns: options.systemDns, timeoutMs: options.timeoutMs });

  const startedAt = Date.now();

  // DMARC, SPF and MX are cheap and independent, so run them together. DKIM
  // probing is by far the slowest part and is kept separate so it can be
  // skipped without holding up everything else.
  const [dmarc, spf, mx, tlsRpt, bimi, dnssec] = await Promise.all([
    auditDmarc(name, resolver),
    auditSpf(name, resolver),
    auditMx(name, resolver),
    auditTlsRpt(name, resolver),
    auditBimi(name, resolver),
    auditDnssec(name, resolver),
  ]);

  const mtaSts = await auditMtaSts(name, resolver, { timeoutMs: options.timeoutMs });

  const dkim = options.skipDkim
    ? { domain: name, selectorsProbed: 0, userSupplied: [], keys: [], found: false, skipped: true }
    : await auditDkim(name, resolver, { selectors: options.selectors, deep: options.deepDkim });

  const audit = { domain: name, spf, dmarc, dkim, mx, mtaSts, tlsRpt, bimi, dnssec };
  const findings = buildFindings(audit);
  const score = scoreFindings(findings, {
    dmarcFound: dmarc.found,
    dmarcPolicy: dmarc.effectivePolicy,
  });

  return {
    ...audit,
    findings,
    ...score,
    meta: {
      checkedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      dnsQueries: resolver.queryCount,
      cacheHits: resolver.cacheHits,
      resolver: options.systemDns ? 'system' : 'DNS-over-HTTPS',
      tool: 'mailward',
    },
  };
}
