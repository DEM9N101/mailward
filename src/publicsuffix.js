/**
 * Minimal registrable-domain ("organizational domain") detection.
 *
 * DMARC needs the organizational domain in order to model what a receiver does
 * when a subdomain has no policy of its own. The fully correct answer requires
 * the Public Suffix List, which is a 15,000 line file that changes constantly.
 * Bundling and syncing it would be the single largest maintenance burden in
 * this project, for a payoff that only matters on a small set of ccTLDs.
 *
 * Instead we ship the multi-label suffixes that actually show up in mail
 * configuration, and fall back to "last two labels" everywhere else. When the
 * guess is load bearing the caller says so in its output, so nobody is misled
 * by a heuristic presented as a fact.
 */

/** Second-level suffixes under which registrations happen. */
const MULTI_LABEL_SUFFIXES = new Set([
  // United Kingdom
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
  // Australia / New Zealand
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz',
  // Japan / Korea / China / India / Singapore / Hong Kong
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ad.jp', 'ed.jp', 'gr.jp', 'lg.jp',
  'co.kr', 'or.kr', 'ne.kr', 're.kr', 'pe.kr', 'go.kr', 'ac.kr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in', 'ac.in', 'edu.in',
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk', 'idv.hk',
  // Brazil / Mexico / Argentina / Latin America
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'art.br', 'blog.br',
  'com.mx', 'net.mx', 'org.mx', 'edu.mx', 'gob.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.co', 'net.co', 'org.co', 'gov.co', 'edu.co',
  // Europe
  'co.at', 'or.at', 'ac.at', 'gv.at',
  'com.es', 'org.es', 'nom.es', 'gob.es', 'edu.es',
  'com.pl', 'net.pl', 'org.pl', 'edu.pl', 'gov.pl',
  'com.pt', 'org.pt', 'edu.pt', 'gov.pt',
  'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr',
  'com.ua', 'net.ua', 'org.ua', 'gov.ua', 'edu.ua',
  'com.ru', 'net.ru', 'org.ru', 'edu.ru', 'gov.ru',
  'com.gr', 'net.gr', 'org.gr', 'edu.gr', 'gov.gr',
  'co.il', 'net.il', 'org.il', 'ac.il', 'gov.il',
  // Africa / Middle East
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'web.za',
  'co.ke', 'or.ke', 'ne.ke', 'go.ke', 'ac.ke',
  'com.ng', 'net.ng', 'org.ng', 'gov.ng', 'edu.ng',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  // North America
  'co.us', 'gov.us', 'k12.us',
  'gc.ca', 'qc.ca', 'on.ca', 'ab.ca', 'bc.ca',
]);

/**
 * Best guess at the registrable domain for `name`.
 * @param {string} name
 * @returns {{ domain: string, exact: boolean }} `exact` is false when the
 *   result came from the two-label fallback rather than a known suffix.
 */
export function organizationalDomain(name) {
  const labels = String(name).trim().replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return { domain: labels.join('.'), exact: true };

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo)) {
    return { domain: labels.slice(-3).join('.'), exact: true };
  }

  // Two labels is right for com/net/org/de/io and every other flat TLD, which
  // is the overwhelming majority of real traffic.
  return { domain: lastTwo, exact: labels.length === 3 ? false : false };
}

/** True when `name` is a subdomain of its own organizational domain. */
export function isSubdomain(name) {
  const { domain } = organizationalDomain(name);
  return normalize(name) !== domain;
}

function normalize(name) {
  return String(name).trim().replace(/\.$/, '').toLowerCase();
}
