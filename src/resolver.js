/**
 * DNS resolution over HTTPS (RFC 8484 JSON flavour).
 *
 * Why DoH instead of the system resolver:
 *  - It works on networks that block or hijack outbound port 53, which is most
 *    corporate networks, a lot of hotel/airport wifi, and many CI runners.
 *  - The answer is not filtered by a local forwarder that rewrites NXDOMAIN
 *    into an ad page, which silently corrupts SPF and DMARC lookups.
 *  - It reports the DNSSEC AD flag, which the Node resolver does not expose.
 *
 * Every lookup goes through `query()` so that SPF evaluation can count DNS
 * queries exactly the way RFC 7208 counts them.
 */

/** Numeric DNS record types we care about. */
export const TYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  CAA: 257,
};

const TYPE_NAME = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]));

/** DNS RCODEs we distinguish. */
export const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 };

export const DEFAULT_PROVIDERS = [
  { name: 'cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'google', url: 'https://dns.google/resolve' },
];

/**
 * A single DNS answer set.
 * @typedef {object} DnsResult
 * @property {string} name          Queried name.
 * @property {string} type          Queried type, e.g. "TXT".
 * @property {number} status        DNS RCODE.
 * @property {string[]} values      Decoded record values.
 * @property {boolean} ad           DNSSEC "authentic data" flag.
 * @property {boolean} cached       Whether this came from the in-process cache.
 * @property {string|null} error    Transport-level error, if the query never completed.
 */

/**
 * Split a DoH TXT `data` field into its constituent character-strings and
 * concatenate them.
 *
 * A TXT record is a sequence of character-strings, each capped at 255 bytes.
 * Long records (very common for DKIM keys and big SPF records) are therefore
 * transmitted as several quoted chunks. RFC 7208 and RFC 6376 both require the
 * chunks to be joined with no separator at all. Naive parsers join them with a
 * space, which corrupts DKIM public keys and breaks SPF parsing, so this is
 * worth doing properly.
 */
export function decodeTxt(data) {
  if (typeof data !== 'string') return '';
  const trimmed = data.trim();
  if (!trimmed.includes('"')) return trimmed;

  let out = '';
  let inQuotes = false;
  let escaped = false;
  for (const ch of trimmed) {
    if (escaped) {
      out += ch;
      escaped = false;
      continue;
    }
    if (ch === '\\') {
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (inQuotes) out += ch;
  }
  return out;
}

/** Strip the trailing dot from a DNS name and lowercase it. */
export function normalizeName(name) {
  return String(name).trim().replace(/\.$/, '').toLowerCase();
}

export class Resolver {
  /**
   * @param {object} [options]
   * @param {Array<{name: string, url: string}>} [options.providers]
   * @param {number} [options.timeoutMs]
   * @param {boolean} [options.systemDns] Use the OS resolver instead of DoH.
   */
  constructor(options = {}) {
    this.providers = options.providers ?? DEFAULT_PROVIDERS;
    this.timeoutMs = options.timeoutMs ?? 8000;
    this.systemDns = options.systemDns ?? false;
    /** @type {Map<string, DnsResult>} */
    this.cache = new Map();
    this.queryCount = 0;
    this.cacheHits = 0;
  }

  /**
   * Resolve a name/type pair. Results are cached for the lifetime of the
   * resolver so that a domain referenced by several SPF includes is only
   * fetched once over the network, while still being counted once per
   * reference for RFC 7208 lookup accounting (which the caller handles).
   *
   * @param {string} name
   * @param {keyof TYPE} type
   * @returns {Promise<DnsResult>}
   */
  async query(name, type) {
    const qname = normalizeName(name);
    const key = `${qname}|${type}`;

    const hit = this.cache.get(key);
    if (hit) {
      this.cacheHits++;
      return { ...hit, cached: true };
    }

    const result = this.systemDns
      ? await this.#querySystem(qname, type)
      : await this.#queryDoh(qname, type);

    this.queryCount++;
    this.cache.set(key, result);
    return result;
  }

  async #queryDoh(qname, type) {
    let lastError = null;

    for (const provider of this.providers) {
      try {
        const url = `${provider.url}?name=${encodeURIComponent(qname)}&type=${type}`;
        const response = await fetch(url, {
          headers: { accept: 'application/dns-json' },
          signal: AbortSignal.timeout(this.timeoutMs),
        });

        if (!response.ok) {
          lastError = `${provider.name} returned HTTP ${response.status}`;
          continue;
        }

        const body = await response.json();
        const wanted = TYPE[type];
        const answers = (body.Answer ?? []).filter((a) => a.type === wanted);

        return {
          name: qname,
          type,
          status: body.Status ?? RCODE.SERVFAIL,
          values: answers.map((a) => (type === 'TXT' ? decodeTxt(a.data) : String(a.data).trim())),
          ad: Boolean(body.AD),
          cached: false,
          error: null,
        };
      } catch (err) {
        lastError = `${provider.name}: ${err.message}`;
      }
    }

    return {
      name: qname,
      type,
      status: RCODE.SERVFAIL,
      values: [],
      ad: false,
      cached: false,
      error: lastError ?? 'no DNS provider reachable',
    };
  }

  async #querySystem(qname, type) {
    const dns = await import('node:dns/promises');
    const base = { name: qname, type, ad: false, cached: false, error: null };
    try {
      if (type === 'TXT') {
        // Node hands back an array of chunk arrays; join chunks with no
        // separator, exactly as the DoH path does.
        const records = await dns.resolveTxt(qname);
        return { ...base, status: RCODE.NOERROR, values: records.map((c) => c.join('')) };
      }
      if (type === 'MX') {
        const records = await dns.resolveMx(qname);
        return {
          ...base,
          status: RCODE.NOERROR,
          values: records.map((r) => `${r.priority} ${r.exchange}`),
        };
      }
      if (type === 'A') {
        return { ...base, status: RCODE.NOERROR, values: await dns.resolve4(qname) };
      }
      if (type === 'AAAA') {
        return { ...base, status: RCODE.NOERROR, values: await dns.resolve6(qname) };
      }
      if (type === 'NS') {
        return { ...base, status: RCODE.NOERROR, values: await dns.resolveNs(qname) };
      }
      if (type === 'CNAME') {
        return { ...base, status: RCODE.NOERROR, values: await dns.resolveCname(qname) };
      }
      if (type === 'SOA') {
        const soa = await dns.resolveSoa(qname);
        return { ...base, status: RCODE.NOERROR, values: [`${soa.nsname} ${soa.hostmaster}`] };
      }
      if (type === 'CAA') {
        const records = await dns.resolveCaa(qname);
        return { ...base, status: RCODE.NOERROR, values: records.map((r) => JSON.stringify(r)) };
      }
      return { ...base, status: RCODE.SERVFAIL, values: [], error: `unsupported type ${type}` };
    } catch (err) {
      const notFound = err.code === 'ENOTFOUND' || err.code === 'ENODATA';
      return {
        ...base,
        status: notFound ? RCODE.NXDOMAIN : RCODE.SERVFAIL,
        values: [],
        error: notFound ? null : err.message,
      };
    }
  }

  /** Convenience: TXT values for a name. */
  async txt(name) {
    return this.query(name, 'TXT');
  }

  /** Parsed MX records, sorted by preference. */
  async mx(name) {
    const result = await this.query(name, 'MX');
    const hosts = result.values
      .map((value) => {
        const match = /^\s*(\d+)\s+(\S+)\s*$/.exec(value);
        if (!match) return null;
        return { preference: Number(match[1]), host: normalizeName(match[2]) };
      })
      .filter(Boolean)
      .sort((a, b) => a.preference - b.preference);
    return { ...result, hosts };
  }
}

export { TYPE_NAME };
