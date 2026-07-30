/**
 * The transport and branding layer: MTA-STS, TLS-RPT, BIMI and DNSSEC.
 *
 * SPF, DKIM and DMARC prove who wrote a message. These prove the connection
 * carrying it was not quietly downgraded to plaintext, and that the reports
 * telling you so can reach you.
 */

/**
 * MTA-STS (RFC 8461). The DNS record only announces a policy id; the policy
 * itself is served over HTTPS, and a broken or expired certificate on the
 * policy host disables the whole mechanism without any DNS-visible symptom.
 *
 * @param {string} domain
 * @param {import('./resolver.js').Resolver} resolver
 * @param {object} [options]
 * @param {number} [options.timeoutMs]
 */
export async function auditMtaSts(domain, resolver, options = {}) {
  const timeoutMs = options.timeoutMs ?? 8000;
  const result = {
    domain,
    found: false,
    id: null,
    record: null,
    policy: null,
    policyUrl: `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
    policyError: null,
    mode: null,
    maxAge: null,
    mxPatterns: [],
    errors: [],
  };

  const txt = await resolver.txt(`_mta-sts.${domain}`);
  const record = txt.values.find((v) => /^v\s*=\s*STSv1/i.test(v.trim()));
  if (!record) return result;

  result.found = true;
  result.record = record;
  const tags = parseKeyValue(record, ';');
  result.id = tags.id ?? null;
  if (!result.id) result.errors.push('MTA-STS record has no "id" tag');

  try {
    const response = await fetch(result.policyUrl, {
      signal: AbortSignal.timeout(timeoutMs),
      redirect: 'error', // RFC 8461: the policy must be served directly, no redirects
      headers: { accept: 'text/plain' },
    });
    if (!response.ok) {
      result.policyError = `policy host returned HTTP ${response.status}`;
      return result;
    }
    const body = await response.text();
    result.policy = body;

    const policyTags = parseKeyValue(body, '\n');
    result.mode = (policyTags.mode ?? '').toLowerCase() || null;
    result.maxAge = policyTags.max_age ? Number(policyTags.max_age) : null;
    result.mxPatterns = [...body.matchAll(/^\s*mx\s*:\s*(\S+)\s*$/gim)].map((m) => m[1].toLowerCase());

    if ((policyTags.version ?? '').toLowerCase() !== 'stsv1') {
      result.errors.push('policy file is missing "version: STSv1"');
    }
    if (!['enforce', 'testing', 'none'].includes(result.mode ?? '')) {
      result.errors.push(`policy mode "${result.mode ?? '(missing)'}" is not valid`);
    }
    if (result.maxAge != null && (result.maxAge < 86400 || result.maxAge > 31557600)) {
      result.errors.push(`max_age of ${result.maxAge}s is outside the sensible 86400-31557600 range`);
    }
    if (result.mxPatterns.length === 0) {
      result.errors.push('policy file lists no "mx:" entries, so every host fails the policy');
    }
  } catch (err) {
    // A TLS failure here is the interesting case: it means senders cannot
    // fetch the policy, so MTA-STS is announced but not actually in force.
    result.policyError = err.message;
  }

  return result;
}

/** TLS-RPT (RFC 8460): where to send TLS failure reports. */
export async function auditTlsRpt(domain, resolver) {
  const txt = await resolver.txt(`_smtp._tls.${domain}`);
  const record = txt.values.find((v) => /^v\s*=\s*TLSRPTv1/i.test(v.trim()));
  if (!record) return { domain, found: false, record: null, rua: [], errors: [] };

  const tags = parseKeyValue(record, ';');
  const rua = (tags.rua ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const errors = [];
  if (rua.length === 0) errors.push('TLS-RPT record has no "rua" destination');
  for (const uri of rua) {
    if (!/^(mailto:|https:)/i.test(uri)) errors.push(`"${uri}" must be a mailto: or https: URI`);
  }

  return { domain, found: true, record, rua, errors };
}

/** BIMI: the logo shown next to authenticated mail. Requires DMARC enforcement. */
export async function auditBimi(domain, resolver, options = {}) {
  const selector = options.selector ?? 'default';
  const txt = await resolver.txt(`${selector}._bimi.${domain}`);
  const record = txt.values.find((v) => /^v\s*=\s*BIMI1/i.test(v.trim()));
  if (!record) return { domain, selector, found: false, record: null, logoUrl: null, vmcUrl: null, errors: [] };

  const tags = parseKeyValue(record, ';');
  const errors = [];
  const logoUrl = tags.l || null;
  const vmcUrl = tags.a || null;

  if (!logoUrl) errors.push('BIMI record has no "l=" logo URL');
  else if (!/^https:/i.test(logoUrl)) errors.push('the logo URL must use https');
  if (vmcUrl && !/^https:/i.test(vmcUrl)) errors.push('the VMC URL must use https');

  return { domain, selector, found: true, record, logoUrl, vmcUrl, errors };
}

/**
 * DNSSEC presence, via the DoH "authentic data" flag.
 *
 * Without DNSSEC every record above can be forged by anyone able to tamper
 * with a DNS response, so this is context for the rest of the report rather
 * than a mail setting in its own right.
 */
export async function auditDnssec(domain, resolver) {
  const soa = await resolver.query(domain, 'SOA');
  return {
    domain,
    signed: soa.ad === true,
    // The system resolver path cannot report the AD flag, so say so rather
    // than reporting an unsigned zone we did not actually verify.
    determinate: !resolver.systemDns,
  };
}

/** Parse "a=b; c=d" or newline-delimited "a: b" documents. */
function parseKeyValue(input, separator) {
  /** @type {Record<string, string>} */
  const out = {};
  for (const part of String(input).split(separator)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const match = /^([a-z_][a-z0-9_]*)\s*[:=]\s*(.*)$/i.exec(trimmed);
    if (!match) continue;
    const key = match[1].toLowerCase();
    if (!(key in out)) out[key] = match[2].trim();
  }
  return out;
}
