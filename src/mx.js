/**
 * MX and inbound-mail checks.
 */

/**
 * @param {string} domain
 * @param {import('./resolver.js').Resolver} resolver
 */
export async function auditMx(domain, resolver) {
  const mx = await resolver.mx(domain);

  // RFC 7505: a single "0 ." record is an explicit statement that the domain
  // accepts no mail. That is a valid, good configuration for a domain used
  // only for a website, and should not be reported as a missing MX.
  const nullMx = mx.hosts.length === 1 && mx.hosts[0].host === '' && mx.hosts[0].preference === 0;

  const hosts = [];
  for (const host of mx.hosts) {
    if (!host.host) continue;
    const [a, aaaa] = await Promise.all([
      resolver.query(host.host, 'A'),
      resolver.query(host.host, 'AAAA'),
    ]);
    hosts.push({
      ...host,
      addresses: [...a.values, ...aaaa.values],
      resolves: a.values.length > 0 || aaaa.values.length > 0,
    });
  }

  // With no MX at all, RFC 5321 says senders fall back to the A/AAAA record.
  let implicitMx = null;
  if (mx.hosts.length === 0) {
    const a = await resolver.query(domain, 'A');
    implicitMx = a.values.length > 0 ? a.values : null;
  }

  return {
    domain,
    found: mx.hosts.length > 0,
    nullMx,
    hosts,
    implicitMx,
    dnsError: mx.error,
  };
}
