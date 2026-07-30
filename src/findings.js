/**
 * Turning records into advice.
 *
 * The audit modules answer "what is published". This module answers the only
 * two questions anyone actually has: what is wrong, and what exactly do I
 * paste into DNS to fix it. Every finding therefore carries a `fix` that is a
 * concrete record, not a link to a specification.
 */

export const SEVERITY = {
  critical: { rank: 0, weight: 30, label: 'critical' },
  high: { rank: 1, weight: 15, label: 'high' },
  medium: { rank: 2, weight: 7, label: 'medium' },
  low: { rank: 3, weight: 2, label: 'low' },
  info: { rank: 4, weight: 0, label: 'info' },
  good: { rank: 5, weight: 0, label: 'ok' },
};

const order = (severity) => SEVERITY[severity]?.rank ?? 9;

/**
 * @param {import('./audit.js').DomainAudit} audit
 * @returns {Array<{id: string, severity: string, title: string, detail: string, fix?: string}>}
 */
export function buildFindings(audit) {
  const findings = [];
  const add = (finding) => findings.push(finding);
  const { domain, spf, dmarc, dkim, mx, mtaSts, tlsRpt, bimi, dnssec } = audit;

  buildDmarcFindings(add, domain, dmarc);
  buildSpfFindings(add, domain, spf);
  buildDkimFindings(add, domain, dkim);
  buildMxFindings(add, domain, mx);
  buildTransportFindings(add, domain, mtaSts, tlsRpt, mx);
  buildBimiFindings(add, bimi, dmarc);
  buildDnssecFindings(add, dnssec);

  findings.sort((a, b) => order(a.severity) - order(b.severity));
  return findings;
}

/* ------------------------------------------------------------------ DMARC */

function buildDmarcFindings(add, domain, dmarc) {
  if (!dmarc.found) {
    add({
      id: 'dmarc/missing',
      severity: 'critical',
      title: 'No DMARC record',
      detail:
        'Anyone can send email that appears to come from this domain, and receiving servers have no instruction to stop them. ' +
        'Gmail and Yahoo also require DMARC from anyone sending in volume, so bulk mail from this domain is likely to be rejected or filtered.',
      fix: dnsRecord(
        `_dmarc.${domain}`,
        `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`,
        'Start at p=none. It changes nothing about delivery and begins collecting reports so you can see who sends as you before you enforce.',
      ),
    });
    return;
  }

  if (dmarc.records.length > 1) {
    add({
      id: 'dmarc/multiple-records',
      severity: 'critical',
      title: `${dmarc.records.length} DMARC records published`,
      detail:
        'When more than one DMARC record exists, receivers cannot tell which one is authoritative and ignore all of them. ' +
        'The domain is currently unprotected despite appearing configured.',
      fix: `Delete every TXT record at ${dmarc.recordName} except the one you want to keep.`,
    });
  }

  for (const error of dmarc.errors) {
    if (/^\d+ DMARC records/.test(error)) continue; // already reported above
    add({
      id: 'dmarc/syntax',
      severity: 'high',
      title: 'DMARC record has a syntax problem',
      detail: `${error}. Receivers that cannot parse the record fall back to treating the domain as having no policy.`,
      fix: `Review the record at ${dmarc.recordName}: ${dmarc.record}`,
    });
  }

  const policy = dmarc.effectivePolicy;

  if (dmarc.inheritedFrom) {
    add({
      id: 'dmarc/inherited',
      severity: 'info',
      title: `Policy inherited from ${dmarc.inheritedFrom}`,
      detail:
        `${domain} has no DMARC record of its own, so receivers apply the policy published at _dmarc.${dmarc.inheritedFrom}. ` +
        `The effective policy for this subdomain is "${policy ?? 'none'}".`,
    });
  }

  if (policy === 'none') {
    add({
      id: 'dmarc/policy-none',
      severity: 'high',
      title: 'DMARC is in monitoring mode (p=none)',
      detail:
        'Reports are being collected but nothing is being blocked. Mail that fails authentication is still delivered, ' +
        'so this provides no protection against someone spoofing the domain.',
      fix: dnsRecord(
        dmarc.recordName,
        withPolicy(dmarc.record, 'quarantine'),
        'Once your reports show all legitimate sources passing, move to quarantine, then to reject.',
      ),
    });
  } else if (policy === 'quarantine') {
    add({
      id: 'dmarc/policy-quarantine',
      severity: 'medium',
      title: 'DMARC is at quarantine, not reject',
      detail:
        'Failing mail is sent to spam rather than refused. This is a good staging point, and the last step is to reject outright.',
      fix: dnsRecord(dmarc.recordName, withPolicy(dmarc.record, 'reject')),
    });
  } else if (policy === 'reject') {
    add({
      id: 'dmarc/policy-reject',
      severity: 'good',
      title: 'DMARC policy is set to reject',
      detail: 'Mail failing authentication for this domain is refused outright. This is the strongest setting.',
    });
  }

  const parsed = dmarc.parsed;
  if (!parsed) return;

  if (parsed.rua.length === 0) {
    add({
      id: 'dmarc/no-rua',
      severity: 'high',
      title: 'No DMARC report address (rua)',
      detail:
        'Without a report address you receive no data about who is sending as your domain, which means there is no safe way ' +
        'to tell whether tightening the policy would break your own mail.',
      fix: dnsRecord(dmarc.recordName, appendTag(dmarc.record, `rua=mailto:dmarc@${domain}`)),
    });
  }

  for (const destination of dmarc.externalDestinations) {
    if (destination.external && !destination.authorized) {
      add({
        id: 'dmarc/external-unauthorized',
        severity: 'high',
        title: `Reports to ${destination.address} are not authorised`,
        detail:
          `${destination.domain} has not published a record authorising it to receive reports for ${domain}, so conforming ` +
          'receivers will not send them. This is the usual reason a correctly configured domain still receives no reports.',
        fix: dnsRecord(
          `${domain}._report._dmarc.${destination.domain}`,
          'v=DMARC1',
          `This record has to be created in DNS for ${destination.domain}. If that is a vendor, they normally do it for you on request.`,
        ),
      });
    }
  }

  if (parsed.pct < 100 && policy !== 'none') {
    add({
      id: 'dmarc/partial-pct',
      severity: 'medium',
      title: `Policy applies to only ${parsed.pct}% of mail`,
      detail:
        `pct=${parsed.pct} means the remaining ${100 - parsed.pct}% of failing mail is treated one step down from your policy. ` +
        'This is useful during a rollout and should not be left in place permanently.',
      fix: 'Remove the pct tag (or set pct=100) once the rollout is complete.',
    });
  }

  if (parsed.policy === 'reject' && parsed.subdomainPolicy === 'none') {
    add({
      id: 'dmarc/subdomain-unprotected',
      severity: 'medium',
      title: 'Subdomains are exempt from the policy (sp=none)',
      detail:
        'The domain itself is protected but every subdomain is not, and attackers routinely spoof subdomains that were never used for mail.',
      fix: 'Remove the sp tag so subdomains inherit p=reject, or set sp=reject explicitly.',
    });
  }

  if (parsed.ruf.length > 0) {
    add({
      id: 'dmarc/forensic-reports',
      severity: 'low',
      title: 'Forensic reports (ruf) are requested',
      detail:
        'Failure reports can contain message content and recipient addresses, so most large receivers never send them and some ' +
        'jurisdictions treat them as personal data. They are rarely worth the privacy exposure.',
      fix: 'Consider removing the ruf tag and relying on aggregate (rua) reports.',
    });
  }
}

/* -------------------------------------------------------------------- SPF */

function buildSpfFindings(add, domain, spf) {
  if (!spf.found) {
    add({
      id: 'spf/missing',
      severity: 'high',
      title: 'No SPF record',
      detail:
        'Nothing tells receivers which servers may send mail for this domain. SPF is also one of the two ways a message can ' +
        'pass DMARC, so without it you are relying entirely on DKIM.',
      fix: dnsRecord(
        domain,
        'v=spf1 include:_spf.google.com -all',
        'Replace the include with whatever actually sends your mail, then end with -all.',
      ),
    });
    return;
  }

  if (spf.records.length > 1) {
    add({
      id: 'spf/multiple-records',
      severity: 'critical',
      title: `${spf.records.length} SPF records published`,
      detail:
        'RFC 7208 allows exactly one. Receivers return PermError and treat SPF as unusable, which usually also breaks DMARC alignment.',
      fix: 'Merge them into a single record. Two records like "v=spf1 include:a -all" and "v=spf1 include:b -all" become "v=spf1 include:a include:b -all".',
    });
  }

  for (const error of spf.parseErrors) {
    add({
      id: 'spf/syntax',
      severity: 'high',
      title: 'SPF record has a syntax problem',
      detail: `${error.message}. Receivers return PermError for a record they cannot parse.`,
      fix: `Review the record: ${spf.record}`,
    });
  }

  const { lookups } = spf;
  if (lookups.exceeded) {
    const worst = [...(lookups.attribution ?? [])].sort((a, b) => b.cost - a.cost).slice(0, 3);
    add({
      id: 'spf/lookup-limit-exceeded',
      severity: 'critical',
      title: `SPF needs ${lookups.used} DNS lookups, the limit is ${lookups.limit}`,
      detail:
        'Receivers stop evaluating at ten lookups and return PermError, which means SPF fails for all of your mail ' +
        'no matter which server sent it. Nothing in the record itself looks wrong, which is why this is so often missed.' +
        (worst.length
          ? `\nMost expensive terms: ${worst.map((t) => `${t.term} (${t.cost})`).join(', ')}.`
          : ''),
      fix:
        'Reduce the include chain. The usual fixes are to drop vendors you no longer use, replace an include with the ' +
        'ip4/ip6 ranges it resolves to (these cost no lookups), or move a vendor onto its own subdomain with its own SPF record.',
    });
  } else if (lookups.used >= 8) {
    add({
      id: 'spf/lookup-limit-close',
      severity: 'medium',
      title: `SPF uses ${lookups.used} of ${lookups.limit} DNS lookups`,
      detail:
        'There is little headroom left. Adding one more vendor, or a vendor silently adding an include to their own record, ' +
        'will push this over the limit and break SPF for the whole domain.',
      fix: 'Trim the include chain now, while it is not yet an outage.',
    });
  }

  if (lookups.voidExceeded) {
    add({
      id: 'spf/void-lookups',
      severity: 'high',
      title: `${lookups.void} lookups returned nothing (limit is ${lookups.voidLimit})`,
      detail:
        'Terms pointing at names that do not exist count as void lookups. More than two is a PermError, and they are almost ' +
        'always leftovers from a vendor you stopped using.',
      fix: 'Remove includes and a/mx terms that no longer resolve.',
    });
  }

  if (spf.allQualifier === '+') {
    add({
      id: 'spf/all-plus',
      severity: 'critical',
      title: 'SPF ends with +all',
      detail:
        'This states that every server on the internet is authorised to send mail as this domain. It is strictly worse than ' +
        'publishing no SPF record at all.',
      fix: dnsRecord(domain, spf.record.replace(/\+?all\s*$/, '-all')),
    });
  } else if (spf.allQualifier === null) {
    add({
      id: 'spf/all-missing',
      severity: 'medium',
      title: 'SPF has no "all" mechanism',
      detail:
        'Without a final all, anything not explicitly listed gets a neutral result, which receivers treat much like no policy.',
      fix: dnsRecord(domain, `${spf.record} -all`),
    });
  } else if (spf.allQualifier === '?') {
    add({
      id: 'spf/all-neutral',
      severity: 'medium',
      title: 'SPF ends with ?all (neutral)',
      detail: 'A neutral result gives receivers no reason to treat unlisted senders differently, so the record has little effect.',
      fix: dnsRecord(domain, spf.record.replace(/\?all\s*$/, '-all')),
    });
  } else if (spf.allQualifier === '~') {
    add({
      id: 'spf/all-softfail',
      severity: 'info',
      title: 'SPF ends with ~all (softfail)',
      detail:
        'This is a reasonable setting, especially alongside an enforcing DMARC policy. Move to -all once you are confident ' +
        'every legitimate sender is listed.',
    });
  } else if (spf.allQualifier === '-') {
    add({
      id: 'spf/all-fail',
      severity: 'good',
      title: 'SPF ends with -all',
      detail: 'Servers not listed are explicitly unauthorised. This is the correct end state.',
    });
  }

  if (spf.usesPtr) {
    add({
      id: 'spf/ptr',
      severity: 'medium',
      title: 'SPF uses the deprecated "ptr" mechanism',
      detail:
        'RFC 7208 tells senders not to publish ptr and receivers may skip it entirely. It is slow, unreliable, and some ' +
        'receivers treat its presence as a signal of a poorly maintained domain.',
      fix: 'Replace ptr with the explicit ip4/ip6 ranges or an include for the sending service.',
    });
  }

  collectBrokenIncludes(spf.tree, add);
}

function collectBrokenIncludes(node, add, depth = 0) {
  if (!node) return;
  for (const child of node.children ?? []) {
    if (child.error) {
      add({
        id: 'spf/include-broken',
        severity: child.error.includes('loop') ? 'high' : 'medium',
        title: `SPF include ${child.domain} is broken`,
        detail: `${child.error} Every include costs one of your ten lookups whether or not it returns anything useful.`,
        fix: `Remove include:${child.domain} from the SPF chain, or fix the record it points at.`,
      });
    }
    collectBrokenIncludes(child, add, depth + 1);
  }
}

/* ------------------------------------------------------------------- DKIM */

function buildDkimFindings(add, domain, dkim) {
  if (dkim.skipped) {
    add({
      id: 'dkim/skipped',
      severity: 'info',
      title: 'DKIM was not checked',
      detail: 'Re-run without --no-dkim to probe for signing keys.',
    });
    return;
  }

  if (!dkim.found) {
    add({
      id: 'dkim/not-found',
      severity: 'medium',
      title: 'No DKIM key found',
      detail:
        `None of the ${dkim.selectorsProbed} selectors tried returned a key. DNS provides no way to list selectors, so this ` +
        'does not prove DKIM is missing: a key on a custom selector is invisible to any scanner. Check a recent message header ' +
        'for "d=" and "s=" and re-run with --selector to confirm.',
      fix: `mailward ${domain} --selector yourselector`,
    });
    return;
  }

  for (const key of dkim.keys) {
    if (key.revoked) {
      add({
        id: 'dkim/revoked',
        severity: 'high',
        title: `DKIM selector "${key.selector}" is revoked`,
        detail:
          'The record exists with an empty public key, which tells receivers to treat every signature from this selector as ' +
          'invalid. If anything still signs with it, that mail fails DKIM.',
        fix: `Either publish the real key at ${key.selector}._domainkey.${domain} or stop signing with this selector.`,
      });
      continue;
    }

    if (key.error) {
      add({
        id: 'dkim/malformed',
        severity: 'high',
        title: `DKIM selector "${key.selector}" has an unreadable key`,
        detail: `${key.error}. Receivers cannot verify signatures made with this selector.`,
        fix: `Re-publish the key at ${key.selector}._domainkey.${domain}, taking care not to introduce line breaks or spaces.`,
      });
      continue;
    }

    if (key.keyType === 'rsa' && key.bits != null && key.bits < 1024) {
      add({
        id: 'dkim/key-too-short',
        severity: 'high',
        title: `DKIM selector "${key.selector}" uses a ${key.bits}-bit key`,
        detail: 'Keys under 1024 bits are rejected outright by several large receivers, so signatures simply do not verify.',
        fix: 'Generate a 2048-bit key and republish it.',
      });
    } else if (key.keyType === 'rsa' && key.bits === 1024) {
      add({
        id: 'dkim/key-weak',
        severity: 'medium',
        title: `DKIM selector "${key.selector}" uses a 1024-bit key`,
        detail: '1024-bit RSA still verifies everywhere today but is being phased out. 2048 is the current norm.',
        fix: 'Rotate to a 2048-bit key when convenient.',
      });
    }

    if (key.testing) {
      add({
        id: 'dkim/testing-mode',
        severity: 'medium',
        title: `DKIM selector "${key.selector}" is in testing mode (t=y)`,
        detail:
          'Testing mode tells receivers to ignore the outcome of the signature check, so the signature provides no protection. ' +
          'It is usually left over from initial setup.',
        fix: `Remove "t=y" from the record at ${key.selector}._domainkey.${domain}.`,
      });
    }
  }

  const usable = dkim.keys.filter((k) => !k.revoked && !k.error);
  if (usable.length > 0) {
    add({
      id: 'dkim/present',
      severity: 'good',
      title: `DKIM key${usable.length > 1 ? 's' : ''} found: ${usable.map((k) => k.selector).join(', ')}`,
      detail: usable
        .map((k) => `${k.selector}: ${k.keyType.toUpperCase()}${k.bits ? ` ${k.bits}-bit` : ''}`)
        .join(' · '),
    });
  }
}

/* --------------------------------------------------------------------- MX */

function buildMxFindings(add, domain, mx) {
  if (mx.nullMx) {
    add({
      id: 'mx/null',
      severity: 'good',
      title: 'Domain explicitly accepts no mail (null MX)',
      detail: 'A null MX record tells senders immediately that this domain receives no mail, which is correct for a send-only or parked domain.',
    });
    return;
  }

  if (!mx.found) {
    add({
      id: 'mx/missing',
      severity: mx.implicitMx ? 'medium' : 'low',
      title: 'No MX records',
      detail: mx.implicitMx
        ? 'With no MX record, senders fall back to delivering to the domain\'s A record, which is rarely what anyone intends and often lands on a web server.'
        : 'This domain cannot receive mail. If that is deliberate, say so explicitly so senders fail fast instead of retrying for days.',
      fix: mx.implicitMx
        ? 'Publish proper MX records, or a null MX ("0 .") if the domain should not receive mail.'
        : dnsRecord(domain, '0 .', 'A null MX record, published as an MX record with priority 0 and target "." - only if this domain should never receive mail.'),
    });
    return;
  }

  const broken = mx.hosts.filter((h) => !h.resolves);
  if (broken.length > 0) {
    add({
      id: 'mx/unresolvable',
      severity: 'high',
      title: `${broken.length} MX host${broken.length > 1 ? 's do' : ' does'} not resolve`,
      detail: `${broken.map((h) => h.host).join(', ')} has no A or AAAA record, so mail directed there cannot be delivered.`,
      fix: 'Correct the MX target or remove the record.',
    });
  }
}

/* -------------------------------------------------------------- Transport */

function buildTransportFindings(add, domain, mtaSts, tlsRpt, mx) {
  if (!mtaSts.found) {
    add({
      id: 'mtasts/missing',
      severity: 'low',
      title: 'No MTA-STS policy',
      detail:
        'SMTP encryption is opportunistic by default, so an attacker positioned between servers can strip TLS and read mail in ' +
        'transit. MTA-STS tells senders to require TLS and refuse to fall back.',
      fix: `Publish a TXT record at _mta-sts.${domain} with "v=STSv1; id=<timestamp>" and serve a policy at https://mta-sts.${domain}/.well-known/mta-sts.txt`,
    });
  } else {
    if (mtaSts.policyError) {
      add({
        id: 'mtasts/policy-unreachable',
        severity: 'high',
        title: 'MTA-STS is announced but the policy cannot be fetched',
        detail:
          `${mtaSts.policyUrl} could not be read (${mtaSts.policyError}). Senders that cannot fetch the policy fall back to ` +
          'unprotected delivery, so the mechanism is advertised but doing nothing. An expired certificate on the policy host is the usual cause.',
        fix: 'Make sure the policy host serves the file over valid HTTPS with no redirects.',
      });
    }

    for (const error of mtaSts.errors) {
      add({ id: 'mtasts/policy-invalid', severity: 'medium', title: 'MTA-STS policy problem', detail: error });
    }

    if (mtaSts.mode === 'testing') {
      add({
        id: 'mtasts/testing',
        severity: 'low',
        title: 'MTA-STS is in testing mode',
        detail: 'Failures are reported but delivery still proceeds unprotected. Move to enforce once reports look clean.',
        fix: 'Change "mode: testing" to "mode: enforce" in the policy file.',
      });
    } else if (mtaSts.mode === 'none') {
      add({
        id: 'mtasts/mode-none',
        severity: 'medium',
        title: 'MTA-STS mode is "none"',
        detail: 'This actively disables the policy. It is meant only as a way to withdraw MTA-STS cleanly.',
      });
    } else if (mtaSts.mode === 'enforce') {
      add({ id: 'mtasts/enforce', severity: 'good', title: 'MTA-STS is enforcing', detail: 'Senders are required to use validated TLS.' });

      const uncovered = (mx.hosts ?? []).filter(
        (host) => host.host && !mtaSts.mxPatterns.some((pattern) => matchesMxPattern(host.host, pattern)),
      );
      if (uncovered.length > 0) {
        add({
          id: 'mtasts/mx-not-covered',
          severity: 'high',
          title: 'MTA-STS policy does not cover all MX hosts',
          detail:
            `${uncovered.map((h) => h.host).join(', ')} is not listed in the policy. Under an enforcing policy, senders refuse ` +
            'to deliver to a host that does not match, so mail to this domain will bounce.',
          fix: `Add the missing hosts to the policy file as "mx: ${uncovered[0].host}".`,
        });
      }
    }
  }

  if (!tlsRpt.found) {
    add({
      id: 'tlsrpt/missing',
      severity: 'low',
      title: 'No TLS-RPT record',
      detail: 'Without it you get no notification when another server fails to establish TLS with yours, which is how a downgrade attack stays invisible.',
      fix: dnsRecord(`_smtp._tls.${domain}`, `v=TLSRPTv1; rua=mailto:tls-reports@${domain}`),
    });
  }
  for (const error of tlsRpt.errors ?? []) {
    add({ id: 'tlsrpt/invalid', severity: 'medium', title: 'TLS-RPT record problem', detail: error });
  }
}

function matchesMxPattern(host, pattern) {
  if (!pattern) return false;
  const normalizedHost = host.toLowerCase().replace(/\.$/, '');
  const normalizedPattern = pattern.toLowerCase().replace(/\.$/, '');
  if (normalizedPattern.startsWith('*.')) {
    const suffix = normalizedPattern.slice(1); // ".example.com"
    // A wildcard matches exactly one label, per RFC 8461.
    if (!normalizedHost.endsWith(suffix)) return false;
    const head = normalizedHost.slice(0, -suffix.length);
    return head.length > 0 && !head.includes('.');
  }
  return normalizedHost === normalizedPattern;
}

/* ------------------------------------------------------------ BIMI/DNSSEC */

function buildBimiFindings(add, bimi, dmarc) {
  if (!bimi.found) return;

  for (const error of bimi.errors) {
    add({ id: 'bimi/invalid', severity: 'medium', title: 'BIMI record problem', detail: error });
  }

  const policy = dmarc.effectivePolicy;
  if (policy !== 'quarantine' && policy !== 'reject') {
    add({
      id: 'bimi/needs-enforcement',
      severity: 'medium',
      title: 'BIMI is published but DMARC is not enforcing',
      detail:
        'Mailbox providers only display a BIMI logo for domains at p=quarantine or p=reject. As things stand the logo will never appear.',
      fix: 'Move DMARC to at least p=quarantine.',
    });
  } else {
    add({ id: 'bimi/present', severity: 'good', title: 'BIMI is published', detail: `Logo: ${bimi.logoUrl ?? 'not set'}` });
  }
}

function buildDnssecFindings(add, dnssec) {
  if (!dnssec.determinate) return;
  if (dnssec.signed) {
    add({ id: 'dnssec/signed', severity: 'good', title: 'DNSSEC is enabled', detail: 'The records in this report are cryptographically signed.' });
  } else {
    add({
      id: 'dnssec/unsigned',
      severity: 'low',
      title: 'DNSSEC is not enabled',
      detail:
        'Every record in this report is served unsigned, so anyone able to tamper with DNS responses can forge your SPF, DKIM and DMARC policy.',
      fix: 'Enable DNSSEC at your DNS host. Most managed providers make this a single switch.',
    });
  }
}

/* ---------------------------------------------------------------- Helpers */

function dnsRecord(name, value, note) {
  const lines = ['Add this TXT record:', `  name:  ${name}`, `  value: ${value}`];
  if (note) lines.push('', `  ${note}`);
  return lines.join('\n');
}

function withPolicy(record, policy) {
  return String(record).replace(/\bp\s*=\s*(none|quarantine|reject)\b/i, `p=${policy}`);
}

function appendTag(record, tag) {
  const trimmed = String(record).trim().replace(/;\s*$/, '');
  return `${trimmed}; ${tag}`;
}

/**
 * A single number for "how exposed is this domain to being spoofed".
 *
 * Severity deductions alone are not enough, because they let a domain collect
 * points for peripheral good hygiene while remaining trivially spoofable. A
 * domain with no DMARC record has no protection at all, no matter how tidy its
 * SPF is, so the grade is also capped by what the DMARC policy actually
 * enforces:
 *
 *   no DMARC        cannot pass       nothing stops a forged message
 *   p=none          cannot exceed C   monitoring only, still spoofable
 *   p=quarantine    cannot exceed B   forged mail is filtered, not refused
 *   p=reject        uncapped
 *
 * Any cap that changes the result is reported in `notes`, so the number is
 * explainable rather than a black box.
 */
export function scoreFindings(findings, context = {}) {
  let score = 100;
  for (const finding of findings) {
    score -= SEVERITY[finding.severity]?.weight ?? 0;
  }
  score = Math.max(0, Math.min(100, score));

  const notes = [];
  const { dmarcFound = true, dmarcPolicy = null } = context;

  let ceiling = 100;
  if (!dmarcFound) {
    ceiling = 39;
    notes.push('Capped: without a DMARC record nothing prevents this domain being spoofed.');
  } else if (dmarcPolicy === 'none') {
    ceiling = 74;
    notes.push('Capped at C: DMARC is monitoring only, so forged mail is still delivered.');
  } else if (dmarcPolicy === 'quarantine') {
    ceiling = 89;
    notes.push('Capped at B: forged mail is filtered rather than refused.');
  }

  if (score > ceiling) score = ceiling;
  else if (notes.length > 0) notes.pop(); // the cap did not actually bind

  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  const counts = {};
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;

  return { score, grade, counts, notes };
}
