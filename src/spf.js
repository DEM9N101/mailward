/**
 * SPF record parsing and RFC 7208 limit analysis.
 *
 * The single most common way SPF silently breaks is the ten DNS lookup limit
 * (RFC 7208 section 4.6.4). Every `include`, `a`, `mx`, `ptr`, `exists` and
 * `redirect` costs one lookup, and the budget is shared across the whole
 * recursive evaluation. Add Google Workspace, a helpdesk, a CRM and a
 * newsletter tool and most domains quietly cross ten. Once they do, receivers
 * return PermError and treat the check as if SPF were never published.
 *
 * Nothing about that failure is visible in the record itself, which is why a
 * regex-based checker reports "SPF looks fine" on a domain whose mail is being
 * rejected. So this module actually walks the include graph and counts.
 *
 * We deliberately keep counting past ten rather than stopping. A real receiver
 * aborts at the limit, but "you are at 14 of 10, and these three includes cost
 * you 9" is the number someone needs in order to fix it.
 */

export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LOOKUP_LIMIT = 2;
const MAX_TOTAL_QUERIES = 120; // hard stop so a malicious include loop cannot hang us
const MAX_DEPTH = 10;

const MECHANISMS = new Set(['all', 'include', 'a', 'mx', 'ptr', 'exists', 'ip4', 'ip6']);
/** Mechanisms and modifiers that consume the ten lookup budget. */
const COSTS_LOOKUP = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
const KNOWN_MODIFIERS = new Set(['redirect', 'exp']);

/**
 * Parse a raw SPF record into terms.
 * @param {string} record
 */
export function parseSpfRecord(record) {
  const terms = [];
  const errors = [];
  const parts = String(record).trim().split(/\s+/).filter(Boolean);

  if (parts.length === 0 || parts[0].toLowerCase() !== 'v=spf1') {
    errors.push({ term: parts[0] ?? '', message: 'record must begin with "v=spf1"' });
  }

  for (const raw of parts.slice(1)) {
    // Modifier: name=value (must be checked before mechanisms, since a
    // mechanism never contains "=" before its first ":" or "/").
    const modifierMatch = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (modifierMatch) {
      const name = modifierMatch[1].toLowerCase();
      terms.push({ kind: 'modifier', name, value: modifierMatch[2], raw });
      if (!KNOWN_MODIFIERS.has(name)) {
        // Unknown modifiers are legal and must be ignored by receivers, but
        // they are almost always a typo such as "redirect" spelled wrong.
        terms.at(-1).unknown = true;
      }
      continue;
    }

    const mechMatch = /^([+\-~?]?)([a-z0-9]+)(?::([^/]*))?(\/\d{1,3}(?:\/\d{1,3})?)?$/i.exec(raw);
    if (!mechMatch) {
      errors.push({ term: raw, message: `"${raw}" is not a valid SPF term` });
      continue;
    }

    const [, qualifier, nameRaw, value, cidr] = mechMatch;
    const name = nameRaw.toLowerCase();

    if (!MECHANISMS.has(name)) {
      errors.push({ term: raw, message: `unknown mechanism "${nameRaw}"` });
      continue;
    }
    if ((name === 'include' || name === 'exists') && !value) {
      errors.push({ term: raw, message: `"${name}" requires a domain, e.g. ${name}:example.com` });
      continue;
    }
    if ((name === 'ip4' || name === 'ip6') && !value) {
      errors.push({ term: raw, message: `"${name}" requires an address, e.g. ${name}:192.0.2.0/24` });
      continue;
    }

    terms.push({
      kind: 'mechanism',
      name,
      qualifier: qualifier || '+',
      value: value ?? null,
      cidr: cidr ?? null,
      raw,
    });
  }

  return { terms, errors };
}

/** Pick the SPF record out of a domain's TXT records. */
export function selectSpfRecords(txtValues) {
  return txtValues.filter((v) => /^v=spf1(\s|$)/i.test(v.trim()));
}

/**
 * Fetch and fully analyse a domain's SPF configuration.
 *
 * @param {string} domain
 * @param {import('./resolver.js').Resolver} resolver
 */
export async function auditSpf(domain, resolver) {
  const txt = await resolver.txt(domain);
  const records = selectSpfRecords(txt.values);

  const result = {
    domain,
    found: records.length > 0,
    records,
    record: records[0] ?? null,
    dnsError: txt.error,
    terms: [],
    parseErrors: [],
    tree: null,
    lookups: {
      used: 0,
      limit: SPF_LOOKUP_LIMIT,
      void: 0,
      voidLimit: SPF_VOID_LOOKUP_LIMIT,
      exceeded: false,
      voidExceeded: false,
      truncated: false,
    },
    allQualifier: null,
    usesPtr: false,
    issues: [],
  };

  if (!result.found) return result;

  const parsed = parseSpfRecord(result.record);
  result.terms = parsed.terms;
  result.parseErrors = parsed.errors;

  const allTerm = parsed.terms.find((t) => t.kind === 'mechanism' && t.name === 'all');
  result.allQualifier = allTerm ? allTerm.qualifier : null;

  const counter = {
    lookups: 0,
    void: 0,
    queries: 0,
    truncated: false,
    /** Lookups attributed to each top-level term, for the "what costs what" view. */
    attribution: [],
  };

  result.tree = await walk(domain, result.record, parsed.terms, resolver, counter, 0, new Set([domain]));

  result.lookups.used = counter.lookups;
  result.lookups.void = counter.void;
  result.lookups.exceeded = counter.lookups > SPF_LOOKUP_LIMIT;
  result.lookups.voidExceeded = counter.void > SPF_VOID_LOOKUP_LIMIT;
  result.lookups.truncated = counter.truncated;
  result.lookups.attribution = counter.attribution;
  result.usesPtr = containsPtr(result.tree);

  return result;
}

function containsPtr(node) {
  if (!node) return false;
  if (node.terms?.some((t) => t.kind === 'mechanism' && t.name === 'ptr')) return true;
  return (node.children ?? []).some(containsPtr);
}

/**
 * Recursively walk the include/redirect graph, counting lookups exactly as a
 * receiver would.
 */
async function walk(domain, record, terms, resolver, counter, depth, seen) {
  const node = {
    domain,
    record,
    terms,
    children: [],
    lookupsBefore: counter.lookups,
    lookupsAfter: 0,
    error: null,
  };

  if (depth > MAX_DEPTH) {
    node.error = 'maximum include depth exceeded (possible loop)';
    counter.truncated = true;
    return node;
  }

  for (const term of terms) {
    if (counter.queries >= MAX_TOTAL_QUERIES) {
      counter.truncated = true;
      break;
    }

    const isLookupMechanism = term.kind === 'mechanism' && COSTS_LOOKUP.has(term.name);
    const isRedirect = term.kind === 'modifier' && term.name === 'redirect';
    if (!isLookupMechanism && !isRedirect) continue;

    counter.lookups++;
    const costStart = counter.lookups;

    // Macros (%{i}, %{d}) expand per-message, so a static audit cannot know
    // what name would be queried. Count the lookup, because a receiver
    // certainly will, but do not query the leftover fragment: doing so
    // produces a bogus NXDOMAIN that inflates the void-lookup count and can
    // report a healthy domain as broken.
    if (hasMacro(term.value)) {
      node.children.push({
        domain: String(term.value),
        record: null,
        terms: [],
        children: [],
        macro: true,
        error: null,
        note: 'contains a macro; expanded per message, not evaluated here',
        lookupsBefore: costStart,
        lookupsAfter: counter.lookups,
      });
      recordAttribution(counter, depth, term, costStart);
      continue;
    }

    if (term.kind === 'mechanism' && (term.name === 'a' || term.name === 'mx')) {
      const target = term.value || domain;
      counter.queries++;
      if (term.name === 'a') {
        const a = await resolver.query(target, 'A');
        if (isVoid(a)) counter.void++;
      } else {
        const mx = await resolver.mx(target);
        if (isVoid(mx)) counter.void++;
        else if (mx.hosts.length > 10) {
          node.children.push({
            domain: target,
            record: null,
            terms: [],
            children: [],
            error: `"mx" resolves to ${mx.hosts.length} hosts; RFC 7208 allows at most 10`,
            lookupsBefore: costStart,
            lookupsAfter: counter.lookups,
          });
        }
      }
      recordAttribution(counter, depth, term, costStart);
      continue;
    }

    if (term.kind === 'mechanism' && term.name === 'exists') {
      counter.queries++;
      const a = await resolver.query(stripMacros(term.value), 'A');
      if (isVoid(a)) counter.void++;
      recordAttribution(counter, depth, term, costStart);
      continue;
    }

    if (term.kind === 'mechanism' && term.name === 'ptr') {
      // Deprecated and expensive; we count it but do not perform the reverse
      // lookups, which would be slow and are not needed to audit the config.
      recordAttribution(counter, depth, term, costStart);
      continue;
    }

    // include / redirect: recurse.
    const target = normalizeTarget(term.kind === 'modifier' ? term.value : term.value);
    if (!target) continue;

    if (seen.has(target)) {
      node.children.push({
        domain: target,
        record: null,
        terms: [],
        children: [],
        error: 'include loop detected (this domain is already in the chain)',
        lookupsBefore: costStart,
        lookupsAfter: counter.lookups,
      });
      recordAttribution(counter, depth, term, costStart);
      continue;
    }

    counter.queries++;
    const childTxt = await resolver.txt(target);
    const childRecords = selectSpfRecords(childTxt.values);

    if (childRecords.length === 0) {
      counter.void++;
      node.children.push({
        domain: target,
        record: null,
        terms: [],
        children: [],
        error:
          childTxt.error != null
            ? `lookup failed: ${childTxt.error}`
            : 'no SPF record published (this include contributes nothing and wastes a lookup)',
        lookupsBefore: costStart,
        lookupsAfter: counter.lookups,
      });
      recordAttribution(counter, depth, term, costStart);
      continue;
    }

    const childParsed = parseSpfRecord(childRecords[0]);
    const child = await walk(
      target,
      childRecords[0],
      childParsed.terms,
      resolver,
      counter,
      depth + 1,
      new Set([...seen, target]),
    );
    if (childRecords.length > 1) {
      child.error = `${childRecords.length} SPF records published; receivers return PermError`;
    }
    child.parseErrors = childParsed.errors;
    node.children.push(child);
    recordAttribution(counter, depth, term, costStart);
  }

  node.lookupsAfter = counter.lookups;
  return node;
}

/** Track how many lookups each top-level term ultimately consumed. */
function recordAttribution(counter, depth, term, costStart) {
  if (depth !== 0) return;
  counter.attribution.push({
    term: term.raw,
    cost: counter.lookups - costStart + 1,
    firstLookupIndex: costStart,
  });
}

function isVoid(result) {
  return result.status === 3 || (result.status === 0 && result.values.length === 0);
}

/** True when a term's value contains an SPF macro expansion. */
function hasMacro(value) {
  return /%\{/.test(String(value ?? ''));
}

function normalizeTarget(value) {
  if (!value) return null;
  return stripMacros(value).replace(/\.$/, '').toLowerCase();
}

/**
 * SPF macros (%{i}, %{d}, ...) expand per-message. We cannot resolve them
 * during a static audit, so we drop them and check what is left.
 */
function stripMacros(value) {
  return String(value ?? '').replace(/%\{[^}]*\}/g, '').replace(/%%/g, '%');
}

/** Total wire length of a record, for the 255-byte character-string limit. */
export function spfRecordLength(record) {
  return Buffer.byteLength(String(record), 'utf8');
}
