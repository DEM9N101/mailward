/**
 * Reading DMARC aggregate reports.
 *
 * Publishing a DMARC record produces a daily trickle of gzipped XML from every
 * large mailbox provider. It is genuinely unreadable by hand, and reading it is
 * the entire point of DMARC: it is the only way to find out who sends mail as
 * your domain before you switch on enforcement and start blocking your own
 * payroll provider.
 *
 * The established open-source answer wants Elasticsearch and Kibana behind it.
 * The commercial answers want a monthly fee and a copy of your mail flow data.
 * This one wants a folder of files.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { join, basename, extname } from 'node:path';
import { extractXmlDocuments } from './archive.js';
import { parseXml, child, children, text } from './xml.js';

/** Sending platforms recognisable from their SPF/DKIM domain. */
const KNOWN_SENDERS = [
  [/(^|\.)google\.com$|(^|\.)googlemail\.com$/i, 'Google Workspace'],
  [/(^|\.)outlook\.com$|(^|\.)protection\.outlook\.com$/i, 'Microsoft 365'],
  [/(^|\.)sendgrid\.net$/i, 'SendGrid'],
  [/(^|\.)amazonses\.com$/i, 'Amazon SES'],
  [/(^|\.)mailgun\.org$|(^|\.)mailgun\.net$/i, 'Mailgun'],
  [/(^|\.)mcsv\.net$|(^|\.)mailchimp\.com$|(^|\.)rsgsv\.net$/i, 'Mailchimp'],
  [/(^|\.)mandrillapp\.com$/i, 'Mandrill'],
  [/(^|\.)sparkpostmail\.com$/i, 'SparkPost'],
  [/(^|\.)mtasv\.net$|(^|\.)postmarkapp\.com$/i, 'Postmark'],
  [/(^|\.)zendesk\.com$/i, 'Zendesk'],
  [/(^|\.)hubspot\.com$|(^|\.)hubspotemail\.net$/i, 'HubSpot'],
  [/(^|\.)salesforce\.com$|(^|\.)exacttarget\.com$/i, 'Salesforce'],
  [/(^|\.)zoho\.com$|(^|\.)zoho\.eu$/i, 'Zoho'],
  [/(^|\.)klaviyomail\.com$/i, 'Klaviyo'],
  [/(^|\.)intercom-mail\.com$/i, 'Intercom'],
  [/(^|\.)shopify\.com$|(^|\.)shopifyemail\.com$/i, 'Shopify'],
  [/(^|\.)atlassian\.net$/i, 'Atlassian'],
  [/(^|\.)freshemail\.io$|(^|\.)freshdesk\.com$/i, 'Freshdesk'],
  [/(^|\.)icloud\.com$|(^|\.)me\.com$/i, 'Apple iCloud Mail'],
];

function identifySender(domains) {
  for (const domain of domains) {
    for (const [pattern, label] of KNOWN_SENDERS) {
      if (pattern.test(domain)) return label;
    }
  }
  return null;
}

/**
 * Parse one aggregate report document.
 * @param {string} xml
 */
export function parseAggregateReport(xml) {
  const root = parseXml(xml);
  if (root.name !== 'feedback') {
    throw new Error(`expected a <feedback> document, found <${root.name}>`);
  }

  const metadata = child(root, 'report_metadata');
  const published = child(root, 'policy_published');
  const range = child(metadata, 'date_range');

  const report = {
    orgName: text(metadata, 'org_name'),
    email: text(metadata, 'email'),
    reportId: text(metadata, 'report_id'),
    dateRange: {
      begin: toDate(text(range, 'begin')),
      end: toDate(text(range, 'end')),
    },
    policyPublished: {
      domain: text(published, 'domain').toLowerCase(),
      adkim: text(published, 'adkim') || 'r',
      aspf: text(published, 'aspf') || 'r',
      p: text(published, 'p') || null,
      sp: text(published, 'sp') || null,
      pct: text(published, 'pct') ? Number(text(published, 'pct')) : 100,
    },
    records: [],
  };

  for (const record of children(root, 'record')) {
    const row = child(record, 'row');
    const evaluated = child(row, 'policy_evaluated');
    const identifiers = child(record, 'identifiers');
    const auth = child(record, 'auth_results');

    const dkimResults = children(auth, 'dkim').map((node) => ({
      domain: text(node, 'domain').toLowerCase(),
      selector: text(node, 'selector'),
      result: text(node, 'result').toLowerCase(),
    }));
    const spfResults = children(auth, 'spf').map((node) => ({
      domain: text(node, 'domain').toLowerCase(),
      scope: text(node, 'scope'),
      result: text(node, 'result').toLowerCase(),
    }));

    const dkimAligned = text(evaluated, 'dkim').toLowerCase();
    const spfAligned = text(evaluated, 'spf').toLowerCase();

    report.records.push({
      sourceIp: text(row, 'source_ip'),
      count: Number(text(row, 'count')) || 0,
      disposition: text(evaluated, 'disposition').toLowerCase() || 'none',
      // These two are the *aligned* results, which is what DMARC actually
      // evaluates. A message can pass raw SPF and still fail DMARC because the
      // passing domain was not the one in the From header.
      dkim: dkimAligned,
      spf: spfAligned,
      pass: dkimAligned === 'pass' || spfAligned === 'pass',
      headerFrom: text(identifiers, 'header_from').toLowerCase(),
      envelopeFrom: text(identifiers, 'envelope_from').toLowerCase(),
      dkimResults,
      spfResults,
      overrides: children(evaluated, 'reason').map((node) => ({
        type: text(node, 'type'),
        comment: text(node, 'comment'),
      })),
    });
  }

  return report;
}

function toDate(seconds) {
  const value = Number(seconds);
  return Number.isFinite(value) && value > 0 ? new Date(value * 1000) : null;
}

/**
 * Read one file, which may be XML, gzip or zip, and may contain several
 * reports.
 * @param {string} path
 */
export async function readReportFile(path) {
  const buffer = await readFile(path);
  const documents = extractXmlDocuments(buffer, basename(path));
  const reports = [];
  const errors = [];

  for (const document of documents) {
    try {
      reports.push({ ...parseAggregateReport(document.xml), sourceFile: path });
    } catch (err) {
      errors.push({ file: path, entry: document.name, message: err.message });
    }
  }

  return { reports, errors };
}

const REPORT_EXTENSIONS = new Set(['.xml', '.gz', '.zip', '.gzip']);

/**
 * Read every report under a path. Accepts a single file or a directory, and
 * walks one level of subdirectories so that a mail client's export folder
 * works without rearranging it.
 * @param {string} path
 */
export async function readReports(path) {
  const info = await stat(path);
  if (info.isFile()) return readReportFile(path);

  const reports = [];
  const errors = [];

  const walk = async (directory, depth) => {
    const entries = await readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (depth > 0) await walk(full, depth - 1);
        continue;
      }
      if (!REPORT_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;
      const result = await readReportFile(full);
      reports.push(...result.reports);
      errors.push(...result.errors);
    }
  };

  await walk(path, 2);
  return { reports, errors };
}

/**
 * Roll a pile of reports up into the answer people actually want: who is
 * sending as me, how much of it authenticates, and is it safe to enforce yet.
 *
 * @param {ReturnType<typeof parseAggregateReport>[]} reports
 */
export function summarizeReports(reports) {
  /** @type {Map<string, any>} */
  const sources = new Map();
  const domains = new Set();
  const organizations = new Set();
  const dispositions = { none: 0, quarantine: 0, reject: 0 };

  let totalMessages = 0;
  let passing = 0;
  let begin = null;
  let end = null;

  for (const report of reports) {
    if (report.policyPublished.domain) domains.add(report.policyPublished.domain);
    if (report.orgName) organizations.add(report.orgName);
    if (report.dateRange.begin && (!begin || report.dateRange.begin < begin)) begin = report.dateRange.begin;
    if (report.dateRange.end && (!end || report.dateRange.end > end)) end = report.dateRange.end;

    for (const record of report.records) {
      totalMessages += record.count;
      if (record.pass) passing += record.count;
      if (record.disposition in dispositions) dispositions[record.disposition] += record.count;

      const key = record.sourceIp;
      if (!sources.has(key)) {
        sources.set(key, {
          ip: key,
          messages: 0,
          passing: 0,
          dkimPassing: 0,
          spfPassing: 0,
          authDomains: new Set(),
          headerFroms: new Set(),
          selectors: new Set(),
        });
      }
      const source = sources.get(key);
      source.messages += record.count;
      if (record.pass) source.passing += record.count;
      if (record.dkim === 'pass') source.dkimPassing += record.count;
      if (record.spf === 'pass') source.spfPassing += record.count;
      if (record.headerFrom) source.headerFroms.add(record.headerFrom);
      for (const dkim of record.dkimResults) {
        if (dkim.domain) source.authDomains.add(dkim.domain);
        if (dkim.selector) source.selectors.add(dkim.selector);
      }
      for (const spf of record.spfResults) if (spf.domain) source.authDomains.add(spf.domain);
    }
  }

  const sourceList = [...sources.values()]
    .map((source) => ({
      ip: source.ip,
      messages: source.messages,
      passing: source.passing,
      failing: source.messages - source.passing,
      passRate: source.messages > 0 ? source.passing / source.messages : 0,
      dkimPassing: source.dkimPassing,
      spfPassing: source.spfPassing,
      authDomains: [...source.authDomains],
      headerFroms: [...source.headerFroms],
      selectors: [...source.selectors],
      sender: identifySender([...source.authDomains]),
    }))
    .sort((a, b) => b.messages - a.messages);

  const failing = totalMessages - passing;
  const passRate = totalMessages > 0 ? passing / totalMessages : 0;
  const failingSources = sourceList.filter((s) => s.failing > 0).sort((a, b) => b.failing - a.failing);

  return {
    reportCount: reports.length,
    organizations: [...organizations].sort(),
    domains: [...domains].sort(),
    dateRange: { begin, end },
    totalMessages,
    passing,
    failing,
    passRate,
    dispositions,
    sources: sourceList,
    failingSources,
    readiness: assessReadiness({ totalMessages, passRate, failingSources, reports }),
  };
}

/**
 * A cautious recommendation about tightening the policy.
 *
 * The failure mode people fear, correctly, is enforcing too early and silently
 * blocking their own invoices. So the thresholds here are conservative and the
 * reasoning is always shown rather than reduced to a yes or no.
 */
function assessReadiness({ totalMessages, passRate, failingSources, reports }) {
  const currentPolicies = new Set(reports.map((r) => r.policyPublished.p).filter(Boolean));
  const current = currentPolicies.size === 1 ? [...currentPolicies][0] : null;

  if (totalMessages === 0) {
    return { level: 'unknown', current, reason: 'No messages appear in these reports yet.' };
  }

  const volumeIsThin = totalMessages < 100;
  const unresolved = failingSources.filter((s) => s.failing >= 5);

  if (passRate >= 0.995 && unresolved.length === 0) {
    return {
      level: volumeIsThin ? 'likely' : 'ready',
      current,
      reason: volumeIsThin
        ? `${formatPercent(passRate)} of ${totalMessages} messages authenticate, but that is a small sample. Collect a couple more weeks before enforcing.`
        : `${formatPercent(passRate)} of ${totalMessages} messages authenticate and no source is failing repeatedly. Moving to p=reject looks safe.`,
    };
  }

  if (passRate >= 0.95) {
    return {
      level: 'quarantine',
      current,
      reason:
        `${formatPercent(passRate)} of ${totalMessages} messages authenticate. ` +
        `${unresolved.length} source${unresolved.length === 1 ? '' : 's'} still fail regularly, so quarantine is a reasonable next step while you fix them.`,
    };
  }

  return {
    level: 'not-ready',
    current,
    reason:
      `Only ${formatPercent(passRate)} of ${totalMessages} messages authenticate. ` +
      'Enforcing now would block legitimate mail. Work through the failing sources below first.',
  };
}

function formatPercent(value) {
  return `${(value * 100).toFixed(1)}%`;
}
