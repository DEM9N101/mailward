import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { parseAggregateReport, readReportFile, summarizeReports } from '../src/report/index.js';
import { extractXmlDocuments, isGzip, isZip, readZip } from '../src/report/archive.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

test('parses an aggregate report', async () => {
  const xml = await readFile(join(fixtures, 'sample-report.xml'), 'utf8');
  const report = parseAggregateReport(xml);

  assert.equal(report.orgName, 'google.com');
  assert.equal(report.reportId, '18446744073709551615');
  assert.equal(report.policyPublished.domain, 'example.com');
  assert.equal(report.policyPublished.p, 'none');
  assert.equal(report.records.length, 4);

  assert.ok(report.dateRange.begin instanceof Date);
  assert.ok(report.dateRange.end > report.dateRange.begin);
});

test('uses the aligned policy_evaluated results to decide pass or fail', async () => {
  const xml = await readFile(join(fixtures, 'sample-report.xml'), 'utf8');
  const report = parseAggregateReport(xml);

  // Passes on DKIM alone.
  assert.equal(report.records[0].pass, true);
  // DKIM fails but SPF is aligned, so DMARC still passes. This is the case a
  // naive "both must pass" reading gets wrong.
  assert.equal(report.records[1].dkim, 'fail');
  assert.equal(report.records[1].spf, 'pass');
  assert.equal(report.records[1].pass, true);
  // Neither aligned.
  assert.equal(report.records[2].pass, false);
});

test('reads the same report from xml, gzip and zip', async () => {
  const results = await Promise.all([
    readReportFile(join(fixtures, 'sample-report.xml')),
    readReportFile(join(fixtures, 'sample-report.xml.gz')),
    readReportFile(join(fixtures, 'sample-report.zip')),
  ]);

  for (const result of results) {
    assert.equal(result.errors.length, 0);
    assert.equal(result.reports.length, 1);
    assert.equal(result.reports[0].reportId, '18446744073709551615');
    assert.equal(result.reports[0].records.length, 4);
  }
});

test('detects container formats by magic number', async () => {
  const gz = await readFile(join(fixtures, 'sample-report.xml.gz'));
  const zip = await readFile(join(fixtures, 'sample-report.zip'));
  const xml = await readFile(join(fixtures, 'sample-report.xml'));

  assert.equal(isGzip(gz), true);
  assert.equal(isZip(zip), true);
  assert.equal(isGzip(xml), false);
  assert.equal(isZip(xml), false);
});

test('reads deflated members out of a real zip archive', async () => {
  const zip = await readFile(join(fixtures, 'sample-report.zip'));
  const entries = readZip(zip);

  assert.equal(entries.length, 1);
  assert.equal(entries[0].name, 'sample-report.xml');
  assert.match(entries[0].data.toString('utf8'), /<feedback>/);
});

test('extractXmlDocuments passes plain XML straight through', async () => {
  const xml = await readFile(join(fixtures, 'sample-report.xml'));
  const documents = extractXmlDocuments(xml, 'sample-report.xml');
  assert.equal(documents.length, 1);
  assert.match(documents[0].xml, /<org_name>google\.com<\/org_name>/);
});

/* ------------------------------------------------------------- summaries */

test('summarises volume, pass rate and failing sources', async () => {
  const { reports } = await readReportFile(join(fixtures, 'sample-report.xml'));
  const summary = summarizeReports(reports);

  assert.equal(summary.totalMessages, 128);
  assert.equal(summary.passing, 120);
  assert.equal(summary.failing, 8);
  assert.equal(Number(summary.passRate.toFixed(4)), 0.9375);
  assert.deepEqual(summary.domains, ['example.com']);

  // Sorted by volume, so the biggest sender leads.
  assert.equal(summary.sources[0].ip, '209.85.220.41');
  assert.equal(summary.sources[0].messages, 100);

  // Failing sources are ranked by how much they are failing.
  assert.equal(summary.failingSources.length, 2);
  assert.equal(summary.failingSources[0].ip, '203.0.113.99');
  assert.equal(summary.failingSources[0].failing, 5);
});

test('identifies a known sending platform from its auth domain', async () => {
  const { reports } = await readReportFile(join(fixtures, 'sample-report.xml'));
  const summary = summarizeReports(reports);
  const sendgrid = summary.sources.find((s) => s.ip === '168.245.10.20');
  assert.equal(sendgrid.sender, 'SendGrid');
});

test('does not recommend enforcement while legitimate mail is failing', async () => {
  const { reports } = await readReportFile(join(fixtures, 'sample-report.xml'));
  const summary = summarizeReports(reports);

  assert.equal(summary.readiness.level, 'not-ready');
  assert.equal(summary.readiness.current, 'none');
  assert.match(summary.readiness.reason, /would block legitimate mail/);
});

test('recommends enforcement once everything authenticates at volume', () => {
  const reports = [
    {
      orgName: 'google.com',
      dateRange: { begin: new Date(0), end: new Date(86400000) },
      policyPublished: { domain: 'example.com', p: 'none', adkim: 'r', aspf: 'r', sp: null, pct: 100 },
      records: [
        { sourceIp: '1.1.1.1', count: 5000, disposition: 'none', dkim: 'pass', spf: 'pass', pass: true, headerFrom: 'example.com', envelopeFrom: '', dkimResults: [], spfResults: [], overrides: [] },
      ],
    },
  ];

  const summary = summarizeReports(reports);
  assert.equal(summary.readiness.level, 'ready');
  assert.match(summary.readiness.reason, /looks safe/);
});

test('treats a tiny but perfect sample cautiously', () => {
  const reports = [
    {
      orgName: 'google.com',
      dateRange: { begin: new Date(0), end: new Date(86400000) },
      policyPublished: { domain: 'example.com', p: 'none', adkim: 'r', aspf: 'r', sp: null, pct: 100 },
      records: [
        { sourceIp: '1.1.1.1', count: 4, disposition: 'none', dkim: 'pass', spf: 'pass', pass: true, headerFrom: 'example.com', envelopeFrom: '', dkimResults: [], spfResults: [], overrides: [] },
      ],
    },
  ];

  const summary = summarizeReports(reports);
  assert.equal(summary.readiness.level, 'likely');
  assert.match(summary.readiness.reason, /small sample/);
});

test('aggregates across several reports', async () => {
  const { reports } = await readReportFile(join(fixtures, 'sample-report.xml'));
  const summary = summarizeReports([...reports, ...reports]);

  assert.equal(summary.reportCount, 2);
  assert.equal(summary.totalMessages, 256);
  // The same IP appearing in both reports must merge into one source.
  assert.equal(summary.sources.length, 4);
  assert.equal(summary.sources[0].messages, 200);
});

test('rejects a document that is not a DMARC report', () => {
  assert.throws(() => parseAggregateReport('<html><body>nope</body></html>'), /expected a <feedback> document/);
});
