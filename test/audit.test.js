/**
 * End-to-end checks: DNS state in, findings out.
 *
 * These run the real orchestration against a fake resolver, so they cover the
 * part users actually see (which findings appear, and what grade) rather than
 * just the individual parsers.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { auditDomain } from '../src/audit.js';
import { FakeResolver } from './helpers/fake-resolver.js';

function rsaRecord() {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return `v=DKIM1; k=rsa; p=${publicKey.export({ type: 'spki', format: 'der' }).toString('base64')}`;
}

const ids = (report) => report.findings.map((f) => f.id);

test('a domain with nothing configured is graded F and told why', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({}),
    skipDkim: true,
  });

  assert.equal(report.grade, 'F');
  assert.ok(ids(report).includes('dmarc/missing'));
  assert.ok(ids(report).includes('spf/missing'));

  // The most severe problem is listed first.
  assert.equal(report.findings[0].severity, 'critical');
  // And it comes with something to paste into DNS.
  assert.match(report.findings[0].fix, /_dmarc\.example\.com/);
});

test('a well configured domain scores an A', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com'],
      'example.com|TXT': ['v=spf1 ip4:192.0.2.0/24 -all'],
      'example.com|MX': ['10 mail.example.com'],
      'mail.example.com|A': ['192.0.2.10'],
      'google._domainkey.example.com|TXT': [rsaRecord()],
      '_smtp._tls.example.com|TXT': ['v=TLSRPTv1; rua=mailto:tls@example.com'],
    }),
  });

  assert.equal(report.grade, 'A');
  assert.ok(ids(report).includes('dmarc/policy-reject'));
  assert.ok(ids(report).includes('spf/all-fail'));
  assert.ok(ids(report).includes('dkim/present'));
  assert.ok(!ids(report).includes('dmarc/missing'));
});

test('+all is reported as critical', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      'example.com|TXT': ['v=spf1 +all'],
      '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
    }),
    skipDkim: true,
  });

  const finding = report.findings.find((f) => f.id === 'spf/all-plus');
  assert.equal(finding.severity, 'critical');
  assert.match(finding.fix, /-all/);
});

test('an SPF chain over the limit is reported as critical with the costly terms named', async () => {
  const records = {
    'example.com|TXT': [
      `v=spf1 ${Array.from({ length: 12 }, (_, i) => `include:v${i}.example`).join(' ')} -all`,
    ],
    '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
  };
  for (let i = 0; i < 12; i++) records[`v${i}.example|TXT`] = ['v=spf1 ip4:192.0.2.1 -all'];

  const report = await auditDomain('example.com', { resolver: new FakeResolver(records), skipDkim: true });

  const finding = report.findings.find((f) => f.id === 'spf/lookup-limit-exceeded');
  assert.equal(finding.severity, 'critical');
  assert.match(finding.title, /12 DNS lookups/);
  assert.match(finding.detail, /Most expensive terms/);
});

test('an unauthorised external report destination is surfaced', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:reports@vendor.net'],
      'example.com|TXT': ['v=spf1 -all'],
    }),
    skipDkim: true,
  });

  const finding = report.findings.find((f) => f.id === 'dmarc/external-unauthorized');
  assert.ok(finding, 'expected the unauthorised destination to be reported');
  assert.match(finding.fix, /example\.com\._report\._dmarc\.vendor\.net/);
});

test('a revoked DKIM key is called out', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      'google._domainkey.example.com|TXT': ['v=DKIM1; k=rsa; p='],
      '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
      'example.com|TXT': ['v=spf1 -all'],
    }),
  });

  const finding = report.findings.find((f) => f.id === 'dkim/revoked');
  assert.equal(finding.severity, 'high');
});

test('a null MX is treated as correct, not as a missing record', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      'example.com|MX': ['0 .'],
      'example.com|TXT': ['v=spf1 -all'],
      '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
    }),
    skipDkim: true,
  });

  assert.ok(ids(report).includes('mx/null'));
  assert.ok(!ids(report).includes('mx/missing'));
});

test('an MX host that does not resolve is reported', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      'example.com|MX': ['10 broken.example.com'],
      'example.com|TXT': ['v=spf1 -all'],
      '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@example.com'],
    }),
    skipDkim: true,
  });

  const finding = report.findings.find((f) => f.id === 'mx/unresolvable');
  assert.equal(finding.severity, 'high');
});

test('BIMI without an enforcing DMARC policy is flagged as ineffective', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      'default._bimi.example.com|TXT': ['v=BIMI1; l=https://example.com/logo.svg'],
      '_dmarc.example.com|TXT': ['v=DMARC1; p=none; rua=mailto:d@example.com'],
      'example.com|TXT': ['v=spf1 -all'],
    }),
    skipDkim: true,
  });

  assert.ok(ids(report).includes('bimi/needs-enforcement'));
});

test('DNSSEC signing is reported when the AD flag is set', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({ 'example.com|SOA': ['ns.example.com admin.example.com'] }, { ad: true }),
    skipDkim: true,
  });

  assert.ok(ids(report).includes('dnssec/signed'));
});

test('rejects input that is not a domain name', async () => {
  await assert.rejects(() => auditDomain('not a domain', { resolver: new FakeResolver({}) }), /does not look like a domain/);
});

test('accepts a URL and reduces it to the hostname', async () => {
  const report = await auditDomain('https://example.com/some/path', {
    resolver: new FakeResolver({}),
    skipDkim: true,
  });
  assert.equal(report.domain, 'example.com');
});

test('findings are ordered by severity', async () => {
  const report = await auditDomain('example.com', { resolver: new FakeResolver({}), skipDkim: true });
  const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4, good: 5 };
  const ranks = report.findings.map((f) => rank[f.severity]);
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
});
