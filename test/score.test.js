/**
 * The grade has to mean something specific: how exposed is this domain to
 * someone sending mail as it. These pin down the ceilings that stop a domain
 * scoring well on peripheral hygiene while remaining spoofable.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreFindings } from '../src/findings.js';
import { auditDomain } from '../src/audit.js';
import { FakeResolver } from './helpers/fake-resolver.js';

const clean = [{ id: 'x', severity: 'good', title: 'fine', detail: '' }];

test('a clean domain at p=reject can score full marks', () => {
  const result = scoreFindings(clean, { dmarcFound: true, dmarcPolicy: 'reject' });
  assert.equal(result.score, 100);
  assert.equal(result.grade, 'A');
  assert.deepEqual(result.notes, []);
});

test('no DMARC record cannot pass, however tidy everything else is', () => {
  const result = scoreFindings(clean, { dmarcFound: false, dmarcPolicy: null });
  assert.equal(result.grade, 'F');
  assert.match(result.notes[0], /without a DMARC record/);
});

test('p=none cannot exceed C', () => {
  const result = scoreFindings(clean, { dmarcFound: true, dmarcPolicy: 'none' });
  assert.equal(result.grade, 'C');
  assert.match(result.notes[0], /monitoring only/);
});

test('p=quarantine cannot exceed B', () => {
  const result = scoreFindings(clean, { dmarcFound: true, dmarcPolicy: 'quarantine' });
  assert.equal(result.grade, 'B');
  assert.match(result.notes[0], /filtered rather than refused/);
});

test('a cap that does not bind is not reported as a note', () => {
  // Already below the ceiling on merit, so the cap explains nothing.
  const bad = [{ id: 'y', severity: 'critical', title: 'bad', detail: '' }, { id: 'z', severity: 'critical', title: 'bad', detail: '' }];
  const result = scoreFindings(bad, { dmarcFound: true, dmarcPolicy: 'quarantine' });
  assert.equal(result.score, 40);
  assert.deepEqual(result.notes, []);
});

test('deductions still apply beneath the ceiling', () => {
  const withProblems = [
    { id: 'a', severity: 'high', title: '', detail: '' },
    { id: 'b', severity: 'medium', title: '', detail: '' },
  ];
  const result = scoreFindings(withProblems, { dmarcFound: true, dmarcPolicy: 'reject' });
  assert.equal(result.score, 100 - 15 - 7);
});

test('end to end: a p=none domain with everything else right still grades C', async () => {
  const report = await auditDomain('example.com', {
    resolver: new FakeResolver({
      '_dmarc.example.com|TXT': ['v=DMARC1; p=none; rua=mailto:dmarc@example.com'],
      'example.com|TXT': ['v=spf1 ip4:192.0.2.0/24 -all'],
      'example.com|MX': ['10 mail.example.com'],
      'mail.example.com|A': ['192.0.2.10'],
      '_smtp._tls.example.com|TXT': ['v=TLSRPTv1; rua=mailto:tls@example.com'],
    }),
    skipDkim: true,
  });

  assert.equal(report.grade, 'C');
  assert.ok(report.findings.some((f) => f.id === 'dmarc/policy-none'));
});
