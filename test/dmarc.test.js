import test from 'node:test';
import assert from 'node:assert/strict';
import { parseDmarcRecord, auditDmarc } from '../src/dmarc.js';
import { FakeResolver } from './helpers/fake-resolver.js';

test('parses the common tags and applies defaults', () => {
  const parsed = parseDmarcRecord('v=DMARC1; p=reject; rua=mailto:d@example.com');
  assert.equal(parsed.errors.length, 0);
  assert.equal(parsed.policy, 'reject');
  assert.equal(parsed.pct, 100);
  assert.equal(parsed.adkim, 'r');
  assert.equal(parsed.aspf, 'r');
  assert.equal(parsed.interval, 86400);
  assert.equal(parsed.rua[0].address, 'd@example.com');
  assert.equal(parsed.rua[0].domain, 'example.com');
});

test('requires the p tag', () => {
  const parsed = parseDmarcRecord('v=DMARC1; rua=mailto:d@example.com');
  assert.ok(parsed.errors.some((e) => /required tag "p"/.test(e)));
});

test('requires v to come first', () => {
  const parsed = parseDmarcRecord('p=reject; v=DMARC1');
  assert.ok(parsed.errors.some((e) => /must come first/.test(e)));
});

test('rejects invalid policies, pct and alignment values', () => {
  assert.ok(parseDmarcRecord('v=DMARC1; p=block').errors.some((e) => /is invalid/.test(e)));
  assert.ok(parseDmarcRecord('v=DMARC1; p=none; pct=150').errors.some((e) => /between 0 and 100/.test(e)));
  assert.ok(parseDmarcRecord('v=DMARC1; p=none; adkim=x').errors.some((e) => /must be r/.test(e)));
});

test('rejects a duplicated tag', () => {
  assert.ok(parseDmarcRecord('v=DMARC1; p=none; p=reject').errors.some((e) => /more than once/.test(e)));
});

test('parses multiple rua addresses and size limits', () => {
  const parsed = parseDmarcRecord('v=DMARC1; p=none; rua=mailto:a@x.com!10m,mailto:b@y.com');
  assert.equal(parsed.rua.length, 2);
  assert.equal(parsed.rua[0].limit, '10m');
  assert.equal(parsed.rua[1].domain, 'y.com');
});

test('flags a rua entry that is not a mailto URI', () => {
  const parsed = parseDmarcRecord('v=DMARC1; p=none; rua=https://example.com/collect');
  assert.ok(parsed.errors.some((e) => /not a mailto/.test(e)));
});

/* --------------------------------------------------------------- lookups */

test('finds a record published directly on the domain', async () => {
  const result = await auditDmarc(
    'example.com',
    new FakeResolver({ '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@example.com'] }),
  );
  assert.equal(result.found, true);
  assert.equal(result.effectivePolicy, 'reject');
  assert.equal(result.inheritedFrom, null);
});

test('a subdomain with no record inherits the organizational policy', async () => {
  const result = await auditDmarc(
    'mail.example.com',
    new FakeResolver({ '_dmarc.example.com|TXT': ['v=DMARC1; p=reject'] }),
  );
  assert.equal(result.found, true);
  assert.equal(result.inheritedFrom, 'example.com');
  assert.equal(result.effectivePolicy, 'reject');
});

test('sp overrides p for an inheriting subdomain', async () => {
  const result = await auditDmarc(
    'mail.example.com',
    new FakeResolver({ '_dmarc.example.com|TXT': ['v=DMARC1; p=reject; sp=none'] }),
  );
  assert.equal(result.inheritedFrom, 'example.com');
  assert.equal(result.effectivePolicy, 'none');
});

test('handles a multi-label public suffix when finding the parent', async () => {
  const result = await auditDmarc(
    'mail.example.co.uk',
    new FakeResolver({ '_dmarc.example.co.uk|TXT': ['v=DMARC1; p=quarantine'] }),
  );
  assert.equal(result.inheritedFrom, 'example.co.uk');
  assert.equal(result.effectivePolicy, 'quarantine');
});

test('reports no record when neither the domain nor its parent publishes one', async () => {
  const result = await auditDmarc('mail.example.com', new FakeResolver({}));
  assert.equal(result.found, false);
});

/* ------------------------------------------- external destination checks */

test('an external rua destination without authorisation is flagged', async () => {
  const result = await auditDmarc(
    'example.com',
    new FakeResolver({
      '_dmarc.example.com|TXT': ['v=DMARC1; p=none; rua=mailto:reports@vendor.net'],
    }),
  );

  const destination = result.externalDestinations[0];
  assert.equal(destination.external, true);
  assert.equal(destination.authorized, false);
  assert.equal(destination.checkedName, 'example.com._report._dmarc.vendor.net');
});

test('an authorised external destination passes', async () => {
  const result = await auditDmarc(
    'example.com',
    new FakeResolver({
      '_dmarc.example.com|TXT': ['v=DMARC1; p=none; rua=mailto:reports@vendor.net'],
      'example.com._report._dmarc.vendor.net|TXT': ['v=DMARC1'],
    }),
  );
  assert.equal(result.externalDestinations[0].authorized, true);
});

test('a rua address on the same organizational domain needs no authorisation', async () => {
  const result = await auditDmarc(
    'example.com',
    new FakeResolver({
      '_dmarc.example.com|TXT': ['v=DMARC1; p=none; rua=mailto:dmarc@mail.example.com'],
    }),
  );
  assert.equal(result.externalDestinations[0].external, false);
  assert.equal(result.externalDestinations[0].authorized, true);
});

test('reports multiple DMARC records', async () => {
  const result = await auditDmarc(
    'example.com',
    new FakeResolver({ '_dmarc.example.com|TXT': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'] }),
  );
  assert.equal(result.records.length, 2);
  assert.ok(result.errors.some((e) => /records published/.test(e)));
});
