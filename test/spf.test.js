import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSpfRecord, selectSpfRecords, auditSpf, SPF_LOOKUP_LIMIT } from '../src/spf.js';
import { FakeResolver } from './helpers/fake-resolver.js';

test('parses mechanisms, qualifiers and modifiers', () => {
  const { terms, errors } = parseSpfRecord('v=spf1 ip4:192.0.2.0/24 include:_spf.example.com -all');
  assert.equal(errors.length, 0);
  assert.equal(terms.length, 3);
  assert.deepEqual(
    terms.map((t) => t.name),
    ['ip4', 'include', 'all'],
  );
  assert.equal(terms[2].qualifier, '-');
  assert.equal(terms[1].value, '_spf.example.com');
});

test('defaults a missing qualifier to +', () => {
  const { terms } = parseSpfRecord('v=spf1 all');
  assert.equal(terms[0].qualifier, '+');
});

test('flags a record that does not start with v=spf1', () => {
  const { errors } = parseSpfRecord('include:example.com -all');
  assert.ok(errors.some((e) => /must begin with/.test(e.message)));
});

test('flags unknown mechanisms and incomplete terms', () => {
  const withUnknown = parseSpfRecord('v=spf1 banana:example.com -all');
  assert.ok(withUnknown.errors.some((e) => /unknown mechanism/.test(e.message)));

  const withoutDomain = parseSpfRecord('v=spf1 include: -all');
  assert.ok(withoutDomain.errors.some((e) => /requires a domain/.test(e.message)));
});

test('recognises redirect as a modifier, not a mechanism', () => {
  const { terms } = parseSpfRecord('v=spf1 redirect=_spf.example.com');
  assert.equal(terms[0].kind, 'modifier');
  assert.equal(terms[0].name, 'redirect');
});

test('selectSpfRecords ignores unrelated TXT records', () => {
  const records = selectSpfRecords([
    'google-site-verification=abc',
    'v=spf1 -all',
    'v=DMARC1; p=none',
  ]);
  assert.deepEqual(records, ['v=spf1 -all']);
});

/* ------------------------------------------------------- lookup counting */

test('counts one lookup per include and does not count ip4/all', async () => {
  const resolver = new FakeResolver({
    'example.com|TXT': ['v=spf1 ip4:192.0.2.0/24 include:a.example include:b.example -all'],
    'a.example|TXT': ['v=spf1 ip4:198.51.100.0/24 -all'],
    'b.example|TXT': ['v=spf1 ip4:203.0.113.0/24 -all'],
  });

  const result = await auditSpf('example.com', resolver);
  assert.equal(result.found, true);
  assert.equal(result.lookups.used, 2);
  assert.equal(result.lookups.exceeded, false);
  assert.equal(result.allQualifier, '-');
});

test('counts nested includes against the same shared budget', async () => {
  // Three top-level includes, each of which includes two more: 3 + 6 = 9.
  const records = {
    'example.com|TXT': ['v=spf1 include:one.example include:two.example include:three.example -all'],
  };
  for (const name of ['one', 'two', 'three']) {
    records[`${name}.example|TXT`] = [`v=spf1 include:${name}-a.example include:${name}-b.example -all`];
    records[`${name}-a.example|TXT`] = ['v=spf1 ip4:192.0.2.1 -all'];
    records[`${name}-b.example|TXT`] = ['v=spf1 ip4:192.0.2.2 -all'];
  }

  const result = await auditSpf('example.com', new FakeResolver(records));
  assert.equal(result.lookups.used, 9);
  assert.equal(result.lookups.exceeded, false);
});

test('detects exceeding the ten lookup limit', async () => {
  const includes = Array.from({ length: 12 }, (_, i) => `include:v${i}.example`);
  const records = { 'example.com|TXT': [`v=spf1 ${includes.join(' ')} -all`] };
  for (let i = 0; i < 12; i++) records[`v${i}.example|TXT`] = ['v=spf1 ip4:192.0.2.1 -all'];

  const result = await auditSpf('example.com', new FakeResolver(records));
  assert.equal(result.lookups.used, 12);
  assert.ok(result.lookups.used > SPF_LOOKUP_LIMIT);
  assert.equal(result.lookups.exceeded, true);
});

test('attributes lookup cost to the top-level term responsible', async () => {
  const result = await auditSpf(
    'example.com',
    new FakeResolver({
      'example.com|TXT': ['v=spf1 include:cheap.example include:expensive.example -all'],
      'cheap.example|TXT': ['v=spf1 ip4:192.0.2.1 -all'],
      'expensive.example|TXT': ['v=spf1 include:x.example include:y.example -all'],
      'x.example|TXT': ['v=spf1 ip4:192.0.2.2 -all'],
      'y.example|TXT': ['v=spf1 ip4:192.0.2.3 -all'],
    }),
  );

  const byTerm = Object.fromEntries(result.lookups.attribution.map((a) => [a.term, a.cost]));
  assert.equal(byTerm['include:cheap.example'], 1);
  assert.equal(byTerm['include:expensive.example'], 3);
});

test('an include with no SPF record counts as a void lookup and is reported', async () => {
  const result = await auditSpf(
    'example.com',
    new FakeResolver({
      'example.com|TXT': ['v=spf1 include:gone.example -all'],
      'gone.example|TXT': [],
    }),
  );

  assert.equal(result.lookups.void, 1);
  assert.equal(result.tree.children[0].domain, 'gone.example');
  assert.match(result.tree.children[0].error, /no SPF record/);
});

test('flags more than two void lookups', async () => {
  const result = await auditSpf(
    'example.com',
    new FakeResolver({
      'example.com|TXT': ['v=spf1 include:a.example include:b.example include:c.example -all'],
      'a.example|TXT': [],
      'b.example|TXT': [],
      'c.example|TXT': [],
    }),
  );
  assert.equal(result.lookups.void, 3);
  assert.equal(result.lookups.voidExceeded, true);
});

test('stops on an include loop instead of hanging', async () => {
  const result = await auditSpf(
    'example.com',
    new FakeResolver({
      'example.com|TXT': ['v=spf1 include:loop.example -all'],
      'loop.example|TXT': ['v=spf1 include:example.com -all'],
    }),
  );

  const loopNode = result.tree.children[0].children[0];
  assert.match(loopNode.error, /loop/);
});

test('macro terms cost a lookup but are not queried', async () => {
  // The malformed leftover of "%{i}._spf.example.com" must never be resolved,
  // because the resulting NXDOMAIN would be counted as a void lookup and could
  // report a healthy domain as broken.
  const resolver = new FakeResolver({
    'example.com|TXT': ['v=spf1 exists:%{i}._spf.example.com -all'],
  });

  const result = await auditSpf('example.com', resolver);
  assert.equal(result.lookups.used, 1);
  assert.equal(result.lookups.void, 0);
  assert.ok(!resolver.asked.some((q) => q.startsWith('._spf.example.com')));
});

test('reports multiple published SPF records', async () => {
  const result = await auditSpf(
    'example.com',
    new FakeResolver({ 'example.com|TXT': ['v=spf1 include:a.example -all', 'v=spf1 -all'] }),
  );
  assert.equal(result.records.length, 2);
});

test('detects the deprecated ptr mechanism anywhere in the chain', async () => {
  const result = await auditSpf(
    'example.com',
    new FakeResolver({
      'example.com|TXT': ['v=spf1 include:nested.example -all'],
      'nested.example|TXT': ['v=spf1 ptr -all'],
    }),
  );
  assert.equal(result.usesPtr, true);
});

test('reports no record when the domain publishes none', async () => {
  const result = await auditSpf('example.com', new FakeResolver({ 'example.com|TXT': [] }));
  assert.equal(result.found, false);
  assert.equal(result.lookups.used, 0);
});
