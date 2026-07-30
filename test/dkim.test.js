import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { parseDkimRecord, inspectKey, auditDkim } from '../src/dkim.js';
import { FakeResolver } from './helpers/fake-resolver.js';

/** Build a DKIM record around a genuinely generated key of the given size. */
function makeRsaRecord(modulusLength, extra = '') {
  const { publicKey } = generateKeyPairSync('rsa', { modulusLength });
  const base64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return `v=DKIM1; k=rsa;${extra} p=${base64}`;
}

test('parses tags out of a key record', () => {
  const tags = parseDkimRecord('v=DKIM1; k=rsa; t=y; p=AAAA');
  assert.equal(tags.v, 'DKIM1');
  assert.equal(tags.k, 'rsa');
  assert.equal(tags.t, 'y');
  assert.equal(tags.p, 'AAAA');
});

test('reads the real modulus length from a 2048-bit key', () => {
  const key = inspectKey(parseDkimRecord(makeRsaRecord(2048)));
  assert.equal(key.keyType, 'rsa');
  assert.equal(key.bits, 2048);
  assert.equal(key.revoked, false);
  assert.equal(key.error, null);
});

test('reads the real modulus length from a 1024-bit key', () => {
  const key = inspectKey(parseDkimRecord(makeRsaRecord(1024)));
  assert.equal(key.bits, 1024);
});

test('treats an empty p= as a revoked key', () => {
  const key = inspectKey(parseDkimRecord('v=DKIM1; k=rsa; p='));
  assert.equal(key.revoked, true);
  assert.equal(key.bits, null);
});

test('reports an unreadable key rather than guessing', () => {
  const key = inspectKey(parseDkimRecord('v=DKIM1; k=rsa; p=not-really-base64-der!!'));
  assert.equal(key.revoked, false);
  assert.match(key.error, /not valid base64 DER/);
});

test('understands ed25519 keys', () => {
  const p = Buffer.alloc(32, 7).toString('base64');
    const key = inspectKey(parseDkimRecord(`v=DKIM1; k=ed25519; p=${p}`));
  assert.equal(key.keyType, 'ed25519');
  assert.equal(key.bits, 256);
  assert.equal(key.error, null);
});

test('tolerates whitespace inside the base64 key', () => {
  // Long keys are split across TXT chunks and some DNS UIs reintroduce spaces.
  const record = makeRsaRecord(2048);
  const withSpaces = record.replace(/p=(.*)$/, (_m, p) => `p=${p.slice(0, 40)} ${p.slice(40)}`);
  assert.equal(inspectKey(parseDkimRecord(withSpaces)).bits, 2048);
});

/* ---------------------------------------------------------------- probing */

test('finds a key on a user-supplied selector', async () => {
  const record = makeRsaRecord(2048);
  const resolver = new FakeResolver({ 'custom._domainkey.example.com|TXT': [record] });

  const result = await auditDkim('example.com', resolver, { selectors: ['custom'], deep: false });
  assert.equal(result.found, true);
  assert.equal(result.keys.length, 1);
  assert.equal(result.keys[0].selector, 'custom');
  assert.equal(result.keys[0].bits, 2048);
});

test('flags a selector left in testing mode', async () => {
  const resolver = new FakeResolver({
    'google._domainkey.example.com|TXT': [makeRsaRecord(2048, ' t=y;')],
  });

  const result = await auditDkim('example.com', resolver, { deep: false });
  assert.equal(result.keys[0].testing, true);
});

test('reports nothing found without claiming DKIM is absent', async () => {
  const result = await auditDkim('example.com', new FakeResolver({}), { deep: false });
  assert.equal(result.found, false);
  assert.ok(result.selectorsProbed > 0);
});

test('probes more selectors in deep mode than in fast mode', async () => {
  const fast = await auditDkim('example.com', new FakeResolver({}), { deep: false });
  const deep = await auditDkim('example.com', new FakeResolver({}), { deep: true });
  assert.ok(deep.selectorsProbed > fast.selectorsProbed);
});
