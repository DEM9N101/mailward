import test from 'node:test';
import assert from 'node:assert/strict';
import { parseXml, child, children, text } from '../src/report/xml.js';

test('parses nested elements and text', () => {
  const root = parseXml('<a><b><c>hello</c></b></a>');
  assert.equal(root.name, 'a');
  assert.equal(text(root, 'b', 'c'), 'hello');
});

test('skips the XML declaration, comments and doctypes', () => {
  const root = parseXml('<?xml version="1.0"?><!-- note --><!DOCTYPE x><feedback><a>1</a></feedback>');
  assert.equal(root.name, 'feedback');
  assert.equal(text(root, 'a'), '1');
});

test('handles self-closing elements', () => {
  const root = parseXml('<a><b/><c>2</c></a>');
  assert.equal(child(root, 'b').children.length, 0);
  assert.equal(text(root, 'c'), '2');
});

test('collects repeated siblings', () => {
  const root = parseXml('<a><r>1</r><r>2</r><r>3</r></a>');
  assert.equal(children(root, 'r').length, 3);
  assert.deepEqual(children(root, 'r').map((n) => n.text.trim()), ['1', '2', '3']);
});

test('decodes named and numeric entities', () => {
  const root = parseXml('<a>&lt;tag&gt; &amp; &quot;quotes&quot; &#65;&#x42;</a>');
  assert.equal(root.text.trim(), '<tag> & "quotes" AB');
});

test('reads CDATA verbatim', () => {
  const root = parseXml('<a><![CDATA[raw <not a tag> & stuff]]></a>');
  assert.equal(root.text.trim(), 'raw <not a tag> & stuff');
});

test('parses attributes, including values containing >', () => {
  const root = parseXml('<a id="1" note="a > b"><b/></a>');
  assert.equal(root.attrs.id, '1');
  assert.equal(root.attrs.note, 'a > b');
  assert.equal(child(root, 'b').name, 'b');
});

test('recovers from a truncated document instead of throwing', () => {
  // Report files do occasionally arrive truncated; reading what is there beats
  // discarding the whole file.
  const root = parseXml('<feedback><record><row>1</row></record>');
  assert.equal(root.name, 'feedback');
  assert.equal(text(root, 'record', 'row'), '1');
});

test('throws when there is no element at all', () => {
  assert.throws(() => parseXml('not xml'), /no XML element found/);
});

test('text() returns an empty string for a missing path', () => {
  const root = parseXml('<a><b>1</b></a>');
  assert.equal(text(root, 'nope', 'nothing'), '');
});
