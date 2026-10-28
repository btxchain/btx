import test from 'node:test';
import assert from 'node:assert/strict';
import {aboutFacts, txExplorerTemplate} from '../web/core/qt-surface.js';

test('accepts https://example.invalid/tx/%s', () => {
  const value = 'https://example.invalid/tx/%s';
  assert.equal(txExplorerTemplate(value), value);
});

test('rejects http', () => {
  assert.equal(txExplorerTemplate('http://example.invalid/tx/%s'), '');
  assert.equal(txExplorerTemplate('http://example.invalid/https/%s'), '');
});

test('rejects two %s', () => {
  assert.equal(txExplorerTemplate('https://example.invalid/tx/%s/%s'), '');
  assert.equal(txExplorerTemplate('https://example.invalid/%s/tx/%s'), '');
});

test('rejects javascript', () => {
  assert.equal(txExplorerTemplate('https://example.invalid/javascript/%s'), '');
  assert.equal(txExplorerTemplate('https://example.invalid/JavaScript/%s'), '');
  assert.equal(txExplorerTemplate('javascript:https://example.invalid/%s'), '');
});

test('rejects data, whitespace, controls, and lengths outside 12..300', () => {
  assert.equal(txExplorerTemplate('https://example.invalid/data:/%s'), '');
  assert.equal(txExplorerTemplate('https://example.invalid/DATA:/%s'), '');
  assert.equal(txExplorerTemplate('https://example.invalid/tx/%s '), '');
  assert.equal(txExplorerTemplate('https://example.invalid/tx/%s\n'), '');
  assert.equal(txExplorerTemplate('https://example.invalid/tx/%s\u0000'), '');
  assert.equal(txExplorerTemplate('https://example.invalid/tx/%s\u007f'), '');
  assert.equal(txExplorerTemplate(''), '');
  assert.equal(txExplorerTemplate(null), '');
  assert.equal(txExplorerTemplate('https://%s'), '');
  const fitted = `https://${'a'.repeat(290)}%s`;
  assert.equal(fitted.length, 300);
  assert.equal(txExplorerTemplate(fitted), fitted);
  assert.equal(txExplorerTemplate(`${fitted}a`), '');
  assert.equal(txExplorerTemplate('https://a/%s'), 'https://a/%s');
});

test('aboutFacts.qualification is the source candidate string', () => {
  const facts = aboutFacts();
  assert.equal(facts.qualification, 'SOURCE_CANDIDATE_NOT_RELEASE_QUALIFIED');
  assert.deepEqual(facts, {
    name: 'BTX Atlas',
    role: 'Interface to this node on the BTX peer network',
    qualification: 'SOURCE_CANDIDATE_NOT_RELEASE_QUALIFIED',
    spends: 'A model cannot approve a spend or a peer change',
  });
  assert.equal(Object.isFrozen(facts), true);
});
