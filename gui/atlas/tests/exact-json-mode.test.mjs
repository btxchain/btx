import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {installDom, findAll, fieldInput, fire, fakeApp} from './dom-stub.mjs';
import {operationDialog} from '../web/views/operations.js';
import {OPERATIONS} from '../web/core/catalog.js';

installDom();

// Top-level rules of the stylesheet as [selector, declarations]; @media and other at-rule blocks are skipped.
function topLevelRules(css) {
  const rules = [];
  let i = 0;
  while (i < css.length) {
    const open = css.indexOf('{', i);
    if (open < 0) break;
    const selector = css.slice(i, open).trim();
    let depth = 1, j = open + 1;
    while (j < css.length && depth) { if (css[j] === '{') depth++; else if (css[j] === '}') depth--; j++; }
    if (!selector.startsWith('@')) rules.push([selector, css.slice(open + 1, j - 1)]);
    i = j;
  }
  return rules;
}

test('the hidden attribute hides an element whatever its display rule', () => {
  const css = fs.readFileSync(new URL('../web/style.css', import.meta.url), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
  const rules = topLevelRules(css);
  const hidden = rules.filter(([selector]) => selector.split(',').map((x) => x.trim()).includes('[hidden]'));
  assert.equal(hidden.length, 1, 'no top-level [hidden] rule');
  assert.match(hidden[0][1].replace(/\s+/g, ''), /(^|;)display:none!important(;|$)/);
  // .fields{display:grid} is what kept the form visible in JSON mode; no rule may force a display back over [hidden].
  assert.ok(rules.some(([selector, body]) => selector === '.fields' && /display:grid/.test(body)));
  assert.equal(/display:\s*(?!none)[a-z-]+\s*!important/.test(css), false);
});

test('exact JSON mode hides the field form and shows only the JSON editor', () => {
  const d = operationDialog(fakeApp(), 'disconnectnode', ['192.0.2.1:19335']);
  const form = findAll(d.element, (n) => n.className === 'fields')[0];
  const raw = findAll(d.element, (n) => n.getAttribute('aria-label') === 'Exact JSON RPC parameters')[0];
  const useRaw = fieldInput(d.element, 'Use exact JSON array/object');
  assert.deepEqual([form.hidden, raw.hidden], [false, true]);
  useRaw.checked = true;
  fire(useRaw, 'change');
  assert.deepEqual([form.hidden, raw.hidden], [true, false]);
  useRaw.checked = false;
  fire(useRaw, 'change');
  assert.deepEqual([form.hidden, raw.hidden], [false, true]);
  d.close();
});

test('a typed passphrase never reaches the exact JSON editor', () => {
  const d = operationDialog(fakeApp(), 'createwallet', ['fresh', false, false, 'correct horse battery', true, true, true, false]);
  const raw = findAll(d.element, (n) => n.getAttribute('aria-label') === 'Exact JSON RPC parameters')[0];
  const useRaw = fieldInput(d.element, 'Use exact JSON array/object');
  assert.equal(raw.value.includes('correct horse battery'), false);
  assert.equal(useRaw.disabled, true);
  assert.equal(raw.hidden, true);
  assert.match(d.element.textContent, /never shown in clear text/);
  d.close();
});

test('exact JSON mode is not offered for any operation that takes a passphrase', () => {
  const methods = OPERATIONS.filter((o) => o.args.some((a) => a.kind === 'secret')).map((o) => o.method);
  assert.deepEqual(methods.toSorted(), ['createwallet', 'encryptwallet', 'migratewallet', 'walletpassphrase', 'walletpassphrasechange']);
  for (const method of methods) {
    const d = operationDialog(fakeApp(), method, [], 'test');
    assert.equal(fieldInput(d.element, 'Use exact JSON array/object').disabled, true, method);
    d.close();
  }
});

test('exact JSON mode stays available and prefilled for an operation without a secret', () => {
  const d = operationDialog(fakeApp(), 'disconnectnode', ['192.0.2.1:19335']);
  const raw = findAll(d.element, (n) => n.getAttribute('aria-label') === 'Exact JSON RPC parameters')[0];
  assert.equal(fieldInput(d.element, 'Use exact JSON array/object').disabled, false);
  assert.equal(raw.value, '["192.0.2.1:19335"]');
  d.close();
});
