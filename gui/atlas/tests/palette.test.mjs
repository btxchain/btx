import {test} from 'node:test';
import assert from 'node:assert/strict';
import {installDom, findAll, settle, fakeApp} from './dom-stub.mjs';
import {OPERATIONS, BY_METHOD} from '../web/core/catalog.js';
import {operationDialog} from '../web/views/operations.js';
import {walletView} from '../web/views/wallet.js';
import {paletteEntries} from '../web/core/palette.js';

installDom();

// The same shape as VIEWS in web/app.js: [id, glyph, label]. No workspace label contains "send".
const VIEWS = [['network', '◎', 'Network'], ['models', '▤', 'Models'], ['wallet', '▱', 'Wallet'], ['settings', '⚙', 'Settings']];
const RAW_SENDS = ['sendrawtransaction', 'sendtoaddress', 'sendmany'];

test('"send" in the palette offers the Wallet → Send composer first', () => {
  for (const query of ['send', 'Send', 'SEND']) {
    const entries = paletteEntries(VIEWS, OPERATIONS, query);
    assert.deepEqual(entries[0], {kind: 'send', title: 'Send BTX · Wallet → Send composer'});
    for (const method of RAW_SENDS) assert.ok(entries.findIndex((e) => e.method === method) > 0, method);
  }
});

test('the raw send templates say they bypass the composer, in the palette and in their dialog', () => {
  const entries = paletteEntries(VIEWS, OPERATIONS, '');
  const all = paletteEntries(VIEWS, OPERATIONS, 'send');
  for (const method of RAW_SENDS) {
    const entry = all.find((e) => e.method === method);
    assert.match(entry.title, /bypasses Wallet → Send checks$/);
    assert.match(BY_METHOD.get(method).notes, /Wallet → Send/);
    const d = operationDialog(fakeApp(), method, [], 'test');
    assert.match(d.element.textContent, /Use Wallet → Send for a normal payment/);
    d.close();
  }
  assert.doesNotMatch(paletteEntries(VIEWS, OPERATIONS, 'bumpfee')[0].title, /bypasses/);
  assert.equal(entries.length, 25);
  assert.deepEqual(entries.slice(0, VIEWS.length).map((e) => e.view), VIEWS.map((v) => v[0]));
});

test('the composer entry opens Wallet on the Send tab', async () => {
  const app = fakeApp();
  app.preferences = {unit: 'BTX'};
  app.state.state.wallet = '';
  app.state.update = () => {};
  app.bridge.read = async () => ({result: []});
  const active = (root) => findAll(root, (n) => n.tagName === 'BUTTON' && n.dataset.walletTab && n.classList.contains('active')).map((n) => n.dataset.walletTab);
  const send = walletView(app, {tab: 'Send'});
  await settle();
  assert.deepEqual(active(send), ['Send']);
  const plain = walletView(app);
  await settle();
  assert.deepEqual(active(plain), ['Overview']);
});
