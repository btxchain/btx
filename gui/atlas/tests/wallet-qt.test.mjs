import test from 'node:test';
import assert from 'node:assert/strict';
import {createWalletDraft, coinSelectionSummary} from '../web/core/wallet-qt.js';

const draft = (overrides = {}) => createWalletDraft({
  name: 'primary',
  disablePrivateKeys: false,
  blank: false,
  passphrase: '',
  avoidReuse: true,
  descriptors: true,
  loadOnStartup: true,
  externalSigner: false,
  ...overrides,
});

test('createwallet draft keeps the eight-argument order', () => {
  assert.deepEqual(draft({
    name: 'savings',
    disablePrivateKeys: false,
    blank: true,
    passphrase: 'correct horse',
    avoidReuse: false,
    descriptors: true,
    loadOnStartup: false,
    externalSigner: false,
  }), ['savings', false, true, 'correct horse', false, true, false, false]);
  assert.equal(draft({passphrase: ''})[3], '');
  assert.equal(draft({name: 'n'.repeat(64), passphrase: 'p'.repeat(1024)}).length, 8);
});

test('external signer requires disabled private keys and descriptors', () => {
  assert.throws(() => draft({name: 'hardware', disablePrivateKeys: false, externalSigner: true}), /external signer/i);
  assert.throws(() => draft({name: 'hardware', disablePrivateKeys: true, descriptors: false, externalSigner: true}), /external signer/i);
  assert.deepEqual(draft({name: 'hardware', disablePrivateKeys: true, externalSigner: true}), ['hardware', true, false, '', true, true, true, true]);
  assert.throws(() => draft({name: ''}));
  assert.throws(() => draft({name: 'a\u0000b'}));
  assert.throws(() => draft({name: 'n'.repeat(65)}));
  assert.throws(() => draft({passphrase: 'p'.repeat(1025)}));
  assert.throws(() => draft({descriptors: 'true'}));
  assert.throws(() => draft({blank: 0}));
});

test('two coins of 0.5 and 0.25 sum exactly', () => {
  const summary = coinSelectionSummary([{amount: '0.5'}, {amount: '0.25'}]);
  assert.deepEqual(summary, {count: 2, amount: '0.75000000'});
  assert.equal(Object.hasOwn(summary, 'fee'), false);
  assert.equal(Object.hasOwn(summary, 'bytes'), false);
  assert.equal(Object.hasOwn(summary, 'change'), false);
  assert.throws(() => coinSelectionSummary({amount: '0.5'}));
  assert.deepEqual(coinSelectionSummary([]), {count: 0, amount: '0.00000000'});
});
