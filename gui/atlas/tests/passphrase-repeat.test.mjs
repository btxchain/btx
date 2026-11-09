import {test} from 'node:test';
import assert from 'node:assert/strict';
import {installDom, findAll, fieldInput, buttonNamed, fire, settle, fakeApp} from './dom-stub.mjs';
import {operationDialog} from '../web/views/operations.js';
import {walletView} from '../web/views/wallet.js';

const document = installDom();

// Each method that sets a new wallet passphrase, the argument that takes it,
// and the other fields a valid request needs.
const NEW_PASSPHRASE = [
  {method: 'encryptwallet', name: 'passphrase', other: {}, wire: (p) => [p]},
  {method: 'walletpassphrasechange', name: 'newpassphrase', other: {oldpassphrase: 'old words'}, wire: (p) => ['old words', p]},
  {method: 'createwallet', name: 'passphrase', other: {wallet_name: 'fresh'}, wire: (p) => ['fresh', false, false, p, true, true, true, false]},
];

for (const {method, name, other, wire} of NEW_PASSPHRASE) {
  test(`${method} asks for ${name} twice and refuses a mismatch before the native review`, async () => {
    const app = fakeApp();
    const d = operationDialog(app, method, [], 'test');
    for (const [field, value] of Object.entries(other)) fieldInput(d.element, field).value = value;
    const first = fieldInput(d.element, name);
    const repeat = fieldInput(d.element, `Repeat ${name}`);
    assert.ok(repeat, `no repeat field for ${name}`);
    assert.equal(repeat.getAttribute('type'), 'password');
    const prepare = buttonNamed(d.element, 'Prepare for native review');

    first.value = 'correct horse battery';
    repeat.value = 'correct horse batery';
    fire(prepare, 'click');
    await settle();
    assert.equal(app.prepared.length, 0);
    assert.match(d.element.textContent, new RegExp(`${name}: the two entries do not match`));

    repeat.value = 'correct horse battery';
    fire(prepare, 'click');
    await settle();
    assert.equal(app.prepared.length, 1);
    assert.equal(app.prepared[0].json, JSON.stringify(wire('correct horse battery')));
    assert.equal(first.value, '');
    assert.equal(repeat.value, '');
    d.close();
  });
}

test('the dialogs that set a passphrase warn that a lost passphrase loses the funds', () => {
  for (const {method} of NEW_PASSPHRASE) {
    const d = operationDialog(fakeApp(), method, [], 'test');
    assert.match(d.element.textContent, /lose access to the BTX in this wallet/, method);
    d.close();
  }
});

test('entering an existing passphrase asks for it once', () => {
  for (const [method, name] of [['walletpassphrase', 'passphrase'], ['walletpassphrasechange', 'oldpassphrase'], ['migratewallet', 'passphrase']]) {
    const d = operationDialog(fakeApp(), method, [], 'test');
    assert.ok(fieldInput(d.element, name), `${method} has no ${name} field`);
    assert.equal(fieldInput(d.element, `Repeat ${name}`), undefined, `${method} repeats ${name}`);
    d.close();
  }
});

test('a passphrase prefilled from the Create wallet panel fills both entries', async () => {
  const app = fakeApp();
  const d = operationDialog(app, 'createwallet', ['fresh', false, false, 'correct horse battery', true, true, true, false]);
  assert.equal(fieldInput(d.element, 'passphrase').value, 'correct horse battery');
  assert.equal(fieldInput(d.element, 'Repeat passphrase').value, 'correct horse battery');
  fire(buttonNamed(d.element, 'Prepare for native review'), 'click');
  await settle();
  assert.equal(app.prepared.length, 1);
  d.close();
});

test('the Create wallet panel refuses a mismatched repeat and opens no review', async () => {
  const app = fakeApp();
  app.preferences = {unit: 'BTX'};
  app.state.state.wallet = '';
  app.state.update = () => {};
  app.bridge.read = async () => ({result: []});
  const root = walletView(app);
  await settle();
  fire(buttonNamed(root, 'Create'), 'click');
  await settle();
  const input = (label) => findAll(root, (n) => n.getAttribute('aria-label') === label)[0];
  assert.match(root.textContent, /lose access to the BTX in this wallet/);
  input('New wallet name').value = 'fresh';
  input('Wallet passphrase').value = 'correct horse battery';
  assert.ok(input('Repeat wallet passphrase'), 'no repeat field on the Create wallet panel');
  input('Repeat wallet passphrase').value = 'correct horse batery';
  const before = document.body.children.length;
  fire(buttonNamed(root, 'Create wallet'), 'click');
  await settle();
  assert.match(root.textContent, /The passphrases do not match/);
  assert.equal(document.body.children.length, before);
  input('Repeat wallet passphrase').value = 'correct horse battery';
  fire(buttonNamed(root, 'Create wallet'), 'click');
  await settle();
  assert.equal(document.body.children.length, before + 1);
  assert.equal(input('Wallet passphrase').value, '');
  assert.equal(input('Repeat wallet passphrase').value, '');
  document.body.children.at(-1).close();
});
