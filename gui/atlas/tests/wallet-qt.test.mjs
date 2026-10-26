import test from 'node:test';
import assert from 'node:assert/strict';
import {createWalletDraft, coinSelectionSummary, receivingAddressArgs, historyWalk, historyActions, nextHistorySkip, coinTree, psbtWithinLimit, addressFacts, walletFacts} from '../web/core/wallet-qt.js';

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

test('receiving address args pass a known type and reject anything else', () => {
  assert.deepEqual(receivingAddressArgs('donation', ''), ['donation']);
  assert.deepEqual(receivingAddressArgs('', ''), ['']);
  assert.deepEqual(receivingAddressArgs('donation', 'p2mr'), ['donation', 'p2mr']);
  for (const addressType of ['bech32', 'bech32m', 'legacy', 'p2sh-segwit', 'p2pkh']) {
    assert.throws(() => receivingAddressArgs('donation', addressType), {message: 'Address type is not supported'});
  }
  assert.throws(() => receivingAddressArgs('donation', 'BECH32'), {message: 'Address type is not supported'});
  assert.throws(() => receivingAddressArgs('donation', undefined), {message: 'Address type is not supported'});
  assert.throws(() => receivingAddressArgs('donation', null), {message: 'Address type is not supported'});
  assert.throws(() => receivingAddressArgs(null, ''), {message: 'Label must be a string'});
  assert.throws(() => receivingAddressArgs(1, 'p2mr'), {message: 'Label must be a string'});
  assert.throws(() => receivingAddressArgs(undefined, 'p2mr'), {message: 'Label must be a string'});
});

test('history walk is a fixed page and the caller owns the cap', () => {
  const walk = historyWalk({pageSize: 100, cap: 2000});
  assert.deepEqual(walk, {pageSize: 100, cap: 2000});
  walk.pageSize = 1;
  assert.deepEqual(historyWalk({pageSize: 100, cap: 2000}), {pageSize: 100, cap: 2000});
  assert.throws(() => historyWalk({pageSize: 50, cap: 2000}), {message: 'History walk requires page size 100 and cap 2000'});
  assert.throws(() => historyWalk({pageSize: 100, cap: 1999}), {message: 'History walk requires page size 100 and cap 2000'});
  assert.equal(nextHistorySkip(0, 100, 100), 100);
  assert.equal(nextHistorySkip(1900, 100, 100), 2000);
  assert.equal(nextHistorySkip(0, 99, 100), null);
  assert.equal(nextHistorySkip(0, 0, 100), null);
  assert.throws(() => nextHistorySkip(-1, 100, 100), {message: 'Skip must be a non-negative integer'});
  assert.throws(() => nextHistorySkip(1.5, 100, 100), {message: 'Skip must be a non-negative integer'});
  assert.throws(() => nextHistorySkip('0', 100, 100), {message: 'Skip must be a non-negative integer'});
  const {pageSize, cap} = historyWalk({pageSize: 100, cap: 2000});
  const loaded = [];
  const fetches = [];
  let skip = 0;
  while (loaded.length < cap) {
    fetches.push(skip);
    const rows = Array.from({length: pageSize}, (_, i) => skip + i);
    const next = nextHistorySkip(skip, rows.length, pageSize);
    const room = cap - loaded.length;
    if (rows.length > room) {
      loaded.push(...rows.slice(0, room));
      break;
    }
    loaded.push(...rows);
    if (next === null || loaded.length >= cap) break;
    skip = next;
  }
  assert.equal(loaded.length, cap);
  assert.equal(fetches.length, 20);
  assert.deepEqual(fetches.slice(0, 3), [0, 100, 200]);
  assert.equal(fetches.at(-1), 1900);
  assert.equal(nextHistorySkip(0, 40, pageSize), null);
});

test('history actions allow bump and abandon only for an unconfirmed send', () => {
  const neither = {bump: false, abandon: false};
  assert.deepEqual(historyActions({category: 'generate', confirmations: 93, 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions({category: 'send', confirmations: 0, 'bip125-replaceable': 'yes'}), {bump: true, abandon: true});
  assert.deepEqual(historyActions({category: 'send', confirmations: 0, 'bip125-replaceable': 'no'}), {bump: false, abandon: true});
  assert.deepEqual(historyActions({category: 'receive', confirmations: 0, 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions({category: 'immature', confirmations: 0}), neither);
  assert.deepEqual(historyActions({category: 'orphan', confirmations: 0, 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions({category: 'send', confirmations: 1, 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions({category: 'send', 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions({confirmations: 0, 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions(null), neither);
  // the desktop app: RPC numbers arrive as exact decimal strings (strict_json::for_ui)
  assert.deepEqual(historyActions({category: 'send', confirmations: '0', 'bip125-replaceable': 'yes'}), {bump: true, abandon: true});
  assert.deepEqual(historyActions({category: 'send', confirmations: '0', 'bip125-replaceable': 'no'}), {bump: false, abandon: true});
  for (const c of ['1', '00', '-0', '0.0', ' 0', '', '-1']) {
    assert.deepEqual(historyActions({category: 'send', confirmations: c, 'bip125-replaceable': 'yes'}), neither, c);
  }
  assert.deepEqual(historyActions({category: 'generate', confirmations: '0', 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions({category: 'Send', confirmations: 0, 'bip125-replaceable': 'yes'}), neither);
  assert.deepEqual(historyActions({category: 'send', confirmations: 0, 'bip125-replaceable': 'unknown'}), {bump: false, abandon: true});
});

test('coin tree groups labels and addresses without dropping coins', () => {
  const savingsA = {address: 'b', label: 'savings', amount: '1', txid: 't1', vout: 0};
  const savingsB = {address: 'a', label: 'savings', amount: '2', txid: 't2', vout: 1};
  const mineFirst = {address: 'a', label: 'mine', amount: '3', txid: 't4', vout: 0};
  const mineSecond = {address: 'a', label: 'mine', amount: '4', txid: 't3', vout: 1};
  const unlabeled = {amount: '5', txid: 't5', vout: 2};
  const input = [savingsA, savingsB, mineFirst, mineSecond, unlabeled];
  const tree = coinTree(input);
  assert.deepEqual(input.map((coin) => coin.txid), ['t1', 't2', 't4', 't3', 't5']);
  assert.deepEqual(tree.map((group) => group.label), ['', 'mine', 'savings']);
  assert.equal(tree[0].addresses.length, 1);
  assert.equal(tree[0].addresses[0].address, '');
  assert.equal(tree[0].addresses[0].coins[0], unlabeled);
  assert.deepEqual(tree[1].addresses.map((bucket) => bucket.address), ['a']);
  assert.deepEqual(tree[1].addresses[0].coins, [mineFirst, mineSecond]);
  assert.equal(tree[1].addresses[0].coins[0], mineFirst);
  assert.deepEqual(tree[2].addresses.map((bucket) => bucket.address), ['a', 'b']);
  assert.equal(tree[2].addresses[0].coins[0], savingsB);
  assert.equal(tree[2].addresses[1].coins[0], savingsA);
  const repeated = {address: 'a', label: 'mine', amount: '1', txid: 't', vout: 0};
  assert.equal(coinTree([repeated, repeated])[0].addresses[0].coins.length, 2);
  assert.equal(coinTree([repeated, repeated]).flatMap((group) => group.addresses.flatMap((bucket) => bucket.coins)).length, 2);
  assert.deepEqual(coinTree([]), []);
  assert.throws(() => coinTree(null), {message: 'Coins must be an array'});
  assert.throws(() => coinTree({length: 1}), {message: 'Coins must be an array'});
});

test('psbt text is within limit only for a string of at most one million characters', () => {
  assert.equal(psbtWithinLimit(''), true);
  assert.equal(psbtWithinLimit('cHNidP8'), true);
  assert.equal(psbtWithinLimit('x'.repeat(1000000)), true);
  assert.equal(psbtWithinLimit('x'.repeat(1000001)), false);
  assert.equal(psbtWithinLimit(null), false);
  assert.equal(psbtWithinLimit(undefined), false);
  assert.equal(psbtWithinLimit(1000000), false);
  assert.equal(psbtWithinLimit(['psbt']), false);
});

test('address facts for a valid address this wallet reports as mine', () => {
  assert.deepEqual(addressFacts({
    solvable: true,
    iswitness: true,
    isscript: false,
    iswatchonly: false,
    ismine: true,
    isvalid: true,
  }), {
    lines: [
      'isvalid: yes',
      'ismine: yes',
      'iswatchonly: no',
      'isscript: no',
      'iswitness: yes',
      'solvable: yes',
    ],
    warning: null,
  });
});

test('address facts warn when the node does not consider the address valid', () => {
  const facts = addressFacts({isvalid: false, ismine: false, iswatchonly: true});
  assert.deepEqual(facts.lines, ['isvalid: no', 'ismine: no', 'iswatchonly: yes']);
  assert.equal(facts.warning, 'The node does not consider this address valid.');
});

test('address facts warn when the wallet does not report the address as mine', () => {
  assert.deepEqual(addressFacts({isvalid: true, ismine: false, solvable: true}), {
    lines: ['isvalid: yes', 'ismine: no', 'solvable: yes'],
    warning: 'This wallet does not report the address as mine.',
  });
  assert.equal(addressFacts({ismine: false}).warning, 'This wallet does not report the address as mine.');
  assert.deepEqual(addressFacts({ismine: false}).lines, ['ismine: no']);
});

test('address facts reject a non-object without throwing', () => {
  const expected = {lines: [], warning: 'Address information was not an object.'};
  for (const info of [null, undefined, 'btx1qexample', 1, true, ['isvalid']]) {
    assert.deepEqual(addressFacts(info), expected);
  }
  assert.doesNotThrow(() => addressFacts(null));
});

test('address facts ignore a scriptPubKey object and every other key', () => {
  const facts = addressFacts({
    address: 'btx1qexample',
    scriptPubKey: {asm: 'OP_TRUE', hex: '51', type: 'witness_v0_keyhash'},
    isvalid: true,
    ismine: true,
    isscript: 'false',
    solvable: true,
  });
  assert.deepEqual(facts, {
    lines: ['isvalid: yes', 'ismine: yes', 'solvable: yes'],
    warning: null,
  });
  assert.equal(facts.lines.some((line) => line.includes('scriptPubKey') || line.includes('OP_TRUE') || line.includes('hex')), false);
});

test('wallet facts include a non-negative transaction count', () => {
  assert.deepEqual(walletFacts({txcount: 0}), ['Transactions: 0']);
  assert.deepEqual(walletFacts({txcount: 12}), ['Transactions: 12']);
  assert.deepEqual(walletFacts({txcount: '0'}), ['Transactions: 0']);
  assert.deepEqual(walletFacts({txcount: '12'}), ['Transactions: 12']);
  assert.deepEqual(walletFacts({txcount: Number.MAX_SAFE_INTEGER}), [`Transactions: ${Number.MAX_SAFE_INTEGER}`]);
  assert.deepEqual(walletFacts({txcount: String(Number.MAX_SAFE_INTEGER)}), [`Transactions: ${Number.MAX_SAFE_INTEGER}`]);
  assert.deepEqual(walletFacts({txcount: -1}), []);
  assert.deepEqual(walletFacts({txcount: 1.5}), []);
  assert.deepEqual(walletFacts({txcount: true}), []);
  assert.deepEqual(walletFacts({txcount: Number.MAX_SAFE_INTEGER + 1}), []);
  assert.deepEqual(walletFacts({txcount: String(Number.MAX_SAFE_INTEGER + 1)}), []);
  for (const txcount of ['00', '-0', '0.0', ' 0', '', '-1', '1.5']) {
    assert.deepEqual(walletFacts({txcount}), [], txcount);
  }
  const counted = walletFacts({txcount: 3, balance: 1.25, unconfirmed_balance: 2, immature_balance: 3, hdseedid: 'seed', seed: 'abandon abandon'});
  assert.deepEqual(counted, ['Transactions: 3']);
  assert.equal(counted.some((line) => /balance|seed|abandon/i.test(line)), false);
});

test('wallet facts include descriptors only as yes or no', () => {
  assert.deepEqual(walletFacts({descriptors: true}), ['Descriptors: yes']);
  assert.deepEqual(walletFacts({descriptors: false}), ['Descriptors: no']);
  assert.deepEqual(walletFacts({descriptors: 'true'}), []);
  assert.deepEqual(walletFacts({descriptors: 1}), []);
  assert.deepEqual(walletFacts({descriptors: true, balance: '9.5', hdseedid: 'seed'}), ['Descriptors: yes']);
});

test('wallet facts say the wallet is locked when unlock expiry is zero', () => {
  assert.deepEqual(walletFacts({unlocked_until: 0}), ['This wallet is locked.']);
  assert.deepEqual(walletFacts({unlocked_until: '0'}), ['This wallet is locked.']);
  assert.deepEqual(walletFacts({unlocked_until: -1}), []);
  assert.deepEqual(walletFacts({unlocked_until: false}), []);
  for (const unlocked_until of ['00', '-0', '0.0', ' 0', '', '-1', '1.5']) {
    assert.deepEqual(walletFacts({unlocked_until}), [], unlocked_until);
  }
  assert.deepEqual(walletFacts({unlocked_until: 0, balance: 4, seed: 'seed phrase'}), ['This wallet is locked.']);
});

test('wallet facts report an unlock expiry for a positive safe integer', () => {
  assert.deepEqual(walletFacts({unlocked_until: 1}), ['This wallet reports an unlock expiry.']);
  assert.deepEqual(walletFacts({unlocked_until: '1700000000'}), ['This wallet reports an unlock expiry.']);
  assert.deepEqual(walletFacts({unlocked_until: Number.MAX_SAFE_INTEGER}), ['This wallet reports an unlock expiry.']);
  assert.deepEqual(walletFacts({unlocked_until: String(Number.MAX_SAFE_INTEGER)}), ['This wallet reports an unlock expiry.']);
  assert.deepEqual(walletFacts({unlocked_until: 1.5}), []);
  assert.deepEqual(walletFacts({unlocked_until: Number.MAX_SAFE_INTEGER + 1}), []);
  assert.deepEqual(walletFacts({unlocked_until: String(Number.MAX_SAFE_INTEGER + 1)}), []);
  assert.deepEqual(walletFacts({
    txcount: 4,
    descriptors: true,
    unlocked_until: 1700000000,
    balance: '9.5',
    immature_balance: 1,
    hdseedid: 'seed',
  }), [
    'Transactions: 4',
    'Descriptors: yes',
    'This wallet reports an unlock expiry.',
  ]);
});

test('wallet facts return an empty list for a non-object', () => {
  for (const info of [null, undefined, 'wallet', 0, true, ['txcount']]) {
    assert.deepEqual(walletFacts(info), []);
    assert.doesNotThrow(() => walletFacts(info));
  }
  const throwing = {};
  Object.defineProperty(throwing, 'txcount', {get() { throw new Error('no'); }});
  assert.doesNotThrow(() => walletFacts(throwing));
  assert.deepEqual(walletFacts(throwing), []);
});
