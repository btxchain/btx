import test from 'node:test';
import assert from 'node:assert/strict';
import {redactObservation, syncBanner, historyFilter, paymentRequest} from '../web/core/qt-gaps.js';

test('redact hides credential_ref and query, keeps name, does not mutate input', () => {
  const input = {
    name: 'atlas',
    credential_ref: 'sekret',
    query: 'select',
    note: 'credential_ref',
    count: 2,
    ok: false,
    nested: {name: 'inner', token: 'abc', items: [1, 'keep']},
  };
  const snapshot = JSON.parse(JSON.stringify(input));
  const out = redactObservation(input);
  assert.equal(out.name, 'atlas');
  assert.equal(out.credential_ref, '[hidden]');
  assert.equal(out.query, '[hidden]');
  assert.equal(out.note, 'credential_ref');
  assert.equal(out.count, 2);
  assert.equal(out.ok, false);
  assert.equal(out.nested.name, 'inner');
  assert.equal(out.nested.token, '[hidden]');
  assert.deepEqual(out.nested.items, [1, 'keep']);
  assert.notEqual(out, input);
  assert.notEqual(out.nested, input.nested);
  assert.notEqual(out.nested.items, input.nested.items);
  assert.deepEqual(input, snapshot);
  const cycle = {name: 'loop', credential_ref: 'sekret'};
  cycle.self = cycle;
  const looped = redactObservation(cycle);
  assert.equal(looped.name, 'loop');
  assert.equal(looped.credential_ref, '[hidden]');
  assert.equal(Object.hasOwn(looped, 'self'), false);
  assert.equal(cycle.self, cycle);
});

test('syncBanner hidden for null; visible for initialblockdownload; visible for progress 0.5; visible for a warning; hidden for progress 1 and empty warnings; detail does not contain qualified', () => {
  assert.deepEqual(syncBanner(null), {visible: false, title: '', detail: ''});
  const ibd = syncBanner({initialblockdownload: true, verificationprogress: 0.25});
  assert.equal(ibd.visible, true);
  assert.equal(ibd.title, 'Initial block download');
  assert.match(ibd.detail, /25\.00%/);
  const mid = syncBanner({initialblockdownload: false, verificationprogress: 0.5, warnings: ''});
  assert.equal(mid.visible, true);
  assert.equal(mid.title, 'Synchronization in progress');
  assert.match(mid.detail, /50\.00%/);
  const warn = syncBanner({verificationprogress: 1, warnings: '  disk space low  '});
  assert.equal(warn.visible, true);
  assert.equal(warn.title, 'Node warning');
  assert.match(warn.detail, /100\.00%/);
  assert.match(warn.detail, /disk space low/);
  const done = syncBanner({verificationprogress: 1, warnings: ''});
  assert.equal(done.visible, false);
  assert.equal(done.title, '');
  assert.equal(done.detail, '');
  for (const banner of [ibd, mid, warn, done]) {
    assert.equal(banner.detail.includes('qualified'), false);
    assert.doesNotMatch(`${banner.title}\n${banner.detail}`, /verified|qualified|passed/i);
  }
});

test('historyFilter filters category and query and does not mutate', () => {
  const rows = [
    {txid: 'AA11', address: 'addrSend', label: 'Cafe', category: 'send'},
    {txid: 'bb22', address: 'addrRecv', label: 'Rent', category: 'receive'},
    {txid: 'cc33', address: 'addrGen', label: 'Coinbase', category: 'generate'},
  ];
  const snapshot = JSON.parse(JSON.stringify(rows));
  assert.deepEqual(historyFilter(rows, {category: 'receive'}).map((row) => row.txid), ['bb22']);
  assert.deepEqual(historyFilter(rows, {query: 'cafe'}).map((row) => row.txid), ['AA11']);
  assert.deepEqual(historyFilter(rows, {query: 'aa11'}).map((row) => row.txid), ['AA11']);
  assert.deepEqual(historyFilter(rows, {category: 'receive', query: 'rent'}).map((row) => row.txid), ['bb22']);
  assert.deepEqual(historyFilter(rows, {category: 'send', query: 'rent'}), []);
  const copy = historyFilter(rows);
  assert.notEqual(copy, rows);
  assert.equal(copy.length, rows.length);
  assert.equal(copy[0], rows[0]);
  assert.deepEqual(rows, snapshot);
  assert.deepEqual(historyFilter(null), []);
  assert.deepEqual(historyFilter({length: 1}), []);
});

test('paymentRequest includes amount, label, and message for a 20-character alphanumeric address and amount 0.00000001; rejects an empty address', () => {
  const address = 'a1b2c3d4e5f6g7h8i9j0';
  assert.equal(address.length, 20);
  const uri = paymentRequest({address, amount: '0.00000001', label: 'Rent', message: 'Thanks'});
  assert.equal(typeof uri, 'string');
  assert.ok(uri.startsWith(`btx:${address}?`));
  assert.ok(uri.includes('amount=0.00000001'));
  assert.ok(uri.includes('label=Rent'));
  assert.ok(uri.includes('message=Thanks'));
  assert.throws(() => paymentRequest({address: ''}));
  assert.throws(() => paymentRequest({address, amount: '1e-8'}));
});
