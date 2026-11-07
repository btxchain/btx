import {test} from 'node:test';
import assert from 'node:assert/strict';
import {modelNodeStatus, modelRecordRows} from '../web/core/model-status.js';

test('present readiness and local generate are facts, and spend is the string given', () => {
  const status = modelNodeStatus(
    {identity_ready: true, modelnet: {automatic_spend_atoms: '0'}},
    {local_generate: false},
  );
  assert.ok(status.lines.some(line => line.includes('yes')));
  assert.ok(status.lines.some(line => line.includes('no')));
  assert.equal(status.spend, '0');
});

test('an empty object invents no lines and does not default spend to 0', () => {
  const status = modelNodeStatus({}, {});
  assert.equal(status.spend, 'unknown');
  assert.deepEqual(status.lines, []);
});

test('missing objects, numeric spend, and non-finite rates stay uninvented', () => {
  assert.deepEqual(modelNodeStatus(null, null), {lines: [], spend: 'unknown'});
  assert.equal(modelNodeStatus({automatic_spend_atoms: 0}, {}).spend, 'unknown');
  assert.equal(modelNodeStatus({automatic_spend_atoms: '0', modelnet: {automatic_spend_atoms: '9'}}, null).spend, '0');
  const nested = modelNodeStatus({money: {initialblockdownload: true, ibd: false}}, null);
  assert.ok(nested.lines.some(line => line.includes('no')));
  assert.equal(nested.lines.filter(line => line.startsWith('IBD:')).length, 1);
  const rates = modelNodeStatus({bytes_per_sec: Number.POSITIVE_INFINITY, modelnet: {ul_bytes_per_sec: 3}}, null);
  assert.equal(rates.lines.some(line => line.includes('Infinity')), false);
  assert.ok(rates.lines.some(line => line.includes('3')));
  assert.equal(modelNodeStatus({helper_ready: 'not a boolean'}, {}).lines.some(line => line.includes('not a boolean')), true);
});

test('modelRecordRows copies an array of objects and drops non-objects', () => {
  const row = {address: 'a'};
  const source = [row, 'skip', null, 1, ['nested']];
  const rows = modelRecordRows(source);
  assert.deepEqual(rows, [row]);
  assert.notEqual(rows, source);
  assert.equal(rows[0], row);
});

test('modelRecordRows uses a peers array on an object', () => {
  const peers = [{endpoint: 'e'}];
  const rows = modelRecordRows({peers, identities: [{id: 'other'}]});
  assert.deepEqual(rows, peers);
  assert.notEqual(rows, peers);
});

test('modelRecordRows uses an identities array on an object', () => {
  const identities = [{id: 'i', name: 'n'}];
  const rows = modelRecordRows({identities});
  assert.deepEqual(rows, identities);
  assert.notEqual(rows, identities);
});

test('modelRecordRows returns no rows for a string', () => {
  assert.deepEqual(modelRecordRows('peers'), []);
});

test('modelRecordRows drops the 201st row', () => {
  const source = Array.from({length: 201}, (_, i) => ({i}));
  const rows = modelRecordRows(source);
  assert.equal(rows.length, 200);
  assert.equal(rows[199], source[199]);
  assert.equal(rows.includes(source[200]), false);
});
