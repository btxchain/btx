import {test} from 'node:test';
import assert from 'node:assert/strict';
import {presentObservation} from '../web/core/observe.js';

test('getblockchaininfo with blocks and an object field is Chain, with a blocks metric and no rows', () => {
  const shown = presentObservation('getblockchaininfo', {blocks: 9, extra: {nested: true}});
  assert.equal(shown.title, 'Chain');
  assert.ok(shown.metrics.some(item => item.label === 'blocks' && item.value === 9));
  assert.equal(shown.rest, true);
  assert.deepEqual(shown.rows, []);
  assert.deepEqual(shown.columns, []);
});

test('getmodelpeers keeps one row and only the address column', () => {
  const peer = {address: 'a', nested: {}};
  const shown = presentObservation('getmodelpeers', {peers: [peer]});
  assert.equal(shown.title, 'Model peers');
  assert.equal(shown.rows.length, 1);
  assert.equal(shown.rows[0], peer);
  assert.deepEqual(shown.columns, ['address']);
  assert.equal(shown.rest, true);
});

test('a string value has no rows and rest false', () => {
  const shown = presentObservation('getblockchaininfo', 'main');
  assert.deepEqual(shown.rows, []);
  assert.deepEqual(shown.columns, []);
  assert.equal(shown.rest, false);
  assert.deepEqual(shown.metrics, []);
});

test('an unknown method keeps its name as the title', () => {
  assert.equal(presentObservation('getpeerinfo', {connections: 2}).title, 'getpeerinfo');
  assert.equal(presentObservation('notAMethod', null).title, 'notAMethod');
});

test('known methods use their observation titles', () => {
  const titles = {
    getblockchaininfo: 'Chain',
    getnetworkinfo: 'Money network',
    getmempoolinfo: 'Mempool',
    getnettotals: 'Traffic',
    getmininginfo: 'Mining',
    getmodelnetworkinfo: 'Model network',
    getmodelpeers: 'Model peers',
    listmodels: 'Models',
    getmodelhostprofile: 'This node',
    getsetupstatus: 'Setup',
    getmemoryinfo: 'Memory',
    getmodelfeed: 'Feed',
    getfundablemodels: 'Fundable models',
    getrecentreleases: 'Recent releases',
    searchbounties: 'Bounties',
  };
  for (const [method, title] of Object.entries(titles)) {
    assert.equal(presentObservation(method, null).title, title);
    assert.equal(presentObservation(method, null).rest, false);
  }
});

test('null, undefined, and scalars are not a native record', () => {
  for (const value of [null, undefined, 1, false, 0]) {
    const shown = presentObservation('getmemoryinfo', value);
    assert.equal(shown.rest, false);
    assert.deepEqual(shown.rows, []);
  }
  assert.equal(presentObservation('getmemoryinfo', []).rest, true);
  assert.equal(presentObservation('getmemoryinfo', {}).rest, true);
});

test('columns skip objects and arrays and stop at six scalar keys', () => {
  const row = {blob: {a: 1}, list: [1], name: 'n', n: 2, ok: true, missing: null, extra: 'e', sixth: 'yes', seventh: 'no', skip: undefined};
  const shown = presentObservation('listmodels', [row]);
  assert.deepEqual(shown.columns, ['name', 'n', 'ok', 'missing', 'extra', 'sixth']);
  assert.equal(shown.columns.includes('blob'), false);
  assert.equal(shown.columns.includes('list'), false);
  assert.equal(shown.columns.includes('seventh'), false);
  assert.equal(shown.columns.includes('skip'), false);
});

test('a models array is used only when record rows are empty, and only objects, capped at 200', () => {
  const objects = Array.from({length: 201}, (_, i) => ({name: `m${i}`}));
  const models = objects.slice();
  models.splice(3, 0, 'skip', null, ['nested']);
  const shown = presentObservation('getfundablemodels', {models});
  assert.equal(shown.title, 'Fundable models');
  assert.equal(shown.rows.length, 200);
  assert.equal(shown.rows[0], objects[0]);
  assert.equal(shown.rows.includes(objects[199]), true);
  assert.equal(shown.rows.includes(objects[200]), false);
  assert.equal(shown.rows.some(row => typeof row === 'string' || Array.isArray(row)), false);
  assert.deepEqual(shown.columns, ['name']);
  const peer = {address: 'a'};
  const both = presentObservation('getmodelpeers', {peers: [peer], models: [{name: 'other'}]});
  assert.deepEqual(both.rows, [peer]);
  assert.deepEqual(both.columns, ['address']);
});
