import {test} from 'node:test';
import assert from 'node:assert/strict';
import {loadRequests, rememberRequest, requestSeconds, qrSvg} from '../web/core/receive-history.js';
import {formatObservedTime} from '../web/core/json.js';
import {feeBins} from '../web/core/mempool.js';
import {atomsPerVbyteFromKvb, blockHeights, feeDecimal, moneyPeers, sessionSamples, txSummary} from '../web/core/network.js';

test('receive history keeps sixteen cleaned requests', () => {
  let raw = '[]';
  for (let i = 0; i < 20; i++) raw = JSON.stringify(rememberRequest(raw, {address: `btx${i}`, amount: '0.00000001', label: 'a\u0000', message: 'm', at: i + 1}));
  const rows = loadRequests(raw);
  assert.equal(rows.length, 16);
  assert.equal(rows[0].address, 'btx19');
  assert.equal(rows[0].label, 'a');
  assert.deepEqual(loadRequests('{'), []);
});

test('network reads keep money peers, headers, and fee units distinct', () => {
  assert.deepEqual(blockHeights('101', 3), ['101', '100', '99']);
  assert.deepEqual(blockHeights('nope'), []);
  const peers = moneyPeers([{id: 7, addr: '127.0.0.1:8333', inbound: true, subver: '/BTX/'}], {privacy: true});
  assert.equal(peers[0].shown, 'peer 7');
  assert.equal(peers[0].endpoint, '127.0.0.1:8333');
  assert.equal(atomsPerVbyteFromKvb('0.001'), '100');
  assert.equal(atomsPerVbyteFromKvb(feeDecimal(0.00000001)), '1');
  assert.throws(() => atomsPerVbyteFromKvb('2'));
  const summary = txSummary({txid: 'aa', amount: '1', details: [{category: 'receive', address: 'btx'}]});
  assert.equal(summary.details.length, 1);
  assert.equal(sessionSamples([{size: 1, bytes: 2}], {size: 'x'}, 3).length, 1);
});

test('QR save is an SVG of the matrix and fee bins are the current snapshot', () => {
  const svg = qrSvg({width: 1, cells: [true]});
  assert.match(svg, /<svg /);
  assert.equal(qrSvg({width: 1, cells: ['x']}), null);
  assert.deepEqual(feeBins({fee_histogram: [[1.5, 2], ['bad', 1], [3, Number.NaN]]}), [{feerate: '1.5', count: '2'}]);
});

test('a saved request time is milliseconds and is shown as its UTC date', () => {
  const at = Date.UTC(2026, 9, 26, 12, 14, 1, 250);
  assert.equal(requestSeconds(at), Math.floor(at / 1000));
  assert.match(formatObservedTime(requestSeconds(at)), /^26 Oct 2026/);
  assert.equal(requestSeconds(0), 0);
  assert.equal(requestSeconds(-5), 0);
  assert.equal(requestSeconds(1.5), 0);
  assert.equal(requestSeconds('1793017000000'), 0);
});
