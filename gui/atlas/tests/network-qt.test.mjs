import {test} from 'node:test';
import assert from 'node:assert/strict';
import {atomsPerVbyteFromKvb, banDurationSeconds, blockHeights, feeDecimal, headerBars, moneyPeers, networkWarnings, sessionSamples, trafficDelta, txSummary} from '../web/core/network.js';

test('trafficDelta subtracts canonical getnettotals counters', () => {
  assert.deepEqual(
    trafficDelta({totalbytesrecv: '10', totalbytessent: '4'}, {totalbytesrecv: '15', totalbytessent: '4'}),
    {received: '5', sent: '0'},
  );
  assert.equal(
    trafficDelta({totalbytesrecv: '10', totalbytessent: '4'}, {totalbytesrecv: '9', totalbytessent: '4'}),
    null,
  );
  assert.equal(
    trafficDelta({totalbytesrecv: '10', totalbytessent: '4'}, {totalbytesrecv: '15', totalbytessent: '3'}),
    null,
  );
  assert.deepEqual(
    trafficDelta({totalbytesrecv: 10, totalbytessent: 4}, {totalbytesrecv: 15, totalbytessent: 4}),
    {received: '5', sent: '0'},
  );
  assert.equal(trafficDelta({totalbytesrecv: '10', totalbytessent: '4'}, {totalbytesrecv: '15'}), null);
  assert.equal(trafficDelta({totalbytesrecv: '10', totalbytessent: '4'}, {totalbytesrecv: '15', totalbytessent: '04'}), null);
  assert.equal(trafficDelta({totalbytesrecv: '10', totalbytessent: '4'}, {totalbytesrecv: '15', totalbytessent: 1.5}), null);
  assert.equal(trafficDelta(null, {totalbytesrecv: '15', totalbytessent: '4'}), null);
});

test('headerBars keeps at most twelve nonnegative header transaction counts', () => {
  assert.deepEqual(headerBars([
    {height: '8', transactions: -1},
    {height: '7', transactions: '-3'},
    {height: '6', transactions: '4'},
    {height: '5', transactions: 0},
  ]), [
    {height: '6', transactions: 4},
    {height: '5', transactions: 0},
  ]);
  const rows = Array.from({length: 14}, (_, height) => ({height, transactions: height}));
  const bars = headerBars(rows);
  assert.equal(bars.length, 12);
  assert.equal(bars[0].height, 0);
  assert.equal(bars[11].transactions, 11);
  assert.deepEqual(headerBars([{height: '1', transactions: '01'}]), []);
  assert.deepEqual(headerBars(null), []);
});

test('networkWarnings returns a trimmed node warning and nothing else', () => {
  assert.equal(networkWarnings({warnings: '  headers behind  '}), 'headers behind');
  assert.equal(networkWarnings({warnings: '   '}), '');
  assert.equal(networkWarnings({warnings: ''}), '');
  assert.equal(networkWarnings({}), '');
  assert.equal(networkWarnings({warnings: null}), '');
  assert.equal(networkWarnings(null), '');
  assert.equal(networkWarnings('headers behind'), '');
});

test('banDurationSeconds is setban bantime in seconds', () => {
  assert.equal(banDurationSeconds(24), 86400);
  assert.equal(banDurationSeconds(1), 3600);
  assert.equal(banDurationSeconds(8760), 31536000);
  assert.throws(() => banDurationSeconds(0), {message: 'Ban duration must be 1 to 8760 hours.'});
  assert.throws(() => banDurationSeconds(8761), {message: 'Ban duration must be 1 to 8760 hours.'});
  assert.throws(() => banDurationSeconds(1.5), {message: 'Ban duration must be 1 to 8760 hours.'});
});

test('existing network readers stay exported', () => {
  assert.deepEqual(blockHeights('3', 2), ['3', '2']);
  assert.equal(moneyPeers([{id: 1, addr: '127.0.0.1:1'}], {privacy: true})[0].shown, 'peer 1');
  assert.equal(txSummary({txid: 'aa'}).txid, 'aa');
  assert.equal(sessionSamples([], {size: 1, bytes: 2}, 1).length, 1);
  assert.equal(atomsPerVbyteFromKvb('0.001'), '100');
  assert.equal(feeDecimal('0.5'), '0.5');
});
