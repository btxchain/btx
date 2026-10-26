import {test} from 'node:test';
import assert from 'node:assert/strict';
import {BY_METHOD} from '../web/core/catalog.js';
import {atomsPerVbyteFromKvb, banDurationSeconds, banSubnet, blockHeights, feeDecimal, headerBars, moneyPeers, networkWarnings, sessionSamples, trafficDelta, txSummary} from '../web/core/network.js';

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
  assert.equal(networkWarnings({warnings: ['  headers behind  ', '   ', 1, 'clock skew']}), 'headers behind\nclock skew');
  assert.equal(networkWarnings({warnings: []}), '');
  assert.equal(networkWarnings({warnings: [1, null]}), '');
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

test('banSubnet gives setban the peer address without its port', () => {
  // A getpeerinfo endpoint with a port is refused by setban: RPC -30 "Error: Invalid IP/Subnet".
  assert.equal(banSubnet('127.0.0.1:64477'), '127.0.0.1');
  assert.equal(banSubnet('[2001:db8::1]:8333'), '2001:db8::1');
  assert.equal(banSubnet('[2001:db8::1]'), '2001:db8::1');
  assert.equal(banSubnet('example.onion:8333'), 'example.onion');
  assert.equal(banSubnet('2001:db8::1'), '2001:db8::1');
  assert.equal(banSubnet('10.0.0.0/8'), '10.0.0.0/8');
  assert.equal(banSubnet(' 127.0.0.1:1 '), '127.0.0.1');
  assert.equal(banSubnet(null), '');
});

test('disconnectnode takes the address or the node id, never both by default', () => {
  // The node refuses ["address", 0]: RPC -32602 "Only one of address and nodeid should be provided."
  const args = BY_METHOD.get('disconnectnode').args;
  assert.deepEqual(args.map(arg => arg.name), ['address', 'nodeid']);
  assert.equal(args.some(arg => arg.required), false);
  assert.equal('default' in args[1], false);
});

test('existing network readers stay exported', () => {
  assert.deepEqual(blockHeights('3', 2), ['3', '2']);
  assert.equal(moneyPeers([{id: 1, addr: '127.0.0.1:1'}], {privacy: true})[0].shown, 'peer 1');
  assert.equal(txSummary({txid: 'aa'}).txid, 'aa');
  assert.equal(sessionSamples([], {size: 1, bytes: 2}, 1).length, 1);
  assert.equal(atomsPerVbyteFromKvb('0.001'), '100');
  assert.equal(feeDecimal('0.5'), '0.5');
});
