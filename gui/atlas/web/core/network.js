import {parseBTX} from './money.js';

export function blockHeights(tip, count = 8) {
  const text = typeof tip === 'number' && Number.isSafeInteger(tip) ? String(tip) : typeof tip === 'string' ? tip : '';
  if (!/^(0|[1-9]\d*)$/.test(text)) return [];
  let height = BigInt(text);
  if (height > 100000000n) return [];
  const limit = Number.isInteger(count) ? Math.min(Math.max(count, 0), 12) : 8;
  const out = [];
  while (out.length < limit) {
    out.push(height.toString());
    if (height === 0n) break;
    height -= 1n;
  }
  return out;
}

export function moneyPeers(peers, {privacy = true} = {}) {
  if (!Array.isArray(peers)) return [];
  const rows = [];
  for (const peer of peers) {
    if (!peer || typeof peer !== 'object') continue;
    const endpoint = typeof peer.addr === 'string' ? peer.addr : '';
    rows.push({
      endpoint,
      shown: privacy || !endpoint ? `peer ${peer.id ?? rows.length}` : endpoint,
      direction: peer.inbound === true ? 'inbound' : peer.inbound === false ? 'outbound' : '',
      type: typeof peer.connection_type === 'string' ? peer.connection_type : '',
      ping: peer.pingtime == null ? '' : String(peer.pingtime),
      height: peer.synced_headers == null ? '' : String(peer.synced_headers),
      version: typeof peer.subver === 'string' ? peer.subver.slice(0, 80) : '',
    });
    if (rows.length === 500) break;
  }
  return rows;
}

export function txSummary(tx) {
  if (!tx || typeof tx !== 'object' || Array.isArray(tx)) return null;
  const details = Array.isArray(tx.details) ? tx.details.slice(0, 32).map(row => ({
    category: row && row.category != null ? String(row.category) : '',
    amount: row ? row.amount : undefined,
    address: row && row.address != null ? String(row.address) : '',
    label: row && row.label != null ? String(row.label) : '',
    vout: row ? row.vout : undefined,
  })) : [];
  return {
    txid: tx.txid != null ? String(tx.txid) : '',
    confirmations: tx.confirmations,
    amount: tx.amount,
    fee: tx.fee,
    time: tx.time,
    blockhash: tx.blockhash != null ? String(tx.blockhash) : '',
    replaceable: tx['bip125-replaceable'],
    category: tx.category != null ? String(tx.category) : '',
    address: tx.address != null ? String(tx.address) : '',
    details,
  };
}

export function sessionSamples(previous, info, now) {
  const prior = Array.isArray(previous) ? previous.filter(row => row && Number.isFinite(row.size) && Number.isFinite(row.bytes)).slice(-59) : [];
  const size = Number(info && info.size);
  const bytes = Number(info && info.bytes);
  if (!Number.isFinite(size) || !Number.isFinite(bytes) || size < 0 || bytes < 0) return prior;
  return [...prior, {at: Number.isFinite(now) ? now : 0, size, bytes}];
}

export function atomsPerVbyteFromKvb(text) {
  const atoms = parseBTX(String(text));
  if (atoms < 0n) throw new Error('Negative fee estimate');
  const rate = (atoms + 999n) / 1000n;
  if (rate > 10000n) throw new Error('Fee estimate exceeds the composer ceiling of 10000 atoms/vB');
  return rate.toString();
}

export function feeDecimal(value) {
  if (typeof value === 'string' && /^(0|[1-9]\d*)(\.\d{1,8})?$/.test(value)) return value;
  if (typeof value === 'number' && Number.isFinite(value) && value >= 0) {
    const text = value.toFixed(8).replace(/\.?0+$/, '');
    if (/^(0|[1-9]\d*)(\.\d{1,8})?$/.test(text)) return text;
  }
  return null;
}

function canonicalBytes(value) {
  if (typeof value === 'string') {
    if (value.length > 80 || !/^(0|[1-9]\d*)$/.test(value)) return null;
    return BigInt(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  return null;
}

export function trafficDelta(previous, current) {
  if (!previous || typeof previous !== 'object' || Array.isArray(previous)) return null;
  if (!current || typeof current !== 'object' || Array.isArray(current)) return null;
  const previousReceived = canonicalBytes(previous.totalbytesrecv);
  const previousSent = canonicalBytes(previous.totalbytessent);
  const currentReceived = canonicalBytes(current.totalbytesrecv);
  const currentSent = canonicalBytes(current.totalbytessent);
  if (previousReceived === null || previousSent === null || currentReceived === null || currentSent === null) return null;
  if (currentReceived < previousReceived || currentSent < previousSent) return null;
  return {
    received: (currentReceived - previousReceived).toString(),
    sent: (currentSent - previousSent).toString(),
  };
}

function headerTransactions(value) {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) return null;
    return value === 0 ? 0 : value;
  }
  if (typeof value === 'string' && value.length <= 16 && /^(0|[1-9]\d*)$/.test(value)) {
    const count = Number(value);
    if (!Number.isSafeInteger(count) || count < 0) return null;
    return count;
  }
  return null;
}

export function networkWarnings(info) {
  if (!info || typeof info !== 'object') return '';
  if (typeof info.warnings === 'string') {
    const text = info.warnings.trim();
    return text.length ? text : '';
  }
  if (!Array.isArray(info.warnings)) return '';
  const lines = [];
  for (const item of info.warnings) {
    if (typeof item !== 'string') continue;
    const text = item.trim();
    if (text.length) lines.push(text);
  }
  return lines.join('\n');
}

export function banDurationSeconds(hours) {
  if (!Number.isInteger(hours) || hours < 1 || hours > 8760) {
    throw new Error('Ban duration must be 1 to 8760 hours.');
  }
  return hours * 3600;
}

export function headerBars(rows) {
  if (!Array.isArray(rows)) return [];
  const out = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object' || Array.isArray(row)) continue;
    const transactions = headerTransactions(row.transactions);
    if (transactions === null) continue;
    out.push({height: row.height, transactions});
    if (out.length === 12) break;
  }
  return out;
}
