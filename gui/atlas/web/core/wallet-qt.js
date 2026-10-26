import {parseBTX, formatBTX} from './money.js';

const CONTROL = /[\u0000-\u001f\u007f]/;

function requireBoolean(value, label) {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

export function createWalletDraft({
  name,
  disablePrivateKeys,
  blank,
  passphrase,
  avoidReuse,
  descriptors,
  loadOnStartup,
  externalSigner,
} = {}) {
  if (typeof name !== 'string' || name.length === 0) throw new Error('Wallet name is empty');
  if (CONTROL.test(name)) throw new Error('Wallet name contains a control character');
  if (name.length > 64) throw new Error('Wallet name is longer than 64 characters');
  if (typeof passphrase !== 'string') throw new Error('Passphrase must be a string');
  if (passphrase.length > 1024) throw new Error('Passphrase is longer than 1024 characters');
  const disable = requireBoolean(disablePrivateKeys, 'disablePrivateKeys');
  const blankWallet = requireBoolean(blank, 'blank');
  const avoid = requireBoolean(avoidReuse, 'avoidReuse');
  const descriptorWallet = requireBoolean(descriptors, 'descriptors');
  const load = requireBoolean(loadOnStartup, 'loadOnStartup');
  const external = requireBoolean(externalSigner, 'externalSigner');
  if (external && (!disable || !descriptorWallet)) throw new Error('An external signer requires disabled private keys and a descriptor wallet');
  return [name, disable, blankWallet, passphrase, avoid, descriptorWallet, load, external];
}

export function coinSelectionSummary(coins) {
  if (!Array.isArray(coins)) throw new Error('Coin selection must be an array');
  let total = 0n;
  for (const coin of coins) {
    if (!coin || typeof coin !== 'object' || typeof coin.amount !== 'string') throw new Error('Each coin needs an amount string');
    total += parseBTX(coin.amount);
  }
  return {count: coins.length, amount: formatBTX(total)};
}

const RECEIVING_ADDRESS_TYPES = new Set(['p2mr']);
const HISTORY_PAGE_SIZE = 100;
const HISTORY_CAP = 2000;
const PSBT_TEXT_LIMIT = 1000000;

export function receivingAddressArgs(label, addressType) {
  if (typeof label !== 'string') throw new Error('Label must be a string');
  if (addressType === '') return [label];
  if (typeof addressType !== 'string' || !RECEIVING_ADDRESS_TYPES.has(addressType)) throw new Error('Address type is not supported');
  return [label, addressType];
}

export function historyWalk({pageSize, cap}) {
  if (pageSize !== HISTORY_PAGE_SIZE || cap !== HISTORY_CAP) throw new Error('History walk requires page size 100 and cap 2000');
  return {pageSize: HISTORY_PAGE_SIZE, cap: HISTORY_CAP};
}

export function nextHistorySkip(skip, rowCount, pageSize) {
  if (!Number.isInteger(skip) || skip < 0) throw new Error('Skip must be a non-negative integer');
  if (rowCount < pageSize) return null;
  return skip + pageSize;
}

function groupKey(value) {
  if (typeof value === 'string') return value;
  if (value == null) return '';
  return String(value);
}

export function coinTree(coins) {
  if (!Array.isArray(coins)) throw new Error('Coins must be an array');
  const byLabel = new Map();
  for (const coin of coins) {
    const source = coin && typeof coin === 'object' ? coin : null;
    const label = groupKey(source ? source.label : undefined);
    const address = groupKey(source ? source.address : undefined);
    let addresses = byLabel.get(label);
    if (!addresses) {
      addresses = new Map();
      byLabel.set(label, addresses);
    }
    let bucket = addresses.get(address);
    if (!bucket) {
      bucket = [];
      addresses.set(address, bucket);
    }
    bucket.push(coin);
  }
  return [...byLabel.keys()].sort((a, b) => a.localeCompare(b)).map((label) => ({
    label,
    addresses: [...byLabel.get(label).keys()].sort((a, b) => a.localeCompare(b)).map((address) => ({
      address,
      coins: byLabel.get(label).get(address),
    })),
  }));
}

export function psbtWithinLimit(text) {
  return typeof text === 'string' && text.length <= PSBT_TEXT_LIMIT;
}

const ADDRESS_FLAGS = ['isvalid', 'ismine', 'iswatchonly', 'isscript', 'iswitness', 'solvable'];

function plainObject(value) {
  if (value === null || typeof value !== 'object') return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function addressFacts(info) {
  if (!plainObject(info)) return {lines: [], warning: 'Address information was not an object.'};
  const lines = [];
  const values = new Map();
  try {
    for (const key of ADDRESS_FLAGS) {
      if (!Object.hasOwn(info, key)) continue;
      const value = info[key];
      if (typeof value !== 'boolean') continue;
      values.set(key, value);
      lines.push(`${key}: ${value ? 'yes' : 'no'}`);
    }
  } catch {
    return {lines: [], warning: 'Address information was not an object.'};
  }
  let warning = null;
  if (values.get('isvalid') === false) warning = 'The node does not consider this address valid.';
  else if (values.get('ismine') === false) warning = 'This wallet does not report the address as mine.';
  return {lines, warning};
}

export function walletFacts(info) {
  try {
    if (!plainObject(info)) return [];
    const lines = [];
    if (Object.hasOwn(info, 'txcount')) {
      const txcount = info.txcount;
      if (Number.isSafeInteger(txcount) && txcount >= 0) lines.push(`Transactions: ${txcount}`);
    }
    if (Object.hasOwn(info, 'descriptors')) {
      const descriptors = info.descriptors;
      if (typeof descriptors === 'boolean') lines.push(`Descriptors: ${descriptors ? 'yes' : 'no'}`);
    }
    if (Object.hasOwn(info, 'unlocked_until')) {
      const unlocked = info.unlocked_until;
      if (unlocked === 0) lines.push('This wallet is locked.');
      else if (Number.isSafeInteger(unlocked) && unlocked > 0) lines.push('This wallet reports an unlock expiry.');
    }
    return lines;
  } catch {
    return [];
  }
}
