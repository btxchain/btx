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
