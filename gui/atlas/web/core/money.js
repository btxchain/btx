// Monetary values never pass through IEEE-754. This mirrors consensus/amount.h.
export const COIN = 100000000n;
export const MAX_ATOMS = 21000000n * COIN;
export function atoms(value, {signed = false} = {}) {
  if (typeof value !== 'string' || value.length > 32 || !/^-?(0|[1-9]\d*)$/.test(value)) throw new Error('Non-canonical atom amount');
  if (value === '-0') throw new Error('Negative zero is not canonical');
  const n = BigInt(value);
  if ((!signed && n < 0n) || n > MAX_ATOMS || n < -MAX_ATOMS) throw new Error('Amount outside native money range');
  return n;
}
export function parseBTX(value, {signed = false} = {}) {
  if (typeof value !== 'string' || value.length > 40 || !/^-?(0|[1-9]\d*)(\.\d{1,8})?$/.test(value)) throw new Error('Enter a decimal BTX amount with at most 8 decimal places');
  const negative = value.startsWith('-');
  const [whole, fraction = ''] = (negative ? value.slice(1) : value).split('.');
  let n = BigInt(whole) * COIN + BigInt(fraction.padEnd(8, '0'));
  if (negative && (n===0n || !signed)) throw Error('Negative amount is not permitted');
  if (negative) n = -n;
  return atoms(n.toString(), {signed});
}
export function formatBTX(value, {signed = true, trim = false} = {}) {
  const n = typeof value === 'bigint' ? atoms(value.toString(), {signed}) : atoms(value, {signed});
  const x = n < 0n ? -n : n;
  let result = `${n < 0n ? '-' : ''}${x / COIN}.${(x % COIN).toString().padStart(8, '0')}`;
  if (trim) result = result.replace(/\.?0+$/, '');
  return result;
}
export function sumAmounts(values) {
  let sum = 0n;
  for (const v of values) { sum += atoms(String(v)); if (sum > MAX_ATOMS) throw new Error('Total exceeds money range'); }
  return sum;
}
export function parseFeeRate(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,5})(\.\d{1,3})?$/.test(value)) throw new Error('Fee rate must be a nonnegative decimal with at most 3 places');
  return value;
}
export function formatUnit(value, unit = 'BTX') {
  const n = atoms(String(value), {signed:true});
  if (unit === 'atoms') return `${n} atoms`;
  if (unit === 'mBTX') {
    const x = n < 0n ? -n : n;
    return `${n < 0n ? '-' : ''}${x / 100000n}.${(x % 100000n).toString().padStart(5, '0')} mBTX`;
  }
  return `${formatBTX(n)} BTX`;
}
