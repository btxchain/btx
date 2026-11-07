import {makePaymentUri} from './uri.js';

const HIDDEN_KEY = /credential|secret|passwd|passphrase|presign|cookie|authorization|private[_-]?key|token/i;
const SKIP = Symbol('skip');

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function hiddenKey(key) {
  return key === 'query' || HIDDEN_KEY.test(key);
}

function copyValue(value, seen) {
  if (Array.isArray(value)) {
    if (seen.has(value)) return SKIP;
    seen.add(value);
    const out = [];
    for (let i = 0; i < value.length; i++) {
      const child = copyValue(value[i], seen);
      if (child !== SKIP) out[i] = child;
    }
    seen.delete(value);
    return out;
  }
  if (isPlainObject(value)) {
    if (seen.has(value)) return SKIP;
    seen.add(value);
    const out = {};
    for (const key of Object.keys(value)) {
      const child = hiddenKey(key) ? '[hidden]' : copyValue(value[key], seen);
      if (child === SKIP) continue;
      Object.defineProperty(out, key, {value: child, enumerable: true, writable: true, configurable: true});
    }
    seen.delete(value);
    return out;
  }
  return value;
}

export function redactObservation(value) {
  const copied = copyValue(value, new WeakSet());
  return copied === SKIP ? undefined : copied;
}

const DECIMAL_PROGRESS = /^(0|[1-9]\d*)(\.\d+)?$/;

function progressText(progress) {
  return `${(progress * 100).toFixed(2)}%`;
}

function finiteProgress(progress) {
  if (typeof progress === 'number') return Number.isFinite(progress) ? progress : undefined;
  if (typeof progress !== 'string' || progress.length > 32 || !DECIMAL_PROGRESS.test(progress)) return undefined;
  const value = Number(progress);
  return Number.isFinite(value) ? value : undefined;
}

export function syncBanner(info) {
  if (info === null || typeof info !== 'object') return {visible: false, title: '', detail: ''};
  const downloading = info.initialblockdownload === true;
  const progress = finiteProgress(info.verificationprogress);
  const progressFinite = progress !== undefined;
  const warnings = String(info.warnings || '').trim();
  const visible = downloading || (progressFinite && progress < 0.999) || warnings !== '';
  if (!visible) return {visible: false, title: '', detail: ''};
  const title = downloading ? 'Initial block download' : (warnings ? 'Node warning' : 'Synchronization in progress');
  const parts = [];
  if (progressFinite && progress >= 0 && progress <= 1) parts.push(progressText(progress));
  if (warnings) parts.push(warnings);
  return {visible: true, title, detail: parts.join(' ')};
}

export function historyFilter(rows, {category = '', query = ''} = {}) {
  if (!Array.isArray(rows)) return [];
  const cat = category ?? '';
  const q = query ?? '';
  if (cat === '' && q === '') return rows.slice();
  const needle = String(q).toLowerCase();
  return rows.filter((row) => {
    if (cat !== '' && (!row || typeof row !== 'object' || row.category !== cat)) return false;
    if (q === '') return true;
    if (!row || typeof row !== 'object') return false;
    return ['txid', 'address', 'label', 'category'].some((key) => String(row[key] ?? '').toLowerCase().includes(needle));
  });
}

export function paymentRequest({address, amount = '', label = '', message = ''} = {}) {
  return makePaymentUri({address, amount, label, message});
}
