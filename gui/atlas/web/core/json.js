// Lossless, duplicate-key-rejecting JSON. Used for RPC forms, not executable code.
const NUMBER = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$/;
const FORBIDDEN = new Set(['__proto__', 'prototype', 'constructor']);
export class JsonNumber {
  constructor(text) {
    if (typeof text !== 'string' || text.length > 128 || !NUMBER.test(text)) throw new Error('Invalid JSON number');
    this.text = text;
    Object.freeze(this);
  }
  toString() { return this.text; }
}
export function parseJson(text, {maxBytes = 1048576, maxDepth = 32, maxNodes = 20000} = {}) {
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > maxBytes) throw new Error('JSON exceeds byte limit');
  let i = 0, count = 0;
  const error = message => { throw new Error(`${message} at byte/character ${i}`); };
  function ws() { while (i < text.length && /[\x20\t\r\n]/.test(text[i])) i++; }
  function string() {
    const start = i++;
    while (i < text.length) {
      const c = text[i++];
      if (c === '"') {
        const value = JSON.parse(text.slice(start, i));
        for (let j = 0; j < value.length; j++) {
          const code = value.charCodeAt(j);
          if (code >= 0xD800 && code <= 0xDBFF) {
            const next = value.charCodeAt(++j);
            if (!(next >= 0xDC00 && next <= 0xDFFF)) error('Unpaired surrogate');
          } else if (code >= 0xDC00 && code <= 0xDFFF) error('Unpaired surrogate');
        }
        return value;
      }
      if (c === '\\') { i++; continue; }
      if (c.charCodeAt(0) < 32) error('Control character');
    }
    return error('Unterminated string');
  }
  function value(depth) {
    if (depth > maxDepth || ++count > maxNodes) error('JSON structural limit');
    ws(); const c = text[i];
    if (c === '"') return string();
    if (c === '[') {
      i++; ws(); const a = [];
      if (text[i] === ']') { i++; return a; }
      while (i < text.length) {
        a.push(value(depth + 1)); ws();
        if (text[i] === ']') { i++; return a; }
        if (text[i++] !== ',') error('Expected comma');
      }
      error('Unterminated array');
    }
    if (c === '{') {
      i++; ws(); const o = Object.create(null), seen = new Set();
      if (text[i] === '}') { i++; return o; }
      while (i < text.length) {
        ws(); if (text[i] !== '"') error('Expected key');
        const k = string();
        if (FORBIDDEN.has(k) || seen.has(k)) error('Forbidden or duplicate key');
        seen.add(k); ws(); if (text[i++] !== ':') error('Expected colon');
        o[k] = value(depth + 1); ws();
        if (text[i] === '}') { i++; return o; }
        if (text[i++] !== ',') error('Expected comma');
      }
      error('Unterminated object');
    }
    for (const [word, out] of [['true',true], ['false',false], ['null',null]]) {
      if (text.slice(i, i + word.length) === word) { i += word.length; return out; }
    }
    const match = text.slice(i).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/);
    if (!match) error('Invalid JSON value');
    i += match[0].length; return new JsonNumber(match[0]);
  }
  const result = value(0); ws(); if (i !== text.length) error('Trailing JSON input');
  return result;
}
export function encodeJson(value, pretty = false) {
  function encode(v, depth) {
    if (depth > 40) throw new Error('JSON depth');
    const indent = n => pretty ? '  '.repeat(n) : '';
    const nl = pretty ? '\n' : '';
    if (v instanceof JsonNumber) return v.text;
    if (typeof v === 'bigint') throw new Error('Use decimal strings for atom quantities');
    if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'number') { if (!Number.isSafeInteger(v)) throw new Error('Only safe integer JS numbers may enter wire JSON'); return String(v); }
    if (Array.isArray(v)) return v.length ? '[' + nl + v.map(x=>indent(depth+1)+encode(x,depth+1)).join(','+nl) + nl + indent(depth)+']' : '[]';
    if (v && typeof v === 'object') {
      const entries = Object.keys(v).sort().map(k=>{
        if (FORBIDDEN.has(k)) throw new Error('Forbidden key');
        return indent(depth+1)+JSON.stringify(k)+':'+(pretty?' ':'')+encode(v[k],depth+1);
      });
      return entries.length ? '{'+nl+entries.join(','+nl)+nl+indent(depth)+'}' : '{}';
    }
    throw new Error('Not JSON');
  }
  return encode(value,0);
}
export function numeric(value, fallback = null) {
  if(!(value instanceof JsonNumber)&&typeof value!=='number'&&typeof value!=='string')return fallback;
  const n = Number(value instanceof JsonNumber ? value.text : value);
  return Number.isFinite(n) && value !== null && value !== '' ? n : fallback;
}
export function displayJson(value) {
  return JSON.stringify(value, (_k,v) => v instanceof JsonNumber ? v.text : typeof v === 'bigint' ? v.toString() : v, 2);
}
export function plainNumbers(value) {
  if (value instanceof JsonNumber) { const n=Number(value.text); if(!Number.isFinite(n)||(!value.text.includes('.')&&!/[eE]/.test(value.text)&&!Number.isSafeInteger(n))) throw Error('Number outside visualization-safe range'); return n; }
  if (Array.isArray(value)) return value.map(plainNumbers);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v])=>[k,plainNumbers(v)]));
  return value;
}

// Compatibility name emphasizes that the parser never converts a wire number to float.
export const parseJsonExact = parseJson;
