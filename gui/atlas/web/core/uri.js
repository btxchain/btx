import {parseBTX, formatBTX} from './money.js';
export function parseBTXUri(input) {
  if (typeof input !== 'string' || input.length > 8192 || /[\x00-\x20\x7f]/.test(input)) throw new Error('Malformed BTX URI');
  if (input.startsWith('btx-p2p://')) { const endpoint=input.slice(10); if(!/^[a-z2-7]{56}\.onion(?::[0-9]{1,5})?$/.test(endpoint)) throw Error('Invalid Tor pairing endpoint'); const port=endpoint.split(':')[1]; if(port&&(Number(port)<1||Number(port)>65535)) throw Error('Invalid peer port'); return Object.freeze({kind:'peer',endpoint}); }
  if (input.startsWith('btx://')) {
    if (/[?#\\]/.test(input) || input.length < 12) throw new Error('Model URIs do not have query strings, fragments, or backslashes');
    return Object.freeze({kind:'model', uri:input}); // Native openbtxuri verifies the actual encoding.
  }
  if (!input.startsWith('btx:') || input.startsWith('btx:/')) throw new Error('Only BTX payment/model links are accepted');
  if(input.split('?').length>2||/%(?![0-9a-fA-F]{2})/.test(input)) throw Error('Malformed payment query encoding');
  const [address, query=''] = input.slice(4).split('?');
  if (!/^[A-Za-z0-9]{14,160}$/.test(address) || input.includes('#')) throw new Error('Invalid address syntax; native address validation still required');
  const fields = new Map();
  for (const [k,v] of new URLSearchParams(query)) {
    if (fields.has(k)) throw new Error('Duplicate URI parameter');
    if (k.startsWith('req-') || k==='r') throw new Error('Required extensions and remote payment requests are not supported');
    if (v.length > 512 || /[\x00-\x1f\x7f]/.test(v)) throw new Error('URI field too long or contains controls');
    fields.set(k,v);
  }
  const amount = fields.has('amount') ? formatBTX(parseBTX(fields.get('amount'))) : '';
  return Object.freeze({kind:'payment',address,amount,label:fields.get('label')||'',message:fields.get('message')||''});
}
export function makePaymentUri({address,amount='',label='',message=''}) {
  if (!/^[A-Za-z0-9]{14,160}$/.test(address)) throw new Error('Invalid address syntax');
  const p = new URLSearchParams();
  if (amount) p.set('amount',formatBTX(parseBTX(amount)));
  if (label) p.set('label',label.slice(0,512));
  if (message) p.set('message',message.slice(0,512));
  return `btx:${address}${p.size?'?'+p:''}`;
}
