
/** Two independent voluntary prices; no imposed reciprocal price or market oracle. */
export function twoSidedPolicies(input, nowSeconds=Math.floor(Date.now()/1000)) {
 const field=(value,name)=>{
  if(typeof value!=='string'||!value)throw Error(`${name} is required`);
  return value;
 };
 const amount=(value,name)=>{
  const text=field(value,name);
  if(!/^(0|[1-9][0-9]*)$/.test(text)||text.length>78)throw Error(`${name} must be an exact atom integer`);
  return text;
 };
 const positive=(value,name)=>{const text=amount(value,name);if(BigInt(text)===0n)throw Error(`${name} must be positive`);return text;};
 const a=field(input.base_asset,'Base asset'),b=field(input.quote_asset,'Quote asset');
 if(a===b||!a.startsWith('btx:')&&!b.startsWith('btx:'))throw Error('One distinct native BTX leg is required');
 const ttl=Number(input.ttl_seconds??3600);
 if(!Number.isSafeInteger(ttl)||ttl<60||ttl>86400)throw Error('Market TTL must be 60–86400 seconds');
 function policy(side,sell,buy) {
  const p=input[side];if(!p||typeof p!=='object')throw Error(`Missing ${side} policy`);
  const mandate=field(p.mandate_id,`${side} output-asset mandate`);
  if(!/^[0-9a-f]{64}$/.test(mandate))throw Error('Mandate IDs must be 64 lowercase hexadecimal characters');
  const market={sell_asset:sell,buy_asset:buy,
   numerator:positive(p.numerator,'Price numerator'),denominator:positive(p.denominator,'Price denominator'),
   maker_fee_atoms:amount(p.maker_fee_atoms,'Maker fee'),max_receive_network_fee_atoms:amount(p.max_receive_network_fee_atoms,'Receive network fee'),
   max_input_atoms:positive(p.max_input_atoms,'Maximum input'),expires_at:nowSeconds+ttl};
  const max_local_fee_atoms=positive(p.max_local_fee_atoms,'Local fee cap');
  const refund_fee_atoms=positive(p.refund_fee_atoms,'Refund fee cap');
  const claim_fee_atoms=positive(p.claim_fee_atoms,'Claim fee cap');
  if(BigInt(refund_fee_atoms)>BigInt(max_local_fee_atoms))throw Error('Refund fee exceeds total local fee authorization');
  return {market,mandate_id:mandate,max_local_fee_atoms,refund_fee_atoms,claim_fee_atoms};
 }
 return [policy('buy_base',a,b),policy('sell_base',b,a)];
}
