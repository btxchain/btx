// Native-only operation preparation. Rendering or opening a URI never executes it.
export const INVITE_PREFIX='btx://swapnet/v1/';
export const MAX_INVITE_BYTES=32768;
export const READ_METHODS=Object.freeze(['getswapnetworkinfo','getswapmode','getswapreadiness',
 'listswappublicoffers','getswapquotes','listswaps','getswapauthinfo','getsharedp2pinfo']);
export function atomString(value,{positive=false}={}){
 if(typeof value!=='string'||! /^(0|[1-9][0-9]{0,77})$/.test(value))throw Error('Use an exact unsigned integer amount in asset atoms.');
 const n=BigInt(value);if(n>=(1n<<256n)||(positive&&n===0n))throw Error('Amount is out of range.');return value;
}
export function parseInvitation(value){
 if(typeof value!=='string'||new TextEncoder().encode(value).length>MAX_INVITE_BYTES||!value.startsWith(INVITE_PREFIX))throw Error('Not a supported SwapNet invitation.');
 const token=value.slice(INVITE_PREFIX.length);if(!/^[A-Za-z0-9_-]+$/.test(token))throw Error('Malformed invitation encoding.');
 return Object.freeze({kind:'swapnet',uri:value,requiresNativeVerification:true,connectionStarted:false,spendingAuthority:false});
}
export function unwrap(value){return value&&Object.prototype.hasOwnProperty.call(value,'result')?value.result:value;}
export function offerRows(result,now=Math.floor(Date.now()/1000)){
 return (result?.offers||[]).flatMap(envelope=>{
  const b=envelope.body;if(!b||b.withdrawn||b.expires_at<=now||!['firm','indicative'].includes(b.kind))return [];
  return b.tiers.map((t,index)=>({provider:b.provider,offerId:b.offer_id,sequence:b.sequence,tier:index,
   kind:b.kind,sellAsset:b.sell_asset,buyAsset:b.buy_asset,sellAtoms:atomString(t.sell_atoms,{positive:true}),
   grossBuyAtoms:atomString(t.buy_atoms,{positive:true}),makerFeeAtoms:atomString(t.maker_fee_atoms),
   networkFeeCapAtoms:atomString(t.max_receive_network_fee_atoms),
   minimumReceiveAtoms:(BigInt(t.buy_atoms)-BigInt(t.maker_fee_atoms)-BigInt(t.max_receive_network_fee_atoms)).toString(),
   slots:t.slots,expiresAt:b.expires_at,assurance:b.kind==='firm'?'Maker-local reserved capacity; allocation and on-chain funding still required':'Indicative only; request an exact signed quote'}));
 });
}
export async function prepareReviewed(bridge,method,request,wallet=null){
 if(!bridge||bridge.mode==='demo'||bridge.mode==='disconnected')throw Error('Connect to the native BTX node first.');
 // Always one RPC request object. Do not flatten keys into positional arguments.
 return unwrap(await bridge.prepare(method,[request],wallet));
}
export function previewId(prepared){
 const id=prepared?.id??prepared?.operation_id??prepared?.prepared?.id;
 if(typeof id!=='string'||id.length===0)throw Error('The native review did not return an operation identifier. Nothing was executed.');return id;
}
export function marketRequest(form){
 for(const key of ['numerator','denominator','max_input_atoms'])atomString(form[key],{positive:true});
 for(const key of ['maker_fee_atoms','max_receive_network_fee_atoms'])atomString(form[key]);
 if(!Number.isSafeInteger(form.expires_at)||form.expires_at<=0)throw Error('Invalid market expiry.');
 return {...form};
}
