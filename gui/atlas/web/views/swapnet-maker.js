import {twoSidedPolicies} from '../core/swapnet-maker.js';
import {prepareReviewed,previewId} from '../core/swapnet-market.js';

export function twoSidedMakerPanel(app) {
 const e=(tag,text='')=>{const n=document.createElement(tag);n.textContent=text;return n;};
 const panel=e('details');panel.className='panel';panel.append(e('summary','Two-sided maker — atomic policy setup'));
 panel.append(e('p','Use two existing owner-authorized mandates, each covering the asset this provider pays out. These are voluntary independent prices. Publishing public offers remains a separate reviewed action.'));
 const controls={};
 function input(host,key,label,value=''){
  const wrap=e('label',label);const n=e('input');n.value=value;n.autocomplete='off';n.spellcheck=false;n.dataset.field=key;wrap.append(n);host.append(wrap);controls[key]=n;
 }
 input(panel,'wallet','Loaded native wallet');
 input(panel,'base_asset','Native BTX asset ID');input(panel,'quote_asset','Independent BTC/ETH asset ID');input(panel,'ttl_seconds','Market lifetime (seconds)','3600');
 for(const [side,label]of[['buy_base','Provider buys BTX: pays the external asset'],['sell_base','Provider sells BTX: pays BTX']]){
  const group=e('fieldset');group.append(e('legend',label));panel.append(group);
  for(const [key,title,initial]of [
   ['mandate_id','Output-asset mandate ID',''],['numerator','Output atoms numerator',''],['denominator','Per input atoms denominator',''],
   ['max_input_atoms','Maximum taker input atoms',''],['maker_fee_atoms','Fee deducted from output atoms','0'],
   ['max_receive_network_fee_atoms','Maximum receive-side network fee atoms',''],['max_local_fee_atoms','Provider total outgoing fee cap atoms',''],
   ['refund_fee_atoms','Provider refund fee cap atoms',''],['claim_fee_atoms','Provider claim fee cap in incoming asset atoms','']]) input(group,`${side}.${key}`,title,initial);
 }
 const output=e('pre');output.style.whiteSpace='pre-wrap';panel.append(output);
 const review=e('button','Review both market policies');review.type='button';panel.append(review);
 let operation=null;let oldWallet='';
 async function cancel(){if(operation){try{await app.bridge.cancel(operation);}catch{}operation=null;}}
 controls.wallet.addEventListener('change',()=>{cancel();output.textContent='Wallet changed. Prepare a new native review.';});
 review.addEventListener('click',async()=>{
  review.disabled=true;await cancel();
  try{
   const data={base_asset:controls.base_asset.value,quote_asset:controls.quote_asset.value,ttl_seconds:controls.ttl_seconds.value,buy_base:{},sell_base:{}};
   for(const [key,n]of Object.entries(controls)){if(key.includes('.')){const [side,field]=key.split('.');data[side][field]=n.value;}}
   const markets=twoSidedPolicies(data);oldWallet=controls.wallet.value;
   const prepared=await prepareReviewed(app.bridge,'setswapmarkets',{markets},oldWallet||null);
   operation=previewId(prepared);output.textContent=JSON.stringify(prepared,null,2);
   const confirm=e('button','Confirm both reviewed market policies');confirm.type='button';
   confirm.addEventListener('click',async()=>{
    if(!operation||controls.wallet.value!==oldWallet){output.textContent='The prepared review is no longer current.';return;}
    confirm.disabled=true;
    try{const value=await app.bridge.execute(operation);operation=null;output.textContent=JSON.stringify(value,null,2);confirm.remove();}
    catch(error){output.textContent=error.message;confirm.disabled=false;}
   },{once:false});panel.append(confirm);
  }catch(error){output.textContent=error.message;}
  finally{review.disabled=false;}
 });
 return panel;
}
