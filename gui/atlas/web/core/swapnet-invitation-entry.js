import {Bridge, isNative} from './bridge.js';
import {parseInvitation, prepareReviewed, previewId} from './swapnet-market.js';

// This entrypoint has no remote network transport. The node alone verifies and dials.
const pending = [];
let active = false;
const bridge = new Bridge();
function node(tag, text='') { const e=document.createElement(tag);e.textContent=text;return e; }
function action(text, fn) { const b=node('button',text);b.type='button';b.addEventListener('click',fn);return b; }
function result(value) { return value && Object.prototype.hasOwnProperty.call(value,'result') ? value.result : value; }
function accept(uri) {
 try { parseInvitation(uri); } catch { return; }
 if(pending.length<8 && !pending.includes(uri))pending.push(uri);
 showNext();
}
function showNext() {
 if(active || !pending.length || !document.body)return;
 active=true; const uri=pending.shift();
 const dialog=node('dialog');dialog.className='swapnet-invite-dialog';
 const title=node('h2','SwapNet invitation — not a payment');
 const warning=node('p','This link is untrusted. Inspecting it does not connect, import keys, change chain verifiers, or authorize spending.');
 const text=node('textarea');text.value=uri;text.readOnly=true;text.rows=4;text.spellcheck=false;
 const status=node('pre');status.style.whiteSpace='pre-wrap';
 const controls=node('div');let prepared=null;let closed=false;
 const close=action('Close',async()=>{closed=true;if(prepared){try{await bridge.cancel(prepared);}catch{}}dialog.close();dialog.remove();active=false;showNext();});
 const inspect=action('Inspect signature and network',async()=>{
  inspect.disabled=true;status.textContent='Inspecting locally…';
  try {
   const record=result(await bridge.read('inspectswapinvite',[{uri}]));
   if(closed)return;
   status.textContent=JSON.stringify(record,null,2);
   const body=record.body||record.invitation?.body||record.envelope?.body||record;
   const endpoints=record.endpoints||body.endpoints;
   if(!Array.isArray(endpoints)||!endpoints.length)throw Error('No verified endpoints returned. Use the SwapNet invitation panel.');
   const select=node('select');for(const [index,entry] of endpoints.entries()){const endpoint=typeof entry==='string'?entry:entry?.endpoint;if(typeof endpoint!=='string')continue;const o=node('option',endpoint);o.value=String(index);select.append(o);}
   const dns=node('input');dns.type='checkbox';const dnsLabel=node('label',' Permit DNS resolution of a hostname after review');dnsLabel.prepend(dns);
   const local=node('input');local.type='checkbox';const localLabel=node('label',' Permit a private-network endpoint after review');localLabel.prepend(local);
   const review=action('Review one connection attempt',async()=>{
    review.disabled=true;
    try{
     const operation=await prepareReviewed(bridge,'connectswapinvite',{uri,endpoint_index:Number(select.value),allow_dns:dns.checked,allow_private:local.checked});
     if(closed){try{await bridge.cancel(previewId(operation));}catch{}return;}
     prepared=previewId(operation);status.textContent=JSON.stringify(operation,null,2);
     const execute=action('Confirm the reviewed connection attempt',async()=>{
      execute.disabled=true;
      try{const value=await bridge.execute(prepared);prepared=null;if(!closed)status.textContent=JSON.stringify(value,null,2);}
      catch(e){if(!closed)status.textContent=e.message;execute.disabled=false;}
     });controls.append(execute);
    }catch(e){if(!closed)status.textContent=e.message;review.disabled=false;}
   });
   controls.replaceChildren(select,dnsLabel,localLabel,review,close);
  }catch(e){if(!closed)status.textContent=e.message;}
  finally{inspect.disabled=false;}
 });
 controls.append(inspect,close);dialog.append(title,warning,text,status,controls);document.body.append(dialog);
 dialog.addEventListener('cancel',e=>{e.preventDefault();close.click();});dialog.showModal();
}
async function init(){
 if(!isNative)return;
 try{for(const uri of await bridge.invoke('atlas_take_swapnet_invites'))accept(uri);}catch{/* Old native shell: paste into the SwapNet invitation panel. */}
 // Custom native dispatch and the Tauri deep-link plugin can deliver an inert URI.
 globalThis.addEventListener('btx-swapnet-invitation',e=>{if(typeof e.detail==='string')accept(e.detail);});
 const listen=globalThis.__TAURI__?.event?.listen;
 if(listen){
  try{await listen('deep-link://new-url',event=>{const items=Array.isArray(event.payload)?event.payload:[event.payload];for(const uri of items)if(typeof uri==='string')accept(uri);});}catch{}
 }
 document.addEventListener('click',e=>{
  const anchor=e.target?.closest?.('a[href]');if(!anchor)return;
  const uri=anchor.getAttribute('href')||'';
  if(uri.startsWith('btx://swapnet/v1/')){e.preventDefault();accept(uri);}
 });
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init,{once:true});else init();
