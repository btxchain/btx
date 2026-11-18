import {test} from 'node:test';
import assert from 'node:assert/strict';
// Maintained diagnostic: actual workspace and Bridge; controlled native replies.

import {swapnetWorkspace} from '../web/views/swapnet-workspace.js';
import {swapnetView} from '../web/views/swapnet.js';
import {installDom,buttonNamed,fire,settle,findAll} from './dom-stub.mjs';
let current;
globalThis.__TAURI__={core:{invoke:(command,args)=>current.invoke(command,args)}};
const {Bridge}=await import('../web/core/bridge.js?market-workflow');
const OFFER='1'.repeat(64),QUOTE='2'.repeat(64),PREVIEW='3'.repeat(64),REQUEST='4'.repeat(64);
const SELL='btx:'+'a'.repeat(64)+':0:native',BUY='btc:'+'b'.repeat(64)+':0:native';
const INPUT='9007199254740993',RECEIVE='18014398509481979',FEE='123456789012345';
const observations=[];
const gate=()=>{let release,reject;const wait=new Promise((r,j)=>{release=r;reject=j;});return{wait,release,reject};};
const tick=async()=>{for(let i=0;i<5;i++)await settle();};
const input=(root,name)=>findAll(root,n=>n.getAttribute('aria-label')===name)[0];
async function press(root,name){const b=buttonNamed(root,name);assert.ok(b,'Missing button: '+name);assert.equal(b.disabled,false);fire(b,'click');await tick();}
function setup({prepareGate=null,executeGate=null,useView=false}={}){
 installDom();
 const runtime={calls:[],prepared:[],executed:[],cancelled:[],
  async invoke(command,args){
   this.calls.push({command,args:structuredClone(args)});
   if(command==='atlas_read'){
    const m=args.request.method;
    const replies={listwallets:['wallet A','wallet B'],getswapnetworkinfo:{automatic_spend_atoms:'0'},getswapreadiness:{ready:true},getswapmode:{mode:'taker',discovery_enabled:true},getswapauthinfo:{principal:'owner:cookie'},
     listswappublicoffers:{offers:[{body:{provider:'maker',offer_id:OFFER,sequence:1,expires_at:2000000000,kind:'firm',sell_asset:SELL,buy_asset:BUY,withdrawn:false,tiers:[{sell_atoms:INPUT,buy_atoms:'18014398509481985',maker_fee_atoms:'2',max_receive_network_fee_atoms:'4',slots:1}]}}]},
     getswapquotes:{quotes:[{id:QUOTE,provider:'maker',sell_asset:SELL,buy_asset:BUY,sell_atoms:INPUT,minimum_receive_atoms:RECEIVE,max_receive_network_fee_atoms:'4'}]},listswaps:{swaps:[]}};
    assert.ok(m in replies,'Unexpected read '+m);return {ok:true,result:structuredClone(replies[m]),epoch:7};
   }
   if(command==='atlas_prepare'){
    const request=structuredClone(args.request),id='prepared-'+this.prepared.length;this.prepared.push({id,request});
    if(prepareGate&&request.method==='previewswap'){const hold=typeof prepareGate==='function'?prepareGate(this.prepared.length):prepareGate;if(hold)await hold.wait;}
    return {id,method:request.method,wallet:request.wallet};
   }
   if(command==='atlas_cancel'){this.cancelled.push(args.id);return null;}
   if(command==='atlas_execute'){
    const p=this.prepared.find(p=>p.id===args.id);assert.ok(p);this.executed.push(structuredClone(p));
    if(p.request.method==='requestpublicswapquote')return {ok:true,result:{request_id:REQUEST}};
    if(p.request.method==='previewswap'){
     if(executeGate)await executeGate.wait;
     return {ok:true,result:{preview_id:PREVIEW,sell_asset:SELL,buy_asset:BUY,sell_atoms:INPUT,maximum_send_atoms:(BigInt(INPUT)+BigInt(FEE)).toString(),net_receive_floor_atoms:RECEIVE,max_local_fee_atoms:FEE,refund_fee_atoms:'5',claim_fee_atoms:'4',provider:'maker',expires_at:2000000000,funds_reserved:false,requires_owner_confirmation:true}};
    }
    throw Error('No financial confirm execution is permitted in this diagnostic');
   }
   throw Error('Unexpected command '+command);
  }};
 current=runtime;const bridge=new Bridge();bridge.connected=true;bridge.epoch=7;
 const app={bridge,cleanup:null};const root=useView?swapnetView(app):swapnetWorkspace(app);return {root,runtime,bridge,app};
}
async function quoteFlow(f){
 await tick();const wallet=input(f.root,'Native BTX wallet');wallet.value='wallet A';fire(wallet,'change');await tick();
 await press(f.root,'Request exact signed quote');
 assert.equal(f.runtime.executed.length,0,'Preparation must not execute');
 await press(f.root,'Continue to native confirmation');
 input(f.root,'Maximum outgoing network fees (input-asset atoms)').value=FEE;
 input(f.root,'Minimum received (output-asset atoms)').value=RECEIVE;
 return wallet;
}
test('healthy actual market workspace preserves quote identity, exact amounts and fees through final preparation',async()=>{
 const f=setup();await quoteFlow(f);await press(f.root,'Preview this exact trade');await press(f.root,'Continue to native confirmation');
 const review=findAll(f.root,n=>n.tagName==='SECTION'&&n.children.some(c=>c.tagName==='H2'&&c.textContent==='Native result'))[0];
 assert.ok(review,'Missing exact preview result section');
 for(const exact of [INPUT,RECEIVE,FEE,SELL,BUY,PREVIEW])assert.ok(review.textContent.includes(exact),'Preview result lost '+exact);
 await press(f.root,'Authorize one bounded swap');
 const ps=f.runtime.prepared.map(p=>p.request);
 assert.deepEqual(ps.map(p=>[p.method,p.wallet]),[['requestpublicswapquote','wallet A'],['previewswap','wallet A'],['confirmswap','wallet A']]);
 assert.deepEqual(JSON.parse(ps[0].params_json),[{provider:'maker',offer_id:OFFER,tier:0}]);
 assert.deepEqual(JSON.parse(ps[1].params_json),[{quote_id:QUOTE,max_local_fee_atoms:FEE,min_receive_atoms:RECEIVE}]);
 assert.deepEqual(JSON.parse(ps[2].params_json),[{preview_id:PREVIEW}]);
 assert.equal(f.runtime.executed.some(p=>p.request.method==='confirmswap'),false);
 observations.push({case:'healthy',prepared:ps,visible_preview_terms:true,financial_execution:false});

});
test('changing wallet after completed preview removes the old authorization control',async()=>{
 const f=setup();const wallet=await quoteFlow(f);await press(f.root,'Preview this exact trade');await press(f.root,'Continue to native confirmation');
 assert.ok(buttonNamed(f.root,'Authorize one bounded swap'));wallet.value='wallet B';fire(wallet,'change');await tick();
 assert.equal(buttonNamed(f.root,'Authorize one bounded swap'),undefined);assert.equal(f.runtime.prepared.length,2);
 observations.push({case:'completed-preview-wallet-change',stale_confirm:false});
});
test('wallet change while preview execution is pending must not resurrect old-wallet trade authorization',async()=>{
 const hold=gate(),f=setup({executeGate:hold});const wallet=await quoteFlow(f);await press(f.root,'Preview this exact trade');await press(f.root,'Continue to native confirmation');
 wallet.value='wallet B';fire(wallet,'change');await tick();assert.equal(buttonNamed(f.root,'Authorize one bounded swap'),undefined);
 hold.release();await tick();const stale=buttonNamed(f.root,'Authorize one bounded swap');
 if(stale){await press(f.root,'Authorize one bounded swap');observations.push({case:'pending-preview-wallet-change',visible_wallet:wallet.value,old_preview_reappeared:true,prepared:f.runtime.prepared.map(p=>p.request),financial_execution:false});}
 assert.equal(!!stale,false,'Old wallet preview returned after wallet changed and exposed a fresh confirm action');
});
test('wallet change while preview preparation is pending must not restore old-wallet Continue',async()=>{
 const hold=gate(),f=setup({prepareGate:hold});const wallet=await quoteFlow(f);await press(f.root,'Preview this exact trade');
 wallet.value='wallet B';fire(wallet,'change');await tick();assert.equal(buttonNamed(f.root,'Continue to native confirmation'),undefined);
 hold.release();await tick();const stale=buttonNamed(f.root,'Continue to native confirmation');
 observations.push({case:'pending-prepare-wallet-change',visible_wallet:wallet.value,stale_continue:!!stale,prepared:f.runtime.prepared.map(p=>p.request),financial_execution:false});
 assert.equal(!!stale,false,'Old wallet prepared operation reappeared after context change');
});


test('context control: returned unused approval is cancelled exactly once on wallet change',async()=>{
 const f=setup();const wallet=await quoteFlow(f);await press(f.root,'Preview this exact trade');
 const id=f.runtime.prepared.at(-1).id;wallet.value='wallet B';fire(wallet,'change');await tick();
 wallet.value='wallet A';fire(wallet,'change');await tick();assert.deepEqual(f.runtime.cancelled,[id]);
});
test('context control: late preparation is cancelled once and cannot execute',async()=>{
 const hold=gate(),f=setup({prepareGate:hold});const wallet=await quoteFlow(f);await press(f.root,'Preview this exact trade');
 const id=f.runtime.prepared.at(-1).id;wallet.value='wallet B';fire(wallet,'change');await tick();hold.release();await tick();
 assert.deepEqual(f.runtime.cancelled,[id]);assert.equal(f.runtime.executed.filter(p=>p.request.method==='previewswap').length,0);
});
test('context control: a new review wins over an older pending preparation',async()=>{
 const hold=gate(),f=setup({prepareGate:n=>n===2?hold:null});await quoteFlow(f);await press(f.root,'Preview this exact trade');
 input(f.root,'Maximum outgoing network fees (input-asset atoms)').value='42';await press(f.root,'Preview this exact trade');
 const latest=f.runtime.prepared.at(-1);assert.ok(buttonNamed(f.root,'Continue to native confirmation'));hold.release();await tick();
 assert.deepEqual(f.runtime.cancelled,['prepared-1']);await press(f.root,'Continue to native confirmation');
 assert.equal(f.runtime.executed.at(-1).id,latest.id);assert.deepEqual(JSON.parse(latest.request.params_json),[{max_local_fee_atoms:'42',min_receive_atoms:RECEIVE,quote_id:QUOTE}]);
});
test('context control: stale preparation rejection does not overwrite the current wallet view',async()=>{
 const hold=gate(),f=setup({prepareGate:hold});const wallet=await quoteFlow(f);await press(f.root,'Preview this exact trade');
 wallet.value='wallet B';fire(wallet,'change');await tick();hold.reject(Error('old wallet secret failure'));await tick();
 assert.equal(f.root.textContent.includes('old wallet secret failure'),false);assert.equal(buttonNamed(f.root,'Continue to native confirmation'),undefined);
});
test('context control: changing connection rejects an old Continue without execute',async()=>{
 const f=setup();await quoteFlow(f);await press(f.root,'Preview this exact trade');
 const id=f.runtime.prepared.at(-1).id;current=f.runtime; // Keep the same controlled native endpoint.
 // The actual Bridge holds its connection epoch; expose it through setup below.
 f.bridge.epoch++;await press(f.root,'Continue to native confirmation');assert.deepEqual(f.runtime.cancelled,[id]);
 assert.equal(f.runtime.executed.filter(p=>p.request.method==='previewswap').length,0);
});
test('context control: disposal retires ready approval and late completion cannot restore controls',async()=>{
 const f=setup();await quoteFlow(f);await press(f.root,'Preview this exact trade');const id=f.runtime.prepared.at(-1).id;
 f.root.dispose();f.root.dispose();await tick();assert.deepEqual(f.runtime.cancelled,[id]);
 // A retained detached control cannot submit its consumed context.
 await press(f.root,'Continue to native confirmation');assert.equal(f.runtime.executed.filter(p=>p.request.method==='previewswap').length,0);
});
test('context control: pending execution remains pending after wallet change, never falsely cancelled or retried',async()=>{
 const hold=gate(),f=setup({executeGate:hold});const wallet=await quoteFlow(f);await press(f.root,'Preview this exact trade');await press(f.root,'Continue to native confirmation');
 wallet.value='wallet B';fire(wallet,'change');await tick();hold.release();await tick();
 assert.deepEqual(f.runtime.cancelled,[]);assert.equal(f.runtime.executed.filter(p=>p.request.method==='previewswap').length,1);
 assert.equal(f.root.textContent.includes('Cancelled.'),false);assert.ok(f.root.textContent.includes('inspect Activity before retrying')); assert.equal(buttonNamed(f.root,'Authorize one bounded swap'),undefined);
});
test('context control: ordinary status refresh does not cancel a valid prepared review',async()=>{
 const f=setup();await quoteFlow(f);await press(f.root,'Preview this exact trade');const id=f.runtime.prepared.at(-1).id;
 await press(f.root,'Refresh');assert.deepEqual(f.runtime.cancelled,[]);await press(f.root,'Continue to native confirmation');assert.equal(f.runtime.executed.at(-1).id,id);
});
test('context control: explicit cancellation retires one approval without execution',async()=>{
 const f=setup();await quoteFlow(f);await press(f.root,'Preview this exact trade');const id=f.runtime.prepared.at(-1).id;
 await press(f.root,'Cancel');assert.deepEqual(f.runtime.cancelled,[id]);assert.equal(buttonNamed(f.root,'Continue to native confirmation'),undefined);assert.equal(f.runtime.executed.filter(p=>p.request.method==='previewswap').length,0);
});

test('context control: late read rejection cannot overwrite the new wallet review',async()=>{
 const f=setup();await quoteFlow(f);await press(f.root,'Peer invitations');
 const hold=gate(),invoke=f.runtime.invoke.bind(f.runtime);f.runtime.invoke=async(command,args)=>{
  if(command==='atlas_read'&&args.request.method==='inspectswapinvite')return hold.wait;
  return invoke(command,args);
 };
 input(f.root,'Signed SwapNet invitation').value='btx://swapnet/v1/abc_DEF-123';await press(f.root,'Verify invitation without connecting');
 const wallet=input(f.root,'Native BTX wallet');wallet.value='wallet B';fire(wallet,'change');await tick();hold.reject(Error('old inspection failure'));await tick();
 assert.equal(f.root.textContent.includes('old inspection failure'),false);assert.equal(f.root.textContent.includes('Wallet changed.'),true);
});
test('context control: disposal cancels a late prepared approval once',async()=>{
 const hold=gate(),f=setup({prepareGate:hold});await quoteFlow(f);await press(f.root,'Preview this exact trade');const id=f.runtime.prepared.at(-1).id;
 f.root.dispose();hold.release();await tick();assert.deepEqual(f.runtime.cancelled,[id]);assert.equal(buttonNamed(f.root,'Continue to native confirmation'),undefined);
});

test('context control: SwapNet view cleanup disposes its workspace through the existing application hook',async()=>{
 const f=setup({useView:true});await quoteFlow(f);await press(f.root,'Preview this exact trade');const id=f.runtime.prepared.at(-1).id;
 assert.equal(typeof f.app.cleanup,'function');f.app.cleanup();await tick();assert.deepEqual(f.runtime.cancelled,[id]);
 await press(f.root,'Continue to native confirmation');assert.equal(f.runtime.executed.filter(p=>p.request.method==='previewswap').length,0);
});
test('context control: the newest quote refresh wins over an older response',async()=>{
 const f=setup();await quoteFlow(f);const hold=gate(),invoke=f.runtime.invoke.bind(f.runtime);let count=0;
 f.runtime.invoke=async(command,args)=>{
  if(command==='atlas_read'&&args.request.method==='getswapquotes'){
   count++;if(count===1)return hold.wait;
   return {ok:true,result:{quotes:[]}};
  }
  return invoke(command,args);
 };
 await press(f.root,'Refresh quotes');await press(f.root,'Refresh quotes');
 hold.release({ok:true,result:{quotes:[{id:QUOTE,provider:'old-maker',minimum_receive_atoms:RECEIVE}]}});await tick();
 assert.equal(buttonNamed(f.root,'Preview this exact trade'),undefined);assert.equal(f.root.textContent.includes('old-maker'),false);
});

test('row context control: an old quote action cannot prepare while a new wallet refresh is pending',async()=>{
 const f=setup();const wallet=await quoteFlow(f),oldPreview=buttonNamed(f.root,'Preview this exact trade');
 const hold=gate(),invoke=f.runtime.invoke.bind(f.runtime);f.runtime.invoke=async(command,args)=>{
  if(command==='atlas_read'&&args.request.method==='getswapreadiness')return hold.wait;
  return invoke(command,args);
 };
 const count=f.runtime.prepared.length;wallet.value='wallet B';fire(wallet,'change');await tick();
 try{fire(oldPreview,'click');await tick();assert.equal(f.runtime.prepared.length,count,'A quote row from wallet A prepared a new request under wallet B');assert.equal(buttonNamed(f.root,'Preview this exact trade'),undefined);}
 finally{hold.release({ok:true,result:{ready:true}});await tick();}
});
test('row context control: an old activity refund action cannot prepare under the new wallet',async()=>{
 const f=setup();const wallet=await quoteFlow(f),hold=gate(),invoke=f.runtime.invoke.bind(f.runtime);let deferRefresh=false;
 f.runtime.invoke=async(command,args)=>{
  if(command==='atlas_read'&&args.request.method==='listswaps')return {ok:true,result:{swaps:[{swap_id:'5'.repeat(64),stage:'funded'}]}};
  if(command==='atlas_read'&&args.request.method==='getswapreadiness'&&deferRefresh)return hold.wait;
  return invoke(command,args);
 };
 await press(f.root,'Swaps & recovery');const oldRefund=buttonNamed(f.root,'refundswap');assert.ok(oldRefund);
 const count=f.runtime.prepared.length;deferRefresh=true;wallet.value='wallet B';fire(wallet,'change');await tick();
 try{fire(oldRefund,'click');await tick();assert.equal(f.runtime.prepared.length,count,'An activity row from wallet A prepared a refund under wallet B');assert.equal(buttonNamed(f.root,'refundswap'),undefined);}
 finally{hold.release({ok:true,result:{ready:true}});await tick();}
});

test('row context control: a pending inspection error cannot overwrite a newer prepared review',async()=>{
 const f=setup();await quoteFlow(f);await press(f.root,'Peer invitations');const hold=gate(),invoke=f.runtime.invoke.bind(f.runtime);
 f.runtime.invoke=async(command,args)=>{if(command==='atlas_read'&&args.request.method==='inspectswapinvite')return hold.wait;return invoke(command,args);};
 input(f.root,'Signed SwapNet invitation').value='btx://swapnet/v1/abc_DEF-123';await press(f.root,'Verify invitation without connecting');
 await press(f.root,'Review one-time peer connection');assert.ok(f.root.textContent.includes('connectswapinvite'));
 hold.reject(Error('obsolete inspection failure'));await tick();assert.ok(f.root.textContent.includes('connectswapinvite'));assert.equal(f.root.textContent.includes('obsolete inspection failure'),false);
 assert.equal(f.runtime.executed.some(p=>p.request.method==='connectswapinvite'),false);
});
