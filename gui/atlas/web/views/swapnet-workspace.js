import {el,button,heading,note,jsonView} from '../components/ui.js';
import {atomString,offerRows,unwrap,prepareReviewed,previewId,parseInvitation} from '../core/swapnet-market.js';

/** Full native market workspace. All writes/dials use the existing Rust/Tauri
 * prepare -> native review -> execute path. Browser rendering never calls RPC.
 */
export function swapnetWorkspace(app){
 const root=el('div',{class:'page'},heading('SwapNet','Direct BTX liquidity. Compare signed offers, approve exact trades, and retain independent recovery.'));
 const status=el('div',{class:'surface-stack'}),review=el('section',{class:'panel'}),content=el('div',{class:'surface-stack'});
 const wallet=el('select',{'aria-label':'Native BTX wallet'}),walletRow=el('label',{},'Native wallet ',wallet);
 let epoch=0,selectedRequest=null,auth=null,contextRevision=0,reviewSequence=0,alive=true,readyApproval=null,executePending=0;
 const context=()=>({revision:contextRevision,epoch:app.bridge.epoch,wallet:wallet.value||null});
 const current=c=>alive&&c.revision===contextRevision&&c.epoch===app.bridge.epoch&&c.wallet===(wallet.value||null)&&(c.review===undefined||c.review===reviewSequence);
 const stale=()=>Object.assign(Error('The market context changed. Review a fresh operation.'),{code:'STALE_CONTEXT'});
 const discard=id=>{void app.bridge.cancel(id).catch(()=>{});};
 const retireReady=(expected=null)=>{if(readyApproval&&(expected===null||readyApproval===expected)){const id=readyApproval;readyApproval=null;discard(id);}};
 const invalidate=()=>{contextRevision++;reviewSequence++;epoch++;retireReady();};
 wallet.append(el('option',{value:''},'Use node binding'));
 const text=(label,value='',type='text')=>{const input=el('input',{type,value,'aria-label':label,autocomplete:'off'});return {input,node:el('label',{class:'field'},label,input)};};
 const area=label=>{const input=el('textarea',{'aria-label':label,rows:4,spellcheck:'false'});return {input,node:el('label',{class:'field'},label,input)};};
 const checkbox=label=>{const input=el('input',{type:'checkbox'});return {input,node:el('label',{},input,' ',label)};};
 const box=(title,...children)=>el('section',{class:'panel'},el('h2',{},title),...children);
 const failure=e=>{if(alive&&e?.code!=='STALE_CONTEXT')review.replaceChildren(note(e?.message||String(e),'warning'));};
 const value=input=>input.value.trim();
 const controls=c=>(label,run,kind='',attrs={})=>button(label,event=>{if(current(c))return run(event);},kind,attrs);
 async function read(method,request=null,c={...context(),review:reviewSequence}){
  if(!current(c))throw stale();
  try{const result=unwrap(await app.bridge.read(method,request===null?[]:[request],c.wallet));
   if(!current(c))throw stale();return result;
  }catch(e){if(!current(c))throw stale();throw e;}
 }
 async function reviewed(method,request,done=null,expected=context()){
  if(!current(expected))return;
  retireReady();const c={...context(),review:++reviewSequence};
  review.replaceChildren(note('Preparing exact arguments for native review…'));
  try{
   const prepared=await prepareReviewed(app.bridge,method,request,c.wallet),id=previewId(prepared);
   if(!current(c)){discard(id);return;}readyApproval=id;
   const execute=button('Continue to native confirmation',async()=>{
    if(!current(c)){retireReady(id);return;}
    if(execute.disabled)return;
    // After execute starts, only the native outcome establishes submission or cancellation.
    // A context change must not claim to undo or retry this operation.
    readyApproval=null;execute.disabled=true;cancel.disabled=true;executePending++;
    try{const result=unwrap(await app.bridge.execute(id));if(!current(c))return;
     review.replaceChildren(el('h2',{},'Native result'),jsonView(result,{open:true}));if(done)await done(result,c);
    }catch(e){if(current(c))failure(e);}finally{executePending--;}
   },'primary');
   const cancel=button('Cancel',async()=>{
    if(!current(c))return;readyApproval=null;reviewSequence++;
    try{await app.bridge.cancel(id);}catch(e){if(alive&&c.revision===contextRevision&&c.epoch===app.bridge.epoch&&c.wallet===(wallet.value||null)&&reviewSequence===c.review+1)failure(e);return;}
    if(alive&&c.revision===contextRevision&&c.epoch===app.bridge.epoch&&c.wallet===(wallet.value||null)&&reviewSequence===c.review+1)review.replaceChildren(note('Cancelled. No new action was authorized.'));
   });
   review.replaceChildren(el('h2',{},method),jsonView(prepared,{open:true,title:'Prepared native operation'}),
    note('Review the exact wallet, asset, amount, fees, beneficiaries and deadlines in the native confirmation. A quote or invitation is not spending authority.'),el('div',{class:'actions'},execute,cancel));
  }catch(e){if(current(c))failure(e);}
 }
 async function refresh(){
  if(!alive)return;const c=context();
  const generation=++epoch;status.replaceChildren(note('Reading native discovery and verifier readiness…'));
  try{
   const [network,readiness,mode,who]=await Promise.all([read('getswapnetworkinfo',null,c),read('getswapreadiness',null,c),read('getswapmode',null,c),read('getswapauthinfo',null,c)]);
   if(generation!==epoch||!current(c))return;auth=who;
   status.replaceChildren(box('Participation and readiness',note(`Mode: ${mode.mode}. Discovery: ${mode.discovery_enabled?'on':'off'}. Existing authorized swaps continue recovery.`),
    note('A local full verifier is required for each chain before settlement. Advertised liquidity is not a proof of reserves.'),jsonView({network,readiness,caller:who},{open:false,title:'Native observations'})));
   await showMarkets();
  }catch(e){if(generation===epoch&&current(c))status.replaceChildren(note(e.message,'warning'));}
 }
 async function showMarkets(){
  const c=context(),action=controls(c);
  const panel=box('Public maker offers',note('Signed firm offers reserve capacity at the maker. They are not collateralized guarantees. Indicative offers may change when quoted.'));
  content.replaceChildren(panel);
  let cursor='';const records=[];
  try{
   for(let pages=0;pages<32;pages++){
    const page=await read('listswappublicoffers',{after:cursor,limit:64},c);records.push(...(page.offers||[]));
    if(!page.next_cursor)break;cursor=page.next_cursor;
    if(pages===31)panel.append(note('Display reached its bounded page limit. More records may exist.'));
   }
   const rows=offerRows({offers:records});
   if(!rows.length)panel.append(note('No live public offers are known. Discovery remains active. No liquidity is invented. Connect an invitation or use a private request for a known pair.'));
   for(const row of rows){
    const request=action('Request exact signed quote',()=>reviewed('requestpublicswapquote',
      {provider:row.provider,offer_id:row.offerId,tier:row.tier},async r=>{selectedRequest=r.request_id;await showQuotes();}));
    panel.append(box(`${row.kind==='firm'?'Reserved firm':'Indicative'} · ${row.sellAtoms} input atoms`,
      note(`${row.sellAsset} → ${row.buyAsset}`),note(`Minimum receive under the advertised fee caps: ${row.minimumReceiveAtoms} atoms.`),
      note(`Provider: ${row.provider}`),note(row.assurance),note(`Expires: ${new Date(row.expiresAt*1000).toISOString()}`),request));
   }
  }catch(e){if(e?.code!=='STALE_CONTEXT'&&alive)panel.append(note(e.message,'warning'));}
 }
 async function showQuotes(){
  const c=context(),action=controls(c);
  const rid=text('Request identifier',selectedRequest||'');const panel=box('Requester-bound quotes',rid.node);
  const results=el('div',{class:'surface-stack'});let quoteSequence=0;
  const load=async()=>{
   const generation=++quoteSequence;
   try{selectedRequest=value(rid.input);const data=await read('getswapquotes',{request_id:selectedRequest},c);if(generation!==quoteSequence)return;results.replaceChildren();
    if(!(data.quotes||[]).length)results.append(note('No live executable quote yet. Refresh while this request is unexpired. A missing reply is not proof of wrongdoing.'));
    for(const q of data.quotes||[]){
     const fee=text('Maximum outgoing network fees (input-asset atoms)');
     const minimum=text('Minimum received (output-asset atoms)',q.minimum_receive_atoms||'0');
     const prepare=action('Preview this exact trade',()=>{
      try{const req={quote_id:q.id,max_local_fee_atoms:atomString(value(fee.input),{positive:true}),min_receive_atoms:atomString(value(minimum.input),{positive:true})};
       reviewed('previewswap',req,(p,c)=>{
        const confirm=button('Authorize one bounded swap',()=>reviewed('confirmswap',{preview_id:p.preview_id},()=>showActivity(),c),'primary');
        review.append(note('The preview has not reserved or sent funds. The next native confirmation authorizes exactly this quote and its fee limits.'),confirm);
       });
      }catch(e){failure(e);}
     });
     results.append(box(`Net floor: ${q.minimum_receive_atoms} output atoms`,note(`Provider: ${q.provider}`),jsonView(q,{open:false}),fee.node,minimum.node,prepare));
    }
    if(data.declined)results.append(jsonView(data.declined,{open:true,title:'Signed provider refusal (native observation)'}));
   }catch(e){if(generation===quoteSequence&&e?.code!=='STALE_CONTEXT'&&alive)results.replaceChildren(note(e.message,'warning'));}
  };
  panel.append(action('Refresh quotes',load),results);content.replaceChildren(panel);if(selectedRequest)await load();
 }
 function showPrivate(){
  const c=context(),action=controls(c);
  const sell=text('Exact sell asset ID'),buy=text('Exact buy asset ID'),amount=text('Input amount in atoms');
  content.replaceChildren(box('Private-size request',note('The legacy RFQ is broadcast over native peers. Its terms may be observable to relays. Public-offer requests are addressed to the selected maker.'),
   sell.node,buy.node,amount.node,action('Review quote request',()=>{try{reviewed('requestswapquote',{sell_asset:value(sell.input),buy_asset:value(buy.input),sell_atoms:atomString(value(amount.input),{positive:true})},async r=>{selectedRequest=r.request_id;await showQuotes();});}catch(e){failure(e);}})));
 }
 async function showMaker(){
  const c=context(),action=controls(c);
  const sell=text('Taker sells (exact asset ID)'),buy=text('Taker receives / maker pays (exact asset ID)');
  const numerator=text('Gross output numerator'),denominator=text('Input denominator'),maximum=text('Maximum input atoms');
  const makerFee=text('Maker fee (output atoms)','0'),receiveFee=text('Maximum recipient network fees (output atoms)');
  const localFee=text('Maximum maker outgoing fees (output atoms)'),refundFee=text('Maker refund budget (output atoms)'),claimFee=text('Maker claim budget (input atoms)');
  const mandate=text('Existing maker mandate ID'),hours=text('Market lifetime in hours','24'),sizes=text('Public standard sizes, comma-separated input atoms');
  const kind=el('select',{'aria-label':'Public offer kind'},el('option',{value:'indicative'},'Indicative'),el('option',{value:'firm'},'Reserved firm'));
  const market=()=>({sell_asset:value(sell.input),buy_asset:value(buy.input),numerator:atomString(value(numerator.input),{positive:true}),
   denominator:atomString(value(denominator.input),{positive:true}),max_input_atoms:atomString(value(maximum.input),{positive:true}),maker_fee_atoms:atomString(value(makerFee.input)),
   max_receive_network_fee_atoms:atomString(value(receiveFee.input)),expires_at:Math.floor(Date.now()/1000)+Math.floor(Number(value(hours.input))*3600)});
  const configure=action('Review maker policy',()=>{try{reviewed('setswapmarket',{market:market(),mandate_id:value(mandate.input),
   max_local_fee_atoms:atomString(value(localFee.input),{positive:true}),refund_fee_atoms:atomString(value(refundFee.input),{positive:true}),
   claim_fee_atoms:atomString(value(claimFee.input),{positive:true}),enabled:true});}catch(e){failure(e);}});
  const publish=action('Review public offer',()=>{try{reviewed('publishswapoffer',{sell_asset:value(sell.input),buy_asset:value(buy.input),
   sizes:value(sizes.input).split(',').map(x=>atomString(x.trim(),{positive:true})),kind:kind.value,slots:1,ttl:120});}catch(e){failure(e);}});
  const cap=text('Cumulative maker payout + fee budget (output atoms)'),tradeCap=text('Maximum maker payout per trade (output atoms)');
  const createGrant=action('Review bounded maker mandate',()=>{
   try{if(!auth?.principal)throw Error('Refresh native caller identity first.');
    const bytes=crypto.getRandomValues(new Uint8Array(32));const nonce=Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
    reviewed('createswapmandate',{mandate:{principal:auth.principal,asset:value(buy.input),max_total_atoms:atomString(value(cap.input),{positive:true}),
     max_trade_atoms:atomString(value(tradeCap.input),{positive:true}),max_fee_atoms:atomString(value(localFee.input),{positive:true}),
     expires_at:market().expires_at,nonce}},r=>{mandate.input.value=r.mandate_id;});
   }catch(e){failure(e);}
  });
  const withdrawal=text('Offer identifier to withdraw');
  const capacity=el('div');
  content.replaceChildren(box('Provide liquidity',note('First configure and fund independently verified chain wallets. A market is written from the taker’s perspective: its buy asset is the maker’s outgoing asset.'),
   action('Enable maker mode (native review)',()=>reviewed('setswapmode',{mode:'maker'},refresh)),sell.node,buy.node,numerator.node,denominator.node,maximum.node,
   makerFee.node,receiveFee.node,localFee.node,refundFee.node,claimFee.node,hours.node,
   cap.node,tradeCap.node,createGrant,mandate.node,configure,
   note('To quote both directions, repeat with the pair reversed and a separate mandate denominated in that direction’s outgoing asset. Neither direction is implied by the other.'),
   sizes.node,el('label',{},'Offer kind ',kind),publish,withdrawal.node,action('Review withdrawal',()=>reviewed('withdrawswapoffer',{offer_id:value(withdrawal.input)})),
   action('Review local reserved capacity',()=>reviewed('getswapmakercapacity',{},r=>capacity.replaceChildren(jsonView(r,{open:true})))),capacity));
 }
 function showPeers(initial=''){
  const c=context(),action=controls(c);
  const invitation=area('Signed SwapNet invitation');invitation.input.value=initial;
  const privateConsent=checkbox('Allow a private or reserved IP endpoint (never loopback or link-local)'),dnsConsent=checkbox('Allow owner-reviewed DNS resolution through the node’s configured network policy');
  const endpoints=text('My reachable BTX P2P endpoints (comma separated)'),info=el('div'),index=el('select',{'aria-label':'Endpoint to connect'});
  const inspect=action('Verify invitation without connecting',async()=>{
   try{parseInvitation(value(invitation.input));const r=await read('inspectswapinvite',{uri:value(invitation.input),allow_private:privateConsent.input.checked},{...c,review:reviewSequence});
    info.replaceChildren(jsonView(r,{open:true}),note('A signature binds the advertised endpoint to a provider key. The TCP peer is not authenticated by this link; trade quotes are verified independently.'));
    index.replaceChildren(...r.endpoints.map((e,i)=>el('option',{value:String(i)},e.endpoint)));
   }catch(e){failure(e);}
  });
  const connect=action('Review one-time peer connection',()=>reviewed('connectswapinvite',{uri:value(invitation.input),endpoint_index:Number(index.value||0),
   allow_private:privateConsent.input.checked,allow_dns:dnsConsent.input.checked}));
  const share=action('Create my signed invitation',()=>reviewed('createswapinvite',{endpoints:value(endpoints.input).split(',').map(x=>x.trim()),ttl:86400,allow_private:privateConsent.input.checked},r=>{
   invitation.input.value=r.uri;review.append(action('Copy invitation',async()=>{try{await app.bridge.copy(r.uri);}catch(e){failure(e);}}));
  }));
  content.replaceChildren(box('Connect and share',note('Invitations contain P2P endpoints and a provider identity—not RPC credentials, wallet keys, verifier URLs, or spending permission.'),
   invitation.node,privateConsent.node,dnsConsent.node,inspect,info,index,connect,
   el('h3',{},'Share this node'),note('Advertise an actually reachable BTX P2P port, not the RPC port or ModelNet port. A NAT/firewall may require an explicit mapping. Tor requires the node’s configured proxy.'),endpoints.node,share));
 }
 function showSetup(){
  const c=context(),action=controls(c);
  const rpc=text('Bitcoin loopback RPC URL','http://127.0.0.1:8332'),cookie=text('Local Bitcoin cookie path'),funding=text('Loaded Bitcoin funding wallet');
  const evmAsset=text('Exact EVM asset ID'),evmRpc=text('EVM loopback RPC URL','http://127.0.0.1:8545'),contract=text('Pinned HTLC contract address'),runtime=text('Expected runtime Keccak-256');
  const deployment=area('Owner-verified deployment manifest JSON');
  content.replaceChildren(box('Independent verification setup',note('SwapNet never obtains verifier endpoints or signing keys from a maker or invitation. Connect your own locally verified chain clients. Discovery remains available while setup is incomplete.'),
   el('h3',{},'Bitcoin'),rpc.node,cookie.node,funding.node,
   action('Review Bitcoin watch-wallet setup',()=>reviewed('setupswapbitcoin',{policy:{rpc_url:value(rpc.input),cookie_path:value(cookie.input),wallet:value(funding.input)}})),
   el('h3',{},'Ethereum / native ETH'),evmAsset.node,evmRpc.node,contract.node,runtime.node,deployment.node,
   action('Review EVM verifier policy',()=>{try{reviewed('setswapassetpolicy',{policy:{asset:value(evmAsset.input),rpc_url:value(evmRpc.input),contract:value(contract.input),runtime_hash:value(runtime.input),deployment:JSON.parse(value(deployment.input))}});}catch(e){failure(e);}}),
   action('Enable taker mode (native review)',()=>reviewed('setswapmode',{mode:'taker'},refresh)),
   action('Observe only; preserve authorized recovery',()=>reviewed('setswapmode',{mode:'observe'},refresh)),
   action('Recovery only; stop new market participation',()=>reviewed('setswapmode',{mode:'recovery'},refresh))));
 }
 async function showActivity(){
  const c=context(),action=controls(c);
  const panel=box('Swaps and recovery',note('Pausing new activity does not revoke already authorized swaps. They may still complete reserved funding, claims, or refunds. Keep both verifiers available.'));
  content.replaceChildren(panel);
  try{const r=await read('listswaps',{limit:100},c);
   for(const swap of r.swaps||[]){const actions=el('div',{class:'actions'});
    for(const method of ['resumeswap','refundswap','cancelswap','exportswapreceipt'])actions.append(action(method,()=>reviewed(method,{swap_id:swap.swap_id})));
    panel.append(box(`${swap.stage} · ${swap.swap_id}`,jsonView(swap,{open:false}),actions));
   }
   if(!(r.swaps||[]).length)panel.append(note('No local swaps.'));
  }catch(e){if(e?.code!=='STALE_CONTEXT'&&alive)panel.append(note(e.message,'warning'));}
  const pass=text('Recovery export passphrase','', 'password'),repeat=text('Confirm recovery passphrase','','password');
  panel.append(pass.node,repeat.node,action('Review encrypted recovery export',()=>{
   const secret=pass.input.value,confirmation=repeat.input.value;pass.input.value='';repeat.input.value='';
   if(secret!==confirmation||secret.length<20){failure(Error('Use matching strong independent passphrases, at least 20 characters.'));return;}
   reviewed('exportswaprecovery',{passphrase:secret});
  }),note('Back up the native BTX wallet separately. The recovery bundle must not be restored while its original owner is still active.'));
 }
 const navigate=show=>()=>{invalidate();review.replaceChildren();return show();};
 const nav=el('div',{class:'actions'},button('Markets',navigate(showMarkets)),button('Quotes',navigate(showQuotes)),button('Private-size RFQ',navigate(showPrivate)),
  button('Provide liquidity',navigate(showMaker)),button('Peer invitations',navigate(()=>showPeers())),button('Verifier setup',navigate(showSetup)),button('Swaps & recovery',navigate(showActivity)),button('Refresh',refresh));
 root.append(walletRow,nav,status,content,review);
 wallet.addEventListener('change',()=>{selectedRequest=null;auth=null;invalidate();content.replaceChildren(note('Reading the selected wallet context…'));review.replaceChildren(note(executePending?'Wallet changed. An earlier operation may still be in progress; inspect Activity before retrying.':'Wallet changed. Previously prepared operations must be re-reviewed.'));refresh();});
 root.dispose=()=>{if(!alive)return;invalidate();alive=false;};
 (async()=>{try{const names=await read('listwallets');for(const name of names||[])wallet.append(el('option',{value:name},name));if(names?.length===1)wallet.value=names[0];}catch{}await refresh();})();
 // A router can pass a startup link here; it opens only the inert preview form.
 root.openSwapInvitation=uri=>{parseInvitation(uri);invalidate();review.replaceChildren();showPeers(uri);};
 return root;
}
