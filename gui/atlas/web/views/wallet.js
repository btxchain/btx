import {el,button,field,note,metric,jsonView,table,dialog,toast,heading,humanBytes,downloadCSV} from '../components/ui.js';
import {operationDialog,operationWorkbench} from './operations.js';
import {parseBTX,formatBTX,formatUnit} from '../core/money.js';
import {formatObservedTime} from '../core/json.js';
import {sourceRows} from '../core/graph.js';
import {historyFilter,paymentRequest} from '../core/qt-gaps.js';
import {loadRequests,rememberRequest,qrSvg} from '../core/receive-history.js';
import {atomsPerVbyteFromKvb,feeDecimal,txSummary} from '../core/network.js';
import {txExplorerTemplate} from '../core/qt-surface.js';
import {createWalletDraft,coinSelectionSummary,receivingAddressArgs,historyWalk,nextHistorySkip,coinTree,psbtWithinLimit,addressFacts,walletFacts} from '../core/wallet-qt.js';
export function walletView(app){
 const root=el('div',{class:'page wallet-page'},heading('Wallet','Self-custody remains in btxd. Signing and broadcasting have independent native reviews.'));
 const wallet=el('select',{'aria-label':'Select wallet'}),summary=el('div',{class:'metrics'}),content=el('div'),selected=app.state.state.wallet||'';
 root.append(el('div',{class:'row'},field('Loaded wallet',wallet),button('Create',()=>{current='Manage';show();}),button('Open',()=>operationDialog(app,'loadwallet')),button('Restore',()=>operationDialog(app,'restorewallet'))),summary);
 const tabs=['Overview','Send','Receive','History','Coins','Address book','Addresses','Sign / Verify','PSBT','Manage'];let current='Overview';
 const tabBar=el('nav',{class:'tabs','aria-label':'Wallet sections'});for(const name of tabs)tabBar.append(button(name,()=>{current=name;show();},'',{dataset:{walletTab:name}}));root.append(tabBar,content);
 async function read(method,params=[]){return(await app.bridge.read(method,params,wallet.value||null)).result;}
 function denomination(v){if(v===undefined||v===null)return '—';try{return formatUnit(parseBTX(String(v),{signed:true}),app.preferences.unit);}catch{return 'Invalid native amount';}}
 function mask(v){return app.state.state.privacy?'••••':String(v??'—');}
 function addressShown(v){if(app.preferences.displayAddresses===false||app.state.state.privacy)return '••••';return String(v??'—');}
 function copyButton(label,text){return button(label,()=>app.bridge.copy(text).catch(e=>toast(e.message,'danger')));}
 function showTransaction(row){const summary=txSummary(row)||{};const template=txExplorerTemplate(app.preferences.txExplorer||'');const txid=/^[a-fA-F0-9]{64}$/.test(summary.txid||'')?summary.txid:'';const link=template&&txid&&app.state.state.privacy!==true?el('a',{href:template.replace('%s',txid),target:'_blank',rel:'noreferrer'},'Open the configured transaction link'):null;dialog('Transaction',el('div',{class:'surface-stack'},el('p',{},`${summary.category||'transaction'} · ${mask(denomination(summary.amount))}`),el('p',{},`Confirmations: ${summary.confirmations??'—'}`),el('p',{},`Fee: ${summary.fee==null?'—':mask(denomination(summary.fee))}`),el('code',{class:'address'},summary.txid||''),link,note('This is the wallet’s record of the transaction. Chain confirmation remains a separate observation. A transaction link leaves this node only when values are visible and a template was saved.'),button('Read the full wallet record',()=>operationDialog(app,'gettransaction',[row.txid]))));}
 async function show(){
  [...tabBar.children].forEach(b=>b.classList.toggle('active',b.dataset.walletTab===current));content.replaceChildren();
  if(!wallet.value){content.append(note('No loaded wallet selected. Models, node observation, and Atlas do not require a wallet.'));if(current==='Manage')content.append(createWalletPanel());return;}
  app.state.update({wallet:wallet.value});const target=wallet.value;
  try{
   if(current==='Overview'){const [info,balances,recent]=await Promise.all([read('getwalletinfo'),read('getbalances'),read('listtransactions',['*',8,0,true])]);if(wallet.value!==target)return;summary.replaceChildren(metric('Available',mask(denomination(balances.mine?.trusted)),'Spendable on this node'),metric('Pending',mask(denomination(balances.mine?.untrusted_pending)),'Not confirmed'),metric('Immature',mask(denomination(balances.mine?.immature)),'Not yet spendable'));
    const latest=Array.isArray(recent)?recent.map(row=>({...row,when:formatObservedTime(row.time),amountShown:mask(denomination(row.amount)),addressShown:addressShown(row.address)})):[];
    content.append(el('div',{class:'panel'},el('h2',{},target),note(info.private_keys_enabled===false?'Watch-only / external signing wallet. The node still owns the watch.':'Wallet keys stay in btxd. Atlas prepares reviews and does not hold the keys.'),...walletFacts(info).map(line=>note(line)),el('div',{class:'row'},button('Send',()=>{current='Send';show();}),button('Receive',()=>{current='Receive';show();}),button('Transactions',()=>{current='History';show();}),button('Peers holding this chain',()=>app.navigate('network'))),table(latest,[{key:'when',label:'Time'},{key:'category',label:'Category'},{key:'amountShown',label:'Amount'},{key:'addressShown',label:'Address'},'confirmations'],{onSelect:showTransaction,empty:'No recent transactions in this wallet.'})),el('details',{},el('summary',{},'More wallet operations'),operationWorkbench(app,{groups:['Wallet','Recovery'],title:'Wallet and recovery functions'})));
   }else if(current==='Send')content.append(sendForm(app,wallet.value));
   else if(current==='Receive')content.append(receiveForm());
   else if(current==='History')await historyTab();
   else if(current==='Coins')await coinsTab();
   else if(current==='Address book')await addressBookTab();
   else if(current==='Addresses'){
    const labels=await read('listlabels');content.append(table(labels.map(label=>({label})),['label'],{onSelect:r=>operationDialog(app,'getaddressesbylabel',[r.label])}),button('Set address label',()=>operationDialog(app,'setlabel')));
   }else if(current==='Sign / Verify')content.append(signVerifyForm());
   else if(current==='PSBT')content.append(psbtForm());
   else content.append(manageSection(),el('details',{},el('summary',{},'More wallet administration'),operationWorkbench(app,{groups:['Wallet','Economy'],title:'Wallet administration and financial operations'})));
  }catch(e){content.append(note(e.message,'danger'));}
 }
 function receiveForm(){
  const amount=el('input',{placeholder:'Optional',inputmode:'decimal',autocomplete:'off',spellcheck:false}),label=el('input',{placeholder:'Optional receiving label',autocomplete:'off'}),message=el('input',{placeholder:'Optional message',autocomplete:'off'}),addressType=el('select',{'aria-label':'Address type'},...[['', 'Node default'],['p2mr','p2mr']].map(([value,text])=>el('option',{value},text))),out=el('div');
  const create=button('Create receiving address — native review',async()=>{
   create.disabled=true;
   try{
    const prepared=await app.bridge.prepare('getnewaddress',receivingAddressArgs(label.value,addressType.value),wallet.value);
    const response=await app.bridge.execute(prepared.id);
    const address=String(response.result);
    const request={address,amount:amount.value.trim(),label:label.value,message:message.value};
    let uri;try{uri=paymentRequest(request);}catch(e){out.replaceChildren(el('code',{class:'address'},address),note(e.message,'danger'));return;}
    try{const stored=rememberRequest(localStorage.getItem('atlas.receive.v1'),{...request,at:Date.now()});localStorage.setItem('atlas.receive.v1',JSON.stringify(stored));}catch{}
    const receipt=el('div',{class:'receipt',dataset:{printRoot:'request'}},el('code',{class:'address'},address),el('code',{class:'address'},uri),el('p',{},`Amount: ${request.amount}`),el('p',{},`Label: ${request.label}`),el('p',{},`Message: ${request.message}`));
    const actions=el('div',{class:'row'},copyButton('Copy URI',uri),copyButton('Copy amount',request.amount),copyButton('Copy label',request.label),copyButton('Copy message',request.message));
    out.replaceChildren(receipt,actions);
    try{const qr=await app.bridge.invoke('atlas_qr',{text:uri});const drawn=drawQR(qr);if(drawn&&drawn.tagName==='CANVAS')receipt.append(drawn);else if(drawn)out.append(drawn);const svg=qrSvg(qr);if(svg)actions.append(button('Save QR image',()=>app.bridge.export(svg,'btx-request.svg').catch(e=>toast(e.message,'danger'))),button('Print this request',()=>window.print()));}catch(e){out.append(note(e.message,'danger'));}
    paintRequests();
   }catch(e){out.replaceChildren(note(e.message,'danger'));}
   finally{create.disabled=false;}
  },'primary');
  const history=el('div');
  function paintRequests(){
   let rows=[];try{rows=loadRequests(localStorage.getItem('atlas.receive.v1'));}catch{rows=[];}
   history.replaceChildren(rows.length?table(rows.map(row=>({...row,when:row.at?formatObservedTime(row.at):'—'})),[{key:'when',label:'Time'},{key:'address',label:'Address',render:addressShown},{key:'amount',label:'Amount'},'label','message',{key:'actions',label:'Actions',render:(_v,row)=>button('Fill form',ev=>{ev.stopPropagation();amount.value=row.amount??'';label.value=row.label??'';message.value=row.message??'';})}]):note('No receiving requests saved in this browser profile.'));
  }
  paintRequests();
  return el('section',{class:'panel'},el('h2',{},'Request payment'),field('Amount (optional)',amount),field('Label (optional)',label),field('Address type',addressType),field('Message (optional)',message),create,out,el('h3',{},'Request history'),note('This history is local to Atlas. It is not a wallet transaction and it does not prove a payment.'),history);
 }
 async function historyTab(){
  let offset=0,raw=[];const area=el('div');
  const category=el('select',{'aria-label':'Transaction category'},...[['','all'],['send','send'],['receive','receive'],['generate','generate'],['immature','immature'],['orphan','orphan']].map(([value,label])=>el('option',{value},label)));
  const query=el('input',{type:'search',placeholder:'Filter transactions','aria-label':'Filter transactions',autocomplete:'off'});
  const rowActions=(_v,row)=>{
   const actions=[button('Bump fee',ev=>{ev.stopPropagation();operationDialog(app,'bumpfee',[row.txid]);}),button('Abandon transaction',ev=>{ev.stopPropagation();operationDialog(app,'abandontransaction',[row.txid]);}),button('Copy transaction id',ev=>{ev.stopPropagation();app.bridge.copy(String(row.txid??'')).catch(e=>toast(e.message,'danger'));})];
   if(typeof row.address==='string'&&row.address!=='')actions.push(button('Copy address',ev=>{ev.stopPropagation();app.bridge.copy(row.address).catch(e=>toast(e.message,'danger'));}));
   if(typeof row.label==='string'&&row.label!=='')actions.push(button('Copy label',ev=>{ev.stopPropagation();app.bridge.copy(row.label).catch(e=>toast(e.message,'danger'));}));
   return el('div',{class:'row'},...actions);
  };
  const columns=[{key:'time',label:'Time',render:v=>formatObservedTime(v)},'category',{key:'amount',label:'Amount',render:v=>mask(denomination(v))},'confirmations',{key:'address',label:'Address',render:v=>addressShown(v)},'label','txid',{key:'actions',label:'Actions',render:rowActions}];
  const exportStatus=el('div');
  let loadingHistory=false;
  const exportLoadedHistory=async()=>{
   if(loadingHistory)return;
   loadingHistory=true;
   exportStatus.replaceChildren();
   try{
    const {pageSize,cap}=historyWalk({pageSize:100,cap:2000});
    const loaded=[];
    let skip=0;
    let shortPage=false;
    while(loaded.length<cap){
     const listed=await read('listtransactions',['*',pageSize,skip,true]);
     const rows=Array.isArray(listed)?listed:[];
     const next=nextHistorySkip(skip,rows.length,pageSize);
     const room=cap-loaded.length;
     if(rows.length>room){loaded.push(...rows.slice(0,room));break;}
     loaded.push(...rows);
     if(next===null){shortPage=true;break;}
     if(loaded.length>=cap)break;
     skip=next;
    }
    const exportRows=loaded.map(row=>({time:formatObservedTime(row.time),category:row.category,amount:app.state.state.privacy?'hidden':row.amount,address:addressShown(row.address),confirmations:row.confirmations,txid:row.txid}));
    await app.bridge.export(downloadCSV(exportRows,['time','category','amount','address','confirmations','txid']),'wallet-history.csv');
    exportStatus.replaceChildren(note(shortPage||loaded.length<cap?`Exported ${loaded.length} transactions.`:'Exported 2000 transactions. Older history was not loaded.'));
   }finally{loadingHistory=false;}
  };
  const paint=()=>{
   const rows=historyFilter(raw,{category:category.value,query:query.value});
   const exportRows=rows.map(row=>({time:formatObservedTime(row.time),category:row.category,amount:app.state.state.privacy?'hidden':row.amount,address:addressShown(row.address),confirmations:row.confirmations,txid:row.txid}));
   area.replaceChildren(table(rows,columns,{search:false,onSelect:showTransaction}),el('div',{class:'row'},button('Export this page',()=>app.bridge.export(downloadCSV(exportRows,['time','category','amount','address','confirmations','txid']),'wallet-history.csv').catch(e=>toast(e.message,'danger'))),button('Export loaded history',()=>{exportLoadedHistory().catch(e=>toast(e.message,'danger'));})),exportStatus,note(`Native page starts at transaction ${offset}; this is not a consistent multi-page snapshot. Privacy mode hides amounts and addresses in the export.`));
  };
  const load=async()=>{const listed=await read('listtransactions',['*',100,offset,true]);raw=Array.isArray(listed)?listed:[];paint();};
  category.addEventListener('change',paint);query.addEventListener('input',paint);
  content.append(el('div',{class:'row'},field('Category',category),field('Filter',query),button('Newer',()=>{offset=Math.max(0,offset-100);load().catch(e=>toast(e.message,'danger'));}),button('Older',()=>{offset+=100;load().catch(e=>toast(e.message,'danger'));})),area);
  await load();
 }
 async function coinsTab(){
  if(app.preferences.coinControl===false){content.append(note('Coin control is off in Settings.'));return;}
  const listed=await read('listunspent',[0,9999999,[],true]);
  const coins=Array.isArray(listed)?listed:[];
  const chosen=new Set();const total=el('strong',{},'0 selected'),exact=el('p');
  const pickedCoins=()=>coins.filter((_,i)=>chosen.has(i));
  const selectionSummary=()=>coinSelectionSummary(pickedCoins().map(c=>({amount:String(c.amount)})));
  const update=()=>{const picked=pickedCoins();app.selectedCoins=picked.map(c=>({txid:c.txid,vout:Number(c.vout)}));let amount=0n;for(const c of picked)amount+=parseBTX(String(c.amount));total.textContent=`${chosen.size} selected · ${mask(formatUnit(amount,app.preferences.unit))}`;const summary=selectionSummary();exact.textContent=`${summary.count} ${summary.amount}`;};
  exact.textContent='0 0.00000000';
  const hideAddress=app.preferences.displayAddresses===false||!!app.state.state.privacy;
  const columns=[{key:'index',label:'Use',render:(v)=>el('input',{type:'checkbox',checked:chosen.has(v),dataset:{coin:v},'aria-label':`Select coin ${v}`,onChange:e=>{e.target.checked?chosen.add(v):chosen.delete(v);update();}})},{key:'amount',label:'Amount',render:v=>mask(denomination(v))},'confirmations',{key:'address',label:'Address',render:v=>addressShown(v)},'spendable','solvable','txid','vout'];
  function syncCoins(){for(const box of content.querySelectorAll('[data-coin]'))box.checked=chosen.has(Number(box.dataset.coin));update();}
  const indexed=coins.map((c,i)=>({...c,index:i}));
  const tree=coinTree(indexed);
  content.append(note('Coin selection is a local draft. Locking coins or signing still requires native review.'),total,exact,note('Fee, bytes, and change are known only after the unsigned transaction is prepared.'));
  if(!indexed.length)content.append(table([],columns,{empty:'No observed records.'}));
  for(const group of tree){
   content.append(el('h3',{},group.label?group.label:'—'));
   for(const bucket of group.addresses){
    const shown=hideAddress?bucket.coins.map(c=>({...c,address:'••••'})):bucket.coins;
    content.append(el('div',{class:'row'},el('h3',{},bucket.address?addressShown(bucket.address):'—'),button('Select this address',()=>{for(const coin of bucket.coins)chosen.add(coin.index);syncCoins();})),table(shown,columns));
   }
  }
  content.append(el('div',{class:'row'},button('Select all',()=>{for(const coin of indexed)chosen.add(coin.index);syncCoins();}),button('Clear selection',()=>{chosen.clear();syncCoins();}),button('Copy selection',()=>{try{const summary=selectionSummary();app.bridge.copy(`${summary.count} ${summary.amount}`).catch(e=>toast(e.message,'danger'));}catch(e){toast(e.message,'danger');}}),button('Use selected inputs',()=>{current='Send';show();}),button('Lock selected',()=>operationDialog(app,'lockunspent',[false,app.selectedCoins||[]])),button('Review locked coins',()=>operationDialog(app,'listlockunspent'))));
 }
 async function addressBookTab(){
  const errors=el('div'),detail=el('div'),receivingHost=el('div'),sendingHost=el('div');
  const bookAddress=el('input',{autocomplete:'off',spellcheck:false,'aria-label':'Address book address'}),bookLabel=el('input',{autocomplete:'off','aria-label':'Address book label'});
  content.append(el('h2',{},'Receiving'),note('These are receiving addresses from the wallet. Private keys are not exported.'),receivingHost,el('h2',{},'Sending'),note('A sending entry is a label stored by the wallet. Clearing the label removes that book entry and does not delete a key.'),sendingHost,el('div',{class:'fields'},field('Address',bookAddress),field('Label',bookLabel)),el('div',{class:'row'},button('Save sending label',()=>operationDialog(app,'setlabel',[bookAddress.value.trim(),bookLabel.value])),button('Clear label',()=>operationDialog(app,'setlabel',[bookAddress.value.trim(),'']))),detail,errors);
  const editButton=row=>button('Edit label',ev=>{ev.stopPropagation();operationDialog(app,'setlabel',[row.address,row.label||'']);});
  async function showMine(row){
   try{
    const info=await read('getaddressinfo',[row.address]);
    const ismine=info&&typeof info==='object'&&Object.prototype.hasOwnProperty.call(info,'ismine')?String(info.ismine):'—';
    detail.replaceChildren(note(`ismine: ${ismine}`),jsonView(info,{open:true,title:'Address info'}));
   }catch(e){detail.replaceChildren(note(e.message,'danger'));}
  }
  try{
   const listed=await read('listreceivedbyaddress',[0,true,true]);
   if(!Array.isArray(listed)){receivingHost.append(note('listreceivedbyaddress did not return a list','danger'));}
   else receivingHost.append(table(listed.map(r=>({label:r.label||'',address:r.address||'',amount:r.amount,confirmations:r.confirmations})),[{key:'label',label:'Label'},{key:'address',label:'Address',render:mask},{key:'amount',label:'Amount',render:v=>mask(denomination(v))},'confirmations',{key:'edit',label:'Edit',render:(_v,row)=>editButton(row)}],{onSelect:showMine}));
  }catch(e){receivingHost.append(note(e.message,'danger'));}
  try{
   const labels=await read('listlabels',['send']);
   const rows=[];
   if(!Array.isArray(labels))throw Error('listlabels did not return a list');
   for(const label of labels){
    try{
     const map=await read('getaddressesbylabel',[label]);
     if(!map||typeof map!=='object'||Array.isArray(map))continue;
     for(const [address,meta] of Object.entries(map))rows.push({address,label:String(label),purpose:meta&&meta.purpose?String(meta.purpose):'send'});
    }catch(e){errors.append(note(e.message,'danger'));}
   }
   sendingHost.append(table(rows,[{key:'label',label:'Label'},{key:'address',label:'Address',render:mask},{key:'purpose',label:'Purpose'},{key:'edit',label:'Edit',render:(_v,row)=>editButton(row)}],{onSelect:showMine}));
  }catch(e){
   errors.append(note(e.message,'danger'));
   try{
    const groups=await read('listaddressgroupings');
    const rows=[];
    if(Array.isArray(groups))for(const group of groups){if(!Array.isArray(group))continue;for(const entry of group){if(!Array.isArray(entry)||!entry[0])continue;rows.push({address:String(entry[0]),label:entry[2]?String(entry[2]):'',amount:entry[1]});}}
    sendingHost.append(table(rows,[{key:'label',label:'Label'},{key:'address',label:'Address',render:mask},{key:'amount',label:'Amount',render:v=>v===undefined?'—':mask(denomination(v))},{key:'edit',label:'Edit',render:(_v,row)=>editButton(row)}],{onSelect:showMine}));
   }catch(e2){sendingHost.append(note(e2.message,'danger'));}
  }
 }
 function signVerifyForm(){
  const signAddress=el('input',{autocomplete:'off',spellcheck:false}),signMessage=el('textarea',{rows:4,spellcheck:false}),signOut=el('div');
  const verifyAddress=el('input',{autocomplete:'off',spellcheck:false}),verifySignature=el('textarea',{rows:3,spellcheck:false}),verifyMessage=el('textarea',{rows:4,spellcheck:false}),verifyOut=el('div');
  const readAddress=button('Read address',async()=>{
   try{
    const facts={};
    try{const info=await read('getaddressinfo',[signAddress.value]);if(info&&typeof info==='object')Object.assign(facts,info);}catch{/* the wallet may not know this address */}
    if(typeof facts.isvalid!=='boolean'){
     const response=await app.bridge.read('validateaddress',[signAddress.value],null);
     const validated=response&&response.result;
     if(validated&&typeof validated==='object'){for(const key of ['isvalid','ismine','iswatchonly','isscript','iswitness','solvable']){if(typeof facts[key]!=='boolean'&&typeof validated[key]==='boolean')facts[key]=validated[key];}}
    }
    const shown=addressFacts(facts);
    signOut.replaceChildren(shown.lines.length||shown.warning?addressFactsNote(shown):note('The node returned no address facts.'));
   }catch(e){signOut.replaceChildren(note(e.message,'danger'));}
  });
  return el('div',{},
   el('section',{class:'panel'},el('h2',{},'Sign message'),note('Signing stays in the native wallet review.'),field('Address',signAddress),field('Message',signMessage),el('div',{class:'row'},button('Sign message',()=>operationDialog(app,'signmessage',[signAddress.value,signMessage.value]),'primary'),readAddress),signOut),
   el('section',{class:'panel'},el('h2',{},'Verify message'),note('Verification is a read. A false result is not success.'),field('Address',verifyAddress),field('Signature',verifySignature),field('Message',verifyMessage),button('Verify message',async()=>{
    try{
     const response=await app.bridge.read('verifymessage',[verifyAddress.value,verifySignature.value,verifyMessage.value],null);
     const value=response?response.result:undefined;
     if(value===true)verifyOut.replaceChildren(note('true'));
     else if(value===false)verifyOut.replaceChildren(note('false','danger'));
     else verifyOut.replaceChildren(note('Verification did not return a boolean.','danger'));
    }catch(e){verifyOut.replaceChildren(note(e.message,'danger'));}
   }),verifyOut));
 }
 function psbtForm(){
  const data=el('textarea',{rows:8,placeholder:'Base64 PSBT',spellcheck:false,class:'mono'});
  const deviceAddress=el('input',{autocomplete:'off',spellcheck:false,'aria-label':'Address to display on device'});
  const hardware=el('section',{class:'panel'},el('h2',{},'Hardware signer'),note('Atlas does not talk to the device directly. btxd and the external signer do. No device in this environment is not a pass.'),button('Enumerate signers',()=>operationDialog(app,'enumeratesigners')),field('Address',deviceAddress),button('Display address on device',()=>operationDialog(app,'walletdisplayaddress',[deviceAddress.value])));
  const psbtTooLong=text=>{if(psbtWithinLimit(text))return false;toast('PSBT is longer than 1000000 characters','danger');return true;};
  return el('div',{},note('Decode first. Signing and broadcast are separate. An unsigned or partially signed PSBT is not a settlement.'),data,el('div',{class:'row'},button('Paste clipboard',async()=>{try{const text=await navigator.clipboard.readText();if(psbtTooLong(text))return;data.value=text;}catch(e){toast(e.message,'danger');}}),button('Import PSBT document',async()=>{try{const text=(await app.bridge.document('psbt_import')).text;if(psbtTooLong(text))return;data.value=text;}catch(e){toast(e.message,'danger');}}),...['decodepsbt','analyzepsbt','walletprocesspsbt','finalizepsbt'].map(m=>button(m,()=>{if(psbtTooLong(data.value))return;operationDialog(app,m,[data.value]);}))),button('Raw transaction broadcast',()=>operationDialog(app,'sendrawtransaction'),'warning'),hardware);
 }
 function createWalletPanel(){
  const name=el('input',{autocomplete:'off',spellcheck:false,'aria-label':'New wallet name'}),disablePrivateKeys=el('input',{type:'checkbox','aria-label':'Disable private keys'}),blank=el('input',{type:'checkbox','aria-label':'Blank wallet'}),avoidReuse=el('input',{type:'checkbox',checked:true,'aria-label':'Avoid reuse'}),descriptors=el('input',{type:'checkbox',checked:true,'aria-label':'Descriptors'}),loadOnStartup=el('input',{type:'checkbox',checked:true,'aria-label':'Load on startup'}),externalSigner=el('input',{type:'checkbox','aria-label':'External signer'}),passphrase=el('input',{type:'password',autocomplete:'off',spellcheck:false,'aria-label':'Wallet passphrase'}),error=el('div');
  const create=button('Create wallet',()=>{
   error.replaceChildren();
   try{
    const draft=createWalletDraft({name:name.value,disablePrivateKeys:disablePrivateKeys.checked,blank:blank.checked,passphrase:passphrase.value,avoidReuse:avoidReuse.checked,descriptors:descriptors.checked,loadOnStartup:loadOnStartup.checked,externalSigner:externalSigner.checked});
    operationDialog(app,'createwallet',draft);
    passphrase.value='';
   }catch(e){error.replaceChildren(note(e.message,'danger'));}
  },'primary');
  return el('section',{class:'panel'},el('h2',{},'Create wallet'),note('The passphrase is sent only in the native createwallet review. It is not written to preferences or browser storage. An external signer requires disabled private keys and a descriptor wallet.'),el('div',{class:'fields'},field('Wallet name',name),field('Disable private keys',disablePrivateKeys),field('Blank',blank),field('Avoid reuse',avoidReuse),field('Descriptors',descriptors),field('Load on startup',loadOnStartup),field('External signer',externalSigner),field('Passphrase',passphrase)),create,error);
 }
 function manageSection(){
  return el('div',{},createWalletPanel(),el('section',{class:'panel'},el('h2',{},'Manage'),note('Migration, backup, and encryption are native wallet operations and are not a completed qualification.'),el('div',{class:'row'},
   button('Close wallet',()=>operationDialog(app,'unloadwallet',[wallet.value])),
   button('Back up wallet',()=>operationDialog(app,'backupwallet')),
   button('Encrypt wallet',()=>operationDialog(app,'encryptwallet')),
   button('Change passphrase',()=>operationDialog(app,'walletpassphrasechange')),
   button('Migrate wallet',()=>operationDialog(app,'migratewallet',[wallet.value])),
   button('Close every loaded wallet',async()=>{try{const names=await read('listwallets');const list=Array.isArray(names)?names:[];dialog('Close wallets',el('div',{class:'surface-stack'},note('Each wallet closes through its own native review.'),...list.map(name=>button(`Close ${name}`,()=>operationDialog(app,'unloadwallet',[name]))),list.length?null:note('No wallets are loaded.')));}catch(e){toast(e.message,'danger');}})
  )));
 }
 wallet.addEventListener('change',show);
 (async()=>{try{const r=await app.bridge.read('listwallets');wallet.append(el('option',{value:''},'Select a loaded wallet'),...r.result.map(w=>el('option',{value:w,selected:w===selected},w)));if(!selected&&r.result.length===1)wallet.value=r.result[0];await show();}catch(e){content.append(note(e.message,'danger'));}})();
 return root;
}
function addressFactsNote(facts){
 const parts=facts.lines.slice();
 if(facts.warning!=null)parts.push(facts.warning);
 const text=parts.join('\n');
 const shown=note(text,facts.warning==null?'':'warning');
 shown.style.whiteSpace='pre-wrap';
 return shown;
}
function sendForm(app,wallet){
 const root=el('section',{class:'panel'}),recipients=el('div'),rows=[],status=el('div'),recipientNotes=el('div');
 const add=(address='',amount='')=>{if(rows.length>=32)return;const addressInput=el('input',{value:address,placeholder:'BTX destination',autocomplete:'off',spellcheck:false}),amountInput=el('input',{value:amount,placeholder:'0.00000000',inputmode:'decimal',autocomplete:'off'});const row=el('div',{class:'recipient'},field('Recipient address',addressInput),field('Amount (BTX)',amountInput));row.append(button('Remove',()=>{const i=rows.findIndex(x=>x.row===row);if(i>=0)rows.splice(i,1);row.remove();}));recipients.append(row);rows.push({row,addressInput,amountInput});};add(app.pendingPayment?.address||'',app.pendingPayment?.amount||'');app.pendingPayment=null;
 const fee=el('input',{value:'0.001',inputmode:'decimal'}),rate=el('input',{value:'2',inputmode:'decimal'}),rbf=el('input',{type:'checkbox',checked:true}),changeAddress=el('input',{placeholder:'Empty lets the wallet choose',autocomplete:'off',spellcheck:false}),subtract=el('input',{type:'checkbox',checked:app.preferences.subtractFee===true}),estimateOut=el('div');let plan=null;
 const showPlan=p=>{plan=p;status.replaceChildren(note(`${p.state} · Chain confirmation is a separate native observation.`),jsonView(p,{open:true,title:'Immutable transaction review'}),el('div',{class:'row'},button('Export PSBT',async()=>{try{await app.bridge.money('export',{id:p.id});}catch(e){toast(e.message,'danger');}}),button('Sign in native wallet',async()=>{try{showPlan(await app.bridge.money('sign',{id:p.id}));}catch(e){status.append(note(e.message,'danger'));}},'warning',{disabled:p.state!=='UNSIGNED'}),button('Broadcast — separate approval',async()=>{try{showPlan(await app.bridge.money('broadcast',{id:p.id}));}catch(e){status.append(note(`${e.message} · Do not repeat an unknown broadcast.`,'danger'));}},'warning',{disabled:p.state!=='SIGNED_NOT_BROADCAST'})));};
 root.append(el('h2',{},'Exact transaction composer'),note('No transaction is signed or broadcast by this form. Native dialogs independently verify the immutable draft. An empty change address lets the wallet choose one. Subtract fee applies only to a single recipient, and the review checks the reduced output plus the fee.'),recipients,el('div',{class:'row'},button('Add recipient',()=>add()),button('Check recipients',async()=>{
  const addresses=rows.map(r=>r.addressInput.value.trim()).filter(address=>address!=='');
  if(!addresses.length){recipientNotes.replaceChildren(note('Enter a recipient address first.'));return;}
  const shown=[];
  try{
   for(const address of addresses){
    const response=await app.bridge.read('validateaddress',[address],null);
    shown.push(addressFactsNote(addressFacts(response?response.result:undefined)));
   }
   recipientNotes.replaceChildren(...shown);
  }catch(e){recipientNotes.replaceChildren(...shown,note(e.message,'danger'));}
 })),recipientNotes,el('div',{class:'fields'},field('Maximum total fee (BTX)',fee),field('Fee rate (atoms/vB)',rate),field('Opt in to replaceability',rbf),field('Change address (optional)',changeAddress),field('Subtract fee from the single recipient',subtract)),el('div',{class:'row'},button('Read node fee estimate',async()=>{try{const reply=await app.bridge.read('estimatesmartfee',[6]);const result=reply.result||{};const decimal=feeDecimal(result.feerate);if(!decimal){estimateOut.replaceChildren(note(Array.isArray(result.errors)&&result.errors.length?result.errors.join(' '):'The node returned no fee estimate in BTX per kvB.'));return;}const atomsPerVb=atomsPerVbyteFromKvb(decimal);estimateOut.replaceChildren(note(`Estimate for 6 blocks: ${decimal} BTX/kvB. The composer uses ${atomsPerVb} atoms/vB, rounded up to the next byte.`),button('Use this rate',()=>{rate.value=atomsPerVb;}));}catch(e){estimateOut.replaceChildren(note(e.message,'danger'));}})),estimateOut,note(`${app.selectedCoins?.length||0} explicitly selected inputs. Empty means native wallet coin selection.`));
 const prepare=button('Prepare unsigned transaction',async()=>{prepare.disabled=true;try{const draft={wallet,recipients:rows.map(r=>({address:r.addressInput.value.trim(),amount:r.amountInput.value.trim()})),inputs:app.selectedCoins||[],maximum_fee:fee.value,fee_rate:rate.value,replaceable:rbf.checked,change_address:changeAddress.value.trim(),subtract_fee:subtract.checked};for(const r of draft.recipients)parseBTX(r.amount);parseBTX(draft.maximum_fee);showPlan(await app.bridge.money('prepare',{draft}));}catch(e){status.replaceChildren(note(e.message,'danger'));}finally{prepare.disabled=false;}},'primary');root.append(prepare,status);return root;
}
function drawQR(qr){const width=Number(qr.width),cells=qr.cells;if(!Number.isInteger(width)||width<1||width>177||!Array.isArray(cells)||cells.length!==width*width)return note('QR unavailable');const canvas=el('canvas',{'aria-label':'Payment URI QR code',role:'img',class:'qr'}),size=5,quiet=4;canvas.width=canvas.height=(width+quiet*2)*size;const c=canvas.getContext('2d');c.fillStyle='#fff';c.fillRect(0,0,canvas.width,canvas.height);c.fillStyle='#000';cells.forEach((dark,i)=>{if(dark)c.fillRect((i%width+quiet)*size,(Math.floor(i/width)+quiet)*size,size,size);});return canvas;}
