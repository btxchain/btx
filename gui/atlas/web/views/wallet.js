import {el,button,field,note,metric,jsonView,table,dialog,toast,heading,humanBytes} from '../components/ui.js';
import {operationDialog,operationWorkbench} from './operations.js';
import {parseBTX,formatBTX,formatUnit} from '../core/money.js';
import {formatObservedTime} from '../core/json.js';
import {sourceRows} from '../core/graph.js';
import {historyFilter,paymentRequest} from '../core/qt-gaps.js';
export function walletView(app){
 const root=el('div',{class:'page wallet-page'},heading('Wallet','Self-custody remains in btxd. Signing and broadcasting have independent native reviews.'));
 const wallet=el('select',{'aria-label':'Select wallet'}),summary=el('div',{class:'metrics'}),content=el('div'),selected=app.state.state.wallet||'';
 root.append(el('div',{class:'row'},field('Loaded wallet',wallet),button('Create',()=>operationDialog(app,'createwallet')),button('Open',()=>operationDialog(app,'loadwallet')),button('Restore',()=>operationDialog(app,'restorewallet'))),summary);
 const tabs=['Overview','Send','Receive','History','Coins','Address book','Addresses','Sign / Verify','PSBT','Manage'];let current='Overview';
 const tabBar=el('nav',{class:'tabs','aria-label':'Wallet sections'});for(const name of tabs)tabBar.append(button(name,()=>{current=name;show();},'',{dataset:{walletTab:name}}));root.append(tabBar,content);
 async function read(method,params=[]){return(await app.bridge.read(method,params,wallet.value||null)).result;}
 function denomination(v){if(v===undefined||v===null)return '—';try{return formatUnit(parseBTX(String(v),{signed:true}),app.preferences.unit);}catch{return 'Invalid native amount';}}
 function mask(v){return app.state.state.privacy?'••••':String(v??'—');}
 function addressShown(v){if(app.preferences.displayAddresses===false||app.state.state.privacy)return '••••';return String(v??'—');}
 function copyButton(label,text){return button(label,()=>app.bridge.copy(text).catch(e=>toast(e.message,'danger')));}
 async function show(){
  [...tabBar.children].forEach(b=>b.classList.toggle('active',b.dataset.walletTab===current));content.replaceChildren();
  if(!wallet.value){content.append(note('No loaded wallet selected. Models, node observation, and Atlas do not require a wallet.'));return;}
  app.state.update({wallet:wallet.value});const target=wallet.value;
  try{
   if(current==='Overview'){const [info,balances]=await Promise.all([read('getwalletinfo'),read('getbalances')]);if(wallet.value!==target)return;summary.replaceChildren(metric('Available',mask(denomination(balances.mine?.trusted)),'Native wallet observation'),metric('Pending',mask(denomination(balances.mine?.untrusted_pending)),'Not confirmed'),metric('Immature',mask(denomination(balances.mine?.immature)),'Not yet spendable'));
    content.append(el('div',{class:'panel'},el('h2',{},target),note(info.private_keys_enabled===false?'Watch-only / external signing wallet':'Native wallet keys are not exported to Atlas.'),jsonView(info),jsonView(balances)),operationWorkbench(app,{groups:['Wallet','Recovery'],title:'Wallet and recovery functions'}));
   }else if(current==='Send')content.append(sendForm(app,wallet.value));
   else if(current==='Receive')content.append(receiveForm());
   else if(current==='History')await historyTab();
   else if(current==='Coins')await coinsTab();
   else if(current==='Address book')await addressBookTab();
   else if(current==='Addresses'){
    const labels=await read('listlabels');content.append(table(labels.map(label=>({label})),['label'],{onSelect:r=>operationDialog(app,'getaddressesbylabel',[r.label])}),button('Set address label',()=>operationDialog(app,'setlabel')));
   }else if(current==='Sign / Verify')content.append(signVerifyForm());
   else if(current==='PSBT')content.append(psbtForm());
   else content.append(manageSection(),operationWorkbench(app,{groups:['Wallet','Economy'],title:'Wallet administration and financial operations'}));
  }catch(e){content.append(note(e.message,'danger'));}
 }
 function receiveForm(){
  const amount=el('input',{placeholder:'Optional',inputmode:'decimal',autocomplete:'off',spellcheck:false}),label=el('input',{placeholder:'Optional receiving label',autocomplete:'off'}),message=el('input',{placeholder:'Optional message',autocomplete:'off'}),out=el('div');
  const create=button('Create receiving address — native review',async()=>{
   create.disabled=true;
   try{
    const prepared=await app.bridge.prepare('getnewaddress',[label.value],wallet.value);
    const response=await app.bridge.execute(prepared.id);
    const address=String(response.result);
    const request={address,amount:amount.value.trim(),label:label.value,message:message.value};
    let uri;try{uri=paymentRequest(request);}catch(e){out.replaceChildren(el('code',{class:'address'},address),note(e.message,'danger'));return;}
    out.replaceChildren(el('code',{class:'address'},address),el('code',{class:'address'},uri),el('p',{},`Amount: ${request.amount}`),el('p',{},`Label: ${request.label}`),el('p',{},`Message: ${request.message}`),el('div',{class:'row'},copyButton('Copy URI',uri),copyButton('Copy amount',request.amount),copyButton('Copy label',request.label),copyButton('Copy message',request.message)));
    try{const qr=await app.bridge.invoke('atlas_qr',{text:uri});out.append(drawQR(qr));}catch(e){out.append(note(e.message,'danger'));}
   }catch(e){out.replaceChildren(note(e.message,'danger'));}
   finally{create.disabled=false;}
  },'primary');
  return el('section',{class:'panel'},el('h2',{},'Request payment'),field('Amount (optional)',amount),field('Label (optional)',label),field('Message (optional)',message),create,out);
 }
 async function historyTab(){
  let offset=0,raw=[];const area=el('div');
  const category=el('select',{'aria-label':'Transaction category'},...[['','all'],['send','send'],['receive','receive'],['generate','generate'],['immature','immature'],['orphan','orphan']].map(([value,label])=>el('option',{value},label)));
  const query=el('input',{type:'search',placeholder:'Filter transactions','aria-label':'Filter transactions',autocomplete:'off'});
  const rowActions=(_v,row)=>el('div',{class:'row'},button('Bump fee',ev=>{ev.stopPropagation();operationDialog(app,'bumpfee',[row.txid]);}),button('Abandon transaction',ev=>{ev.stopPropagation();operationDialog(app,'abandontransaction',[row.txid]);}));
  const columns=[{key:'time',label:'Time',render:v=>formatObservedTime(v)},'category',{key:'amount',label:'Amount',render:v=>mask(denomination(v))},'confirmations',{key:'address',label:'Address',render:v=>addressShown(v)},'label','txid',{key:'actions',label:'Actions',render:rowActions}];
  const paint=()=>{
   const rows=historyFilter(raw,{category:category.value,query:query.value});
   area.replaceChildren(table(rows,columns,{search:false,onSelect:r=>operationDialog(app,'gettransaction',[r.txid])}),note(`Native page starts at transaction ${offset}; this is not a consistent multi-page snapshot.`));
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
  const chosen=new Set();const total=el('strong',{},'0 selected');
  const update=()=>{app.selectedCoins=coins.filter((_,i)=>chosen.has(i)).map(c=>({txid:c.txid,vout:Number(c.vout)}));let amount=0n;for(const c of coins.filter((_,i)=>chosen.has(i)))amount+=parseBTX(String(c.amount));total.textContent=`${chosen.size} selected · ${mask(formatUnit(amount,app.preferences.unit))}`;};
  const hideAddress=app.preferences.displayAddresses===false||!!app.state.state.privacy;
  const columns=[{key:'index',label:'Use',render:(v)=>el('input',{type:'checkbox','aria-label':`Select coin ${v}`,onChange:e=>{e.target.checked?chosen.add(v):chosen.delete(v);update();}})},{key:'amount',label:'Amount',render:v=>mask(denomination(v))},'confirmations',{key:'address',label:'Address',render:v=>addressShown(v)},'spendable','solvable','txid','vout'];
  const indexed=coins.map((c,i)=>({...c,index:i}));
  const groups=new Map();
  for(const coin of indexed){const key=String(coin.address??'');if(!groups.has(key))groups.set(key,[]);groups.get(key).push(coin);}
  content.append(note('Coin selection is a local draft. Locking coins or signing still requires native review.'),total);
  if(!indexed.length)content.append(table([],columns,{empty:'No observed records.'}));
  for(const [address,rows] of groups){
   const shown=hideAddress?rows.map(c=>({...c,address:'••••'})):rows;
   content.append(el('h3',{},address?addressShown(address):'—'),table(shown,columns));
  }
  content.append(el('div',{class:'row'},button('Use selected inputs',()=>{current='Send';show();}),button('Lock selected',()=>operationDialog(app,'lockunspent',[false,app.selectedCoins||[]])),button('Review locked coins',()=>operationDialog(app,'listlockunspent'))));
 }
 async function addressBookTab(){
  const errors=el('div'),detail=el('div'),receivingHost=el('div'),sendingHost=el('div');
  content.append(el('h2',{},'Receiving'),note('These are receiving addresses from the wallet. Private keys are not exported.'),receivingHost,el('h2',{},'Sending'),note('Sending addresses come from the address book.'),sendingHost,el('div',{class:'row'},button('Set address label',()=>operationDialog(app,'setlabel'))),detail,errors);
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
  const signAddress=el('input',{autocomplete:'off',spellcheck:false}),signMessage=el('textarea',{rows:4,spellcheck:false});
  const verifyAddress=el('input',{autocomplete:'off',spellcheck:false}),verifySignature=el('textarea',{rows:3,spellcheck:false}),verifyMessage=el('textarea',{rows:4,spellcheck:false}),verifyOut=el('div');
  return el('div',{},
   el('section',{class:'panel'},el('h2',{},'Sign message'),note('Signing stays in the native wallet review.'),field('Address',signAddress),field('Message',signMessage),button('Sign message',()=>operationDialog(app,'signmessage',[signAddress.value,signMessage.value]),'primary')),
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
  return el('div',{},note('Decode first. Signing and broadcast are separate. An unsigned or partially signed PSBT is not a settlement.'),data,el('div',{class:'row'},button('Paste clipboard',async()=>{try{data.value=await navigator.clipboard.readText();}catch(e){toast(e.message,'danger');}}),button('Import PSBT document',async()=>{try{data.value=(await app.bridge.document('psbt_import')).text;}catch(e){toast(e.message,'danger');}}),...['decodepsbt','analyzepsbt','walletprocesspsbt','finalizepsbt'].map(m=>button(m,()=>operationDialog(app,m,[data.value])))),button('Raw transaction broadcast',()=>operationDialog(app,'sendrawtransaction'),'warning'),hardware);
 }
 function manageSection(){
  return el('section',{class:'panel'},el('h2',{},'Manage'),note('Migration, backup, and encryption are native wallet operations and are not a completed qualification.'),el('div',{class:'row'},
   button('Close wallet',()=>operationDialog(app,'unloadwallet',[wallet.value])),
   button('Back up wallet',()=>operationDialog(app,'backupwallet')),
   button('Encrypt wallet',()=>operationDialog(app,'encryptwallet')),
   button('Change passphrase',()=>operationDialog(app,'walletpassphrasechange')),
   button('Migrate wallet',()=>operationDialog(app,'migratewallet',[wallet.value]))
  ));
 }
 wallet.addEventListener('change',show);
 (async()=>{try{const r=await app.bridge.read('listwallets');wallet.append(el('option',{value:''},'Select a loaded wallet'),...r.result.map(w=>el('option',{value:w,selected:w===selected},w)));if(!selected&&r.result.length===1)wallet.value=r.result[0];await show();}catch(e){content.append(note(e.message,'danger'));}})();
 return root;
}
function sendForm(app,wallet){
 const root=el('section',{class:'panel'}),recipients=el('div'),rows=[],status=el('div');
 const add=(address='',amount='')=>{if(rows.length>=32)return;const addressInput=el('input',{value:address,placeholder:'BTX destination',autocomplete:'off',spellcheck:false}),amountInput=el('input',{value:amount,placeholder:'0.00000000',inputmode:'decimal',autocomplete:'off'});const row=el('div',{class:'recipient'},field('Recipient address',addressInput),field('Amount (BTX)',amountInput));row.append(button('Remove',()=>{const i=rows.findIndex(x=>x.row===row);if(i>=0)rows.splice(i,1);row.remove();}));recipients.append(row);rows.push({row,addressInput,amountInput});};add(app.pendingPayment?.address||'',app.pendingPayment?.amount||'');app.pendingPayment=null;
 const fee=el('input',{value:'0.001',inputmode:'decimal'}),rate=el('input',{value:'2',inputmode:'decimal'}),rbf=el('input',{type:'checkbox',checked:true});let plan=null;
 const showPlan=p=>{plan=p;status.replaceChildren(note(`${p.state} · Chain confirmation is a separate native observation.`),jsonView(p,{open:true,title:'Immutable transaction review'}),el('div',{class:'row'},button('Export PSBT',async()=>{try{await app.bridge.money('export',{id:p.id});}catch(e){toast(e.message,'danger');}}),button('Sign in native wallet',async()=>{try{showPlan(await app.bridge.money('sign',{id:p.id}));}catch(e){status.append(note(e.message,'danger'));}},'warning',{disabled:p.state!=='UNSIGNED'}),button('Broadcast — separate approval',async()=>{try{showPlan(await app.bridge.money('broadcast',{id:p.id}));}catch(e){status.append(note(`${e.message} · Do not repeat an unknown broadcast.`,'danger'));}},'warning',{disabled:p.state!=='SIGNED_NOT_BROADCAST'})));};
 root.append(el('h2',{},'Exact transaction composer'),note('No transaction is signed or broadcast by this form. Native dialogs independently verify the immutable draft. The wallet chooses change; Atlas checks ownership and exact recipient scripts.'),recipients,button('Add recipient',()=>add()),el('div',{class:'fields'},field('Maximum total fee (BTX)',fee),field('Fee rate (atoms/vB)',rate),field('Opt in to replaceability',rbf)),note(`${app.selectedCoins?.length||0} explicitly selected inputs. Empty means native wallet coin selection.`));
 const prepare=button('Prepare unsigned transaction',async()=>{prepare.disabled=true;try{const draft={wallet,recipients:rows.map(r=>({address:r.addressInput.value.trim(),amount:r.amountInput.value.trim()})),inputs:app.selectedCoins||[],maximum_fee:fee.value,fee_rate:rate.value,replaceable:rbf.checked};for(const r of draft.recipients)parseBTX(r.amount);parseBTX(draft.maximum_fee);showPlan(await app.bridge.money('prepare',{draft}));}catch(e){status.replaceChildren(note(e.message,'danger'));}finally{prepare.disabled=false;}},'primary');root.append(prepare,status);return root;
}
function drawQR(qr){const width=Number(qr.width),cells=qr.cells;if(!Number.isInteger(width)||width<1||width>177||!Array.isArray(cells)||cells.length!==width*width)return note('QR unavailable');const canvas=el('canvas',{'aria-label':'Payment URI QR code',role:'img',class:'qr'}),size=5,quiet=4;canvas.width=canvas.height=(width+quiet*2)*size;const c=canvas.getContext('2d');c.fillStyle='#fff';c.fillRect(0,0,canvas.width,canvas.height);c.fillStyle='#000';cells.forEach((dark,i)=>{if(dark)c.fillRect((i%width+quiet)*size,(Math.floor(i/width)+quiet)*size,size,size);});return canvas;}
