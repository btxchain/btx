import {el,button,heading,note,badge,metric,table,jsonView,dialog,toast,humanBytes,field} from '../components/ui.js';
import {sourceRows} from '../core/graph.js';
import {syncBanner} from '../core/qt-gaps.js';
import {operationDialog,operationWorkbench} from './operations.js';
import {operationButtons} from './models.js';
export function observationView(app,view){
 const definitions={
  swarms:['Swarms & communities','Following a model family is not a grant to train, seed, spend or route private prompts.',['getmodelnetworkinfo','getmodelpeers','listmodels'],'Models'],
  economy:['Economy & funding','Targets, pledges, confirmed backing, reservations, enforceable claims and settled transactions remain separate.',['getmodelfeed','getfundablemodels','getrecentreleases','searchbounties'],'Economy'],
  compute:['Local compute','Capabilities are reported by the native helper; missing engines and unqualified hardware stay explicit.',['getmodelhostprofile','getsetupstatus','getmodelnetworkinfo','getmemoryinfo'],'Compute'],
  mining:['Mining & monetary node','Native MatMul/ExactReplay status. No synthetic throughput or invented earnings.',['getmininginfo','getblockchaininfo','getmempoolinfo','getnettotals'],'Node']
 };const [title,subtitle,methods,group]=definitions[view],root=el('div',{class:'page'},heading(title,subtitle)),area=el('div',{class:'surface-stack'});
 if(view==='economy')root.append(note('A local budget or unsigned plan is not a spendable L2 balance. The GUI does not upgrade an unqualified native payment backend.','warning'));
 if(view==='swarms')root.append(note('Peers, model communities, work relationships and payment relationships are different graphs. This screen exposes this node’s partial observations.'));
 root.append(button('Refresh these observations',load),area,operationWorkbench(app,{groups:view==='compute'?['Compute','Capabilities']:[group],title:'Native operations'}));
 async function load(){area.replaceChildren();let chain=app.state.state.sources.getblockchaininfo?.result;for(const m of methods){const box=el('section',{class:'panel'},el('div',{class:'row'},el('h2',{},m),badge('Native source')));area.append(box);try{const envelope=await app.bridge.read(m);if(m==='getblockchaininfo')chain=envelope.result;box.append(jsonView(envelope.result,{open:true,title:`Observed ${new Date(envelope.observed_at).toLocaleTimeString()} · partial local view`}));if(m==='listmodels')box.append(table(sourceRows(envelope),['name','model_id','bytes_verified','incomplete']));}catch(err){box.append(note(err.message,'danger'));}}if(view==='mining'){const sync=syncBanner(chain)||{};if(sync.visible===true)area.append(el('p',{class:'sync-line'},el('strong',{},sync.title==null?'':String(sync.title)),sync.detail==null?'':String(sync.detail)));}}
 load();return root;
}
export function activityView(app){
 const root=el('div',{class:'page'},heading('Activity & evidence','GUI intentions and native outcomes are different records. No result is silently promoted to execution proof.')),native=el('div'),local=el('div');root.append(button('Refresh audit observations',refresh),native,el('section',{class:'panel'},el('h2',{},'Current-session observations'),local));
 async function refresh(){local.replaceChildren(table(app.events.values().reverse(),['time','kind','message']));try{const j=await app.bridge.activity();native.replaceChildren(note(j.scope),j.unresolved?.length?note(`${j.unresolved.length} unresolved operations. Reconcile their native outcome before any retry.`,'warning'):note('No unresolved operations in the bounded local GUI journal.'),table(j.entries||[],['sequence','time_ms','operation_id','method','phase']),jsonView({checkpoint:j.checkpoint,note:'Local hash chain, not tamper-proof against the same OS user and not a native research ledger.'}),button('Export redacted GUI audit',()=>app.bridge.export(JSON.stringify(j,null,2),'atlas-audit.json').catch(e=>toast(e.message,'danger'))));}catch(e){native.replaceChildren(note(e.message,'danger'));}}
 refresh();return root;
}
export function toolsView(app){
 const root=el('div',{class:'page'},heading('Node tools','Peer management, mempool inspection, pairing, configuration and a native-reviewed RPC workbench.'));
 const method=el('input',{placeholder:'Exact discovered RPC method',spellcheck:false}),available=app.bridge.available?[...app.bridge.available]:[];root.append(el('section',{class:'panel'},el('h2',{},'RPC console'),note('Read-only methods use an explicit allowlist. Every other method requires complete native review; a method’s name or an agent suggestion grants no authority.'),el('div',{class:'row'},method,button('Open command',()=>{if(!/^[a-zA-Z0-9_]{1,96}$/.test(method.value)){toast('Invalid method name','danger');return;}operationDialog(app,method.value);}),button('Refresh method inventory',async()=>{try{await app.bridge.discover();toast('Native RPC inventory refreshed');}catch(e){toast(e.message,'danger');}}))));
 root.append(mempoolPanel(app),peersPanel(app),torPanel(app),helpPanel(app));
 root.append(operationWorkbench(app,{groups:['Node'],title:'Node diagnostics and control'}));return root;
}
function mempoolPanel(app){
 const body=el('div',{class:'surface-stack'}),refresh=button('Refresh',()=>load());
 const panel=el('section',{class:'panel'},el('div',{class:'row'},el('h2',{},'Mempool'),refresh),note('This is the current mempool, not a historical chart.'),body);
 async function load(){refresh.disabled=true;try{
  const [infoR,rawR]=await Promise.allSettled([app.bridge.read('getmempoolinfo'),app.bridge.read('getrawmempool',[false])]);
  if(!body.isConnected)return;body.replaceChildren();
  if(infoR.status==='fulfilled'){const info=infoR.value.result||{};body.append(el('div',{class:'metrics'},metric('Size',info.size??'—','transactions'),metric('Bytes',humanBytes(info.bytes),'serialized'),metric('Usage',humanBytes(info.usage),'memory')));}
  else body.append(note(infoR.reason?.message||'Mempool info unavailable','danger'));
  if(rawR.status==='fulfilled'){const listed=txidsFrom(rawR.value.result);if(!listed)body.append(note('No transaction id list was returned for the current mempool.'));else{body.append(table(listed.ids.map(txid=>({txid})),['txid'],{empty:'No transactions in the current mempool.'}));if(listed.total>listed.ids.length)body.append(note(`Showing ${listed.ids.length} of ${listed.total} transaction ids in the current mempool.`));}}
  else body.append(note(rawR.reason?.message||'Mempool transaction list unavailable','danger'));
 }finally{if(refresh.isConnected)refresh.disabled=false;}}
 load();return panel;
}
function txidsFrom(raw){if(!Array.isArray(raw))return null;const ids=[];for(const entry of raw){const txid=typeof entry==='string'?entry:entry&&typeof entry.txid==='string'?entry.txid:'';if(txid)ids.push(txid);if(ids.length===100)break;}return{ids,total:raw.length};}
function peersPanel(app){
 const body=el('div',{class:'surface-stack'}),refresh=button('Refresh',()=>load());
 const panel=el('section',{class:'panel'},el('div',{class:'row'},el('h2',{},'Peers'),refresh),note('Ban opens native review for setban. This view does not ban a peer by itself.'),body);
 async function load(){refresh.disabled=true;try{
  const envelope=await app.bridge.read('getpeerinfo');if(!body.isConnected)return;
  const peers=Array.isArray(envelope.result)?envelope.result.filter(p=>p&&typeof p==='object'):[];
  const extra=peers.some(p=>Object.prototype.hasOwnProperty.call(p,'banscore'))?'banscore':'bytessent';
  const rows=peers.map(p=>({address:String(p.addr??p.address??''),subver:p.subver??'',synced_headers:p.synced_headers??'',[extra]:p[extra]??'',peer:p}));
  const grid=table(rows,[{key:'address',label:'address',render:address=>el('span',{class:'row'},el('span',{class:'address'},address||'—'),button('Ban',event=>{event.stopPropagation();operationDialog(app,'setban',[address,'add']);},'',{onKeydown:event=>{if(event.key==='Enter'||event.key===' ')event.stopPropagation();}}))},'subver','synced_headers',extra],{onSelect:row=>dialog('Observed peer',jsonView(row.peer,{open:true})),empty:'No peers observed.'});
  const peerTable=grid.querySelector('table');if(peerTable){peerTable.dataset.stripe='peer';peerTable.classList.toggle('peer-stripes',app.preferences.peerStripes===true);}
  body.replaceChildren(grid);
 }catch(err){if(body.isConnected)body.replaceChildren(note(err.message,'danger'));}finally{if(refresh.isConnected)refresh.disabled=false;}}
 load();return panel;
}
function torPanel(app){
 return el('section',{class:'panel'},el('h2',{},'Tor pairing'),note('Experimental BTX peer pairing. The onion address is a local network observation, not a model or wallet credential.'),button('Inspect local onion endpoints',async()=>{try{
  const r=await app.bridge.read('getnetworkinfo');const addresses=(r.result.localaddresses||[]).filter(x=>String(x.address||'').endsWith('.onion'));const body=el('div',{class:'surface-stack'});
  if(!addresses.length)body.append(note('No onion endpoint observed. Enable/configure Tor through the native node.'));
  for(const a of addresses){const uri=`btx-p2p://${a.address}${a.port?':'+a.port:''}`;const block=el('div',{class:'surface-stack'},el('code',{class:'address'},uri),button('Copy pairing URI',()=>app.bridge.copy(uri).catch(e=>toast(e.message,'danger'))));try{block.append(drawQR(await app.bridge.invoke('atlas_qr',{text:uri})));}catch(err){block.append(note(err&&err.message?err.message:String(err),'danger'));}body.append(block);}
  dialog('Observed Tor pairing',body);
 }catch(e){toast(e.message,'danger');}}));
}
function helpPanel(app){
 const name=el('input',{placeholder:'Optional command name',spellcheck:false,autocomplete:'off','aria-label':'Optional command name'}),out=el('div'),run=button('Show help',async()=>{const command=name.value.trim();run.disabled=true;try{const envelope=await app.bridge.read('help',command?[command]:[]);out.replaceChildren(jsonView(envelope.result,{open:true,title:'Native help'}));}catch(err){out.replaceChildren(note(err.message,'danger'));}finally{if(run.isConnected)run.disabled=false;}});
 return el('section',{class:'panel'},el('h2',{},'Help'),note('Reads native help text only. It does not execute the named command.'),field('Command name',name,'Optional. Leave blank to read the help index.'),el('div',{class:'row'},run),out);
}
function drawQR(qr){const width=Number(qr&&qr.width),cells=qr&&qr.cells;if(!Number.isInteger(width)||width<1||width>177||!Array.isArray(cells)||cells.length!==width*width)return note('QR unavailable');const canvas=el('canvas',{'aria-label':'Pairing URI QR code',role:'img',class:'qr'}),size=5,quiet=4;canvas.width=canvas.height=(width+quiet*2)*size;const c=canvas.getContext('2d');c.fillStyle='#fff';c.fillRect(0,0,canvas.width,canvas.height);c.fillStyle='#000';cells.forEach((dark,i)=>{if(dark)c.fillRect((i%width+quiet)*size,(Math.floor(i/width)+quiet)*size,size,size);});return canvas;}
