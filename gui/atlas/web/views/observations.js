import {el,button,heading,note,badge,metric,table,jsonView,dialog,toast,humanBytes} from '../components/ui.js';
import {sourceRows} from '../core/graph.js';
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
 async function load(){area.replaceChildren();for(const m of methods){const box=el('section',{class:'panel'},el('div',{class:'row'},el('h2',{},m),badge('Native source')));area.append(box);try{const e=await app.bridge.read(m);box.append(jsonView(e.result,{open:true,title:`Observed ${new Date(e.observed_at).toLocaleTimeString()} · partial local view`}));if(m==='listmodels')box.append(table(sourceRows(e),['name','model_id','bytes_verified','incomplete']));}catch(e){box.append(note(e.message,'danger'));}}}
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
 root.append(el('section',{class:'panel'},el('h2',{},'Tor pairing'),note('Experimental BTX peer pairing. The onion address is a local network observation, not a model or wallet credential.'),button('Inspect local onion endpoints',async()=>{try{const r=await app.bridge.read('getnetworkinfo');const addresses=(r.result.localaddresses||[]).filter(x=>String(x.address||'').endsWith('.onion'));const body=el('div',{class:'surface-stack'});if(!addresses.length)body.append(note('No onion endpoint observed. Enable/configure Tor through the native node.'));for(const a of addresses){const uri=`btx-p2p://${a.address}${a.port?':'+a.port:''}`;body.append(el('code',{class:'address'},uri),button('Copy pairing URI',()=>app.bridge.copy(uri).catch(e=>toast(e.message,'danger'))));}dialog('Observed Tor pairing',body);}catch(e){toast(e.message,'danger');}})));
 root.append(operationWorkbench(app,{groups:['Node'],title:'Node diagnostics and control'}));return root;
}
