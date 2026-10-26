import {el,button,field,heading,note,badge,table,dialog,jsonView,humanBytes,toast,metric} from '../components/ui.js';
import {sourceRows} from '../core/graph.js';
import {presentObservation} from '../core/observe.js';
import {operationDialog,operationWorkbench} from './operations.js';
import {modelPanels} from './model-panels.js';
import {modelNodeStatus,modelRecordRows} from '../core/model-status.js';
export function modelsView(app){
 const root=el('div',{class:'page'},heading('Models','Acquire, preserve, inspect and run verified local models. Downloads are not execution grants.'));
 const query=el('input',{type:'search',placeholder:'Search locally known models…','aria-label':'Model search'}),scope=el('select',{},el('option',{value:'LOCAL'},'Local catalogue'),el('option',{value:'NETWORK'},'Network search — explicit disclosure')),results=el('div'),tabs=el('nav',{class:'tabs'});let selected='Catalogue';
 const names=['Catalogue','Downloads','Shared','Collections','Preservation','Peers','Identity','Capabilities'];
 const renderRows=data=>{const rows=sourceRows(data);results.replaceChildren(note('Search coverage is partial. Availability advertisements do not prove byte verification or runtime permission.'),table(rows,[{key:'name',label:'Model'},{key:'format',label:'Format'},{key:'size_bytes',label:'Size',render:v=>humanBytes(v)},{key:'bytes_verified',label:'Verified bytes'},{key:'incomplete',label:'Incomplete'},'model_id'],{onSelect:m=>modelDetails(app,m)}));};
 const search=button('Search',async()=>{search.disabled=true;try{const p=[{text:query.value,scope:scope.value,limit:100}];if(scope.value==='NETWORK'){const prepared=await app.bridge.prepare('searchmodels',p);renderRows((await app.bridge.execute(prepared.id)).result);}else renderRows((await app.bridge.read('searchmodels',p)).result);}catch(e){results.replaceChildren(note(e.message,'danger'));}finally{search.disabled=false;}},'primary');
 const bar=el('div',{class:'row'},query,scope,search,button('Import / host',()=>operationDialog(app,'hostmodel')),button('Open model link',()=>app.openResource()));
 async function show(){[...tabs.children].forEach(b=>b.classList.toggle('active',b.dataset.tab===selected));bar.hidden=selected!=='Catalogue';results.replaceChildren();try{
  switch(selected){
   case 'Catalogue':renderRows(app.state.state.sources.listmodels||await app.bridge.read('listmodels'));break;
   case 'Downloads':{const r=await app.bridge.read('getmodeltransfers');results.append(table(sourceRows(r),['name','state','percent','bytes_per_sec','eta_s','job_id'],{onSelect:r=>dialog('Transfer',el('div',{},jsonView(r,{open:true}),button('Inspect native job',()=>operationDialog(app,'getmodeljob',[r.job_id])),button('Cancel job — native review',()=>operationDialog(app,'cancelmodeljob',[r.job_id]))))}),note('Cancelling a UI wait is not cancellation of a native transfer. Use the explicit job operation.'));break;}
   case 'Shared':{const rows=sourceRows(app.state.state.sources.listmodels).filter(m=>m.seeded===true||m.pinned===true||m.state==='SEEDING');results.append(table(rows,['name','model_id','state','ratio','served_bytes'],{onSelect:m=>modelDetails(app,m)}),operationButtons(app,['hostmodel','seedmodel','unseedmodel','unhostmodel','getmodelsharecard','exportmodellink']));break;}
   case 'Collections':{const workbench=operationWorkbench(app,{groups:['Models'],title:'Collections and directory operations'});results.append(operationButtons(app,['subscribemodelcollection','subscribemodelpolicy','joinmodelcircle','leavemodelcircle']),el('details',{},el('summary',{},'Collection operations'),workbench));break;}
   case 'Preservation':{const result=(await app.bridge.read('getmodelpolicy')).result,shown=presentObservation('getmodelpolicy',result),parts=[];if(shown.metrics.length)parts.push(el('div',{class:'metrics'},...shown.metrics.map(item=>metric(item.label,item.value))));if(shown.columns.length)parts.push(table(shown.rows,shown.columns));results.append(...parts,jsonView(result,{open:false,title:'Native record'}),operationButtons(app,['setmodelpolicy','seedmodel','unseedmodel','removemodel']),note('Automatic spend remains zero. A larger storage or propagation grant is an independent native policy change.'));break;}
   case 'Peers':{const r=await app.bridge.read('getmodelpeers');results.append(...recordObservation(modelRecordRows(r&&r.result),['address','endpoint','id','peer','direction','state','version','name'],r,'Native model peer observations'),operationButtons(app,['addmodelnode','importmodelcontacts','exportmodelcontacts','importmodeltrust']));break;}
   case 'Identity':{const r=await app.bridge.read('listmodelidentities');results.append(...recordObservation(modelRecordRows(r&&r.result),['id','name','purpose','state','fingerprint'],r,'Model identities — not wallet keys'),operationButtons(app,['createmodelidentity','listmodelrules','setmodelrule','removemodelrule','delegatemodelservice','revokemodelservice']));break;}
   case 'Capabilities':results.append(modelPanels(app),el('details',{},el('summary',{},'Open generic template'),operationWorkbench(app,{groups:['Capabilities','Compute'],title:'Capabilities and Compute templates'})),note('Installed, available, admitted, executing, and qualified are distinct states. Missing methods remain unavailable.'));break;
  }
 }catch(e){results.append(note(e.message,'danger'));}}
 for(const name of names)tabs.append(button(name,()=>{selected=name;show();},'',{dataset:{tab:name}}));
 const nodeFacts=el('div');
 let hostProfile=null,nodeAlive=true;
 function paintNode(){
  const sources=app.state.state.sources||{};
  const setup=sources.getsetupstatus?sources.getsetupstatus.result??null:null;
  const status=modelNodeStatus(setup,hostProfile);
  nodeFacts.replaceChildren(...status.lines.map(text=>el('p',{},text)),el('p',{},`automatic_spend_atoms: ${status.spend}`));
 }
 paintNode();
 const stopStatus=app.state.subscribe(()=>{if(nodeAlive)paintNode();});
 const earlierCleanup=app.cleanup;
 app.cleanup=()=>{nodeAlive=false;stopStatus();if(typeof earlierCleanup==='function')earlierCleanup();};
 const bridge=app.bridge;
 if(bridge&&bridge.mode!=='disconnected'&&bridge.connected===true&&typeof bridge.read==='function'){
  try{
   Promise.resolve(bridge.read('getmodelhostprofile')).then(envelope=>{
    if(!nodeAlive)return;
    hostProfile=envelope&&typeof envelope==='object'&&Object.prototype.hasOwnProperty.call(envelope,'result')?envelope.result:null;
    paintNode();
   }).catch(()=>{});
  }catch{/* disconnected bridge refused the read */}}
 const nodePanel=el('section',{class:'panel'},el('h2',{},'This node on the model network'),note('This page does not fetch a model or spend.'),nodeFacts,operationButtons(app,['showmodel','getmodelwatchstatus','getmodelpolicy']));
 root.append(nodePanel,tabs,bar,results);show();return root;
}
function recordColumns(rows,preferred){
 const chosen=preferred.filter(key=>Object.prototype.hasOwnProperty.call(rows[0],key));
 if(chosen.length)return chosen;
 const key=Object.keys(rows[0])[0];
 return [key||preferred[0]];
}
function recordObservation(rows,preferred,envelope,title){
 const view=rows.length?table(rows,recordColumns(rows,preferred)):note('No rows in this observation.');
 return [view,el('details',{},el('summary',{},'Native record'),jsonView(envelope,{open:true,title}))];
}
export function operationButtons(app,methods){return el('div',{class:'actions'},...methods.map(m=>button(m,()=>operationDialog(app,m),'',{disabled:app.bridge.supported(m)===false})));}
export function modelDetails(app,m){const id=m.model_id||m.id||m.uri||m.share?.uri;if(!id)return;const body=el('div',{class:'surface-stack'},badge(m.bytes_verified===true&&m.incomplete===false?'Verified local bytes':'Verification incomplete / unknown'),note('Byte verification is not quality evaluation, software admission or permission to execute.'),jsonView(m,{open:true}),el('div',{class:'actions'},...['showmodel','getmodel','getmodelsharecard','loadmodel','generatemodel','unloadmodel'].map(method=>button(method,()=>operationDialog(app,method,[id])))),button('Configure local assistant',()=>app.openAssistant(id),'primary'));dialog(m.name||String(id).slice(0,64),body);}
