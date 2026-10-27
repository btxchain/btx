import {OPERATIONS,BY_METHOD} from '../core/catalog.js';
import {JsonNumber,parseJsonExact,encodeJson} from '../core/json.js';
import {parseBTX} from '../core/money.js';
import {el,button,field,note,badge,jsonView,dialog,toast} from '../components/ui.js';

function fieldControl(arg,bridge){
 let input;if(arg.kind==='boolean'){input=el('input',{type:'checkbox',checked:arg.default===true});}
 else if(arg.kind==='json'||arg.kind==='long'){input=el('textarea',{rows:arg.kind==='json'?4:3,value:typeof arg.default==='object'?JSON.stringify(arg.default,null,2):arg.default??'',spellcheck:false});}
 else if(arg.kind==='enum'){input=el('select',{},...(arg.options||[]).map(x=>el('option',{value:x,selected:x===arg.default},x)));}
 else input=el('input',{type:arg.kind==='secret'?'password':'text',value:arg.default??'',autocomplete:'off',spellcheck:false,'data-sensitive':arg.kind==='secret'?'true':null});
 const wrap=field(arg.name+(arg.required?' *':''),input,arg.kind==='amount'?'Exact BTX decimal, never binary floating point.':arg.kind==='integer'?'Integer':arg.kind==='secret'?'Not saved in preferences, assistant context, or the audit journal. Clear after use.':'');
 if(['path','savepath'].includes(arg.kind))wrap.append(button('Choose native path',async()=>{try{const r=await bridge.document(arg.kind==='savepath'?'destination_path':'source_path');input.value=r.path;}catch(e){toast(e.message,'danger');}},'subtle'));
 return{input,wrap,value(){const s=input.value;if(arg.kind==='boolean')return input.checked;if((s===''||s===undefined)&&!arg.required)return undefined;if(arg.kind==='json')return parseJsonExact(s||'{}');if(arg.kind==='integer'){if(!/^-?(0|[1-9][0-9]*)$/.test(s))throw Error(`${arg.name}: use an exact integer`);return new JsonNumber(s);}if(arg.kind==='amount'){parseBTX(s);return new JsonNumber(s);}return s;}};
}
export function prefillFieldText(kind,value){
 if(value instanceof JsonNumber)return value.text;
 if(value!==null&&typeof value==='object')return encodeJson(value);
 return String(value);
}
export function rawPreferred(args,prefill){
 if(!Array.isArray(prefill)||prefill.length!==1)return false;
 const value=prefill[0];
 if(value===null||typeof value!=='object'||value instanceof JsonNumber||Array.isArray(value))return false;
 const kind=args&&args[0]&&args[0].kind;
 return kind!=='json'&&kind!=='long';
}
export function operationDialog(app,method,prefill=[],walletContext){
 const definition=BY_METHOD.get(method)||{method,title:method,risk:'dangerous',args:[],wallet:false,notes:'Discovered native method. Read its current help; no argument shape is assumed.'};
 const body=el('div',{class:'operation-form'}),result=el('div'),wallet=el('input',{value:walletContext===undefined?(app.state.state.wallet||''):String(walletContext),placeholder:'Exact loaded wallet name',autocomplete:'off'}),raw=el('textarea',{rows:6,spellcheck:false,value:'[]',class:'mono','aria-label':'Exact JSON RPC parameters'});
 const useRaw=el('input',{type:'checkbox',checked:!definition.args.length||rawPreferred(definition.args,prefill)}),controls=definition.args.map(a=>fieldControl(a,app.bridge));
 for(let i=0;i<prefill.length&&i<controls.length;i++){const a=definition.args[i],v=prefill[i];if(a.kind==='boolean')controls[i].input.checked=!!v;else controls[i].input.value=prefillFieldText(a.kind,v);}
 const fields=el('div',{class:'fields'},...controls.map(c=>c.wrap));
 const updateMode=()=>{fields.hidden=useRaw.checked;raw.hidden=!useRaw.checked;};useRaw.addEventListener('change',updateMode);updateMode();
 if(prefill.length)raw.value=encodeJson(prefill);
 body.append(el('div',{class:'row'},badge(method,'cyan'),badge(definition.risk,definition.risk==='read'?'':'warning')),note('The connected node is authoritative. The form is a template, not proof that the method or signature is supported.'),definition.notes&&note(definition.notes,'warning'),field('Wallet context (blank means node endpoint)',wallet),field('Use exact JSON array/object',useRaw),fields,raw,result);
 const helpButton=button('Read current native help',async()=>{try{helpButton.disabled=true;const text=await app.bridge.help(method);result.replaceChildren(jsonView(text,{open:true,title:'Connected node help'}));}catch(e){result.replaceChildren(note(e.message,'danger'));}finally{helpButton.disabled=false;}});
 const run=button(definition.risk==='read'?'Read observation':'Prepare for native review',async()=>{
  run.disabled=true;let prepared;
  try{
   let params;if(useRaw.checked)params=parseJsonExact(raw.value);else{params=controls.map(c=>c.value());while(params.length&&params.at(-1)===undefined)params.pop();params=params.map(x=>x===undefined?null:x);}
   const json=encodeJson(params),context=wallet.value||null;
   if(definition.risk==='read'){try{const r=await app.bridge.read(method,json,context);result.replaceChildren(jsonView(r,{open:true}));return;}catch(e){if(e.code!=='READ_DENIED')throw e;}}
   prepared=await app.bridge.prepare(method,json,context);
   result.replaceChildren(note(`Prepared ${prepared.id.slice(0,12)}… · Native dialog will show the immutable request. This page cannot approve it.`));
   for(let i=0;i<controls.length;i++)if(definition.args[i].kind==='secret')controls[i].input.value='';
   if(definition.risk!=='read')raw.value='[]';
   const response=await app.bridge.execute(prepared.id);result.replaceChildren(jsonView(response,{open:true}));app.refreshSoon();
  }catch(e){result.replaceChildren(note(`${e.code||'REQUEST'} · ${e.message}${e.outcome_unknown?' · DO NOT RETRY. Reconcile with the native node and transaction/operation ID.':''}`,'danger'));}
  finally{run.disabled=false;}
 },definition.risk==='read'?'primary':'warning');
 if(app.bridge.supported(method)===false){run.disabled=true;body.prepend(note('This method is absent from the connected node’s help catalogue. It is disabled.','warning'));}
 body.append(el('div',{class:'actions'},helpButton,run));const d=dialog(definition.title,body);
 d.element.addEventListener('close',()=>{raw.value='';controls.forEach(c=>{c.input.value='';});},{once:true});return d;
}
export function operationWorkbench(app,{groups=null,title='Operation workbench'}={}){
 const root=el('section',{},el('h2',{},title)),search=el('input',{type:'search',placeholder:'Find a function or native RPC…','aria-label':'Find native operation'}),list=el('div',{class:'operation-grid'}),count=el('span',{class:'muted'});
 const render=()=>{const q=search.value.toLowerCase();const defs=OPERATIONS.filter(o=>(!groups||groups.includes(o.group))&&`${o.group} ${o.title} ${o.method}`.toLowerCase().includes(q));list.replaceChildren();for(const o of defs.slice(0,120)){const available=app.bridge.supported(o.method);list.append(button([o.title],()=>operationDialog(app,o.method),'operation-card',{title:o.method,dataset:{method:o.method}}));const b=list.lastChild;b.append(el('small',{},o.method),el('span',{class:`badge ${o.risk==='read'?'':'warning'}`},available===false?'Unavailable on node':o.risk));}count.textContent=`${defs.length} templates · ${Math.min(defs.length,120)} displayed · Availability follows native help`;};
 search.addEventListener('input',render);root.append(search,count,list);render();return root;
}
