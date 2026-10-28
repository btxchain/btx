import {el,note,jsonView,button,metric,toast,field} from './ui.js';
import promptJson from '../core/openui-prompt.json' with { type: 'json' };
import {parseOpenUI,queryPlan,realizeOpenUI,validateOpenUIDocument,rememberOpenUI,summarizeObservation,mergeOpenUI,mergedSource,groupRuns,EXAMPLE_PROGRAM,OPENUI_SCHEMA} from '../core/openui.js';
const {prompt}=promptJson;
const STORAGE_KEY='atlas.openui.v1';
function textCell(value){return value==null?'':String(value);}
function prop(node,key){
 const props=node.props;
 if(props&&typeof props==='object'&&!Array.isArray(props)&&Object.prototype.hasOwnProperty.call(props,key))return props[key];
 return node[key];
}
function renderTable(props){
 const columns=Array.isArray(props.columns)?props.columns:[];
 const rows=Array.isArray(props.rows)?props.rows:[];
 const body=[];
 for(const row of rows){
  if(!Array.isArray(row))continue;
  body.push(el('tr',{},...row.map(cell=>el('td',{},textCell(cell)))));
 }
 return el('div',{class:'table-scroll'},el('table',{},el('thead',{},el('tr',{},...columns.map(cell=>el('th',{},textCell(cell))))),el('tbody',{},...body)));
}
function renderChildren(children,handlers){
 const nodes=[];
 const groups=groupRuns(Array.isArray(children)?children:[]);
 for(let i=0;i<groups.length;){
  const group=groups[i];
  if(group.type==='buttons'){
   nodes.push(el('div',{class:'row'},...group.items.map(item=>renderNode(item,handlers))));
   i++;
  }else if(group.item&&group.item.type==='Metric'){
   const tiles=[];
   while(i<groups.length&&groups[i].type==='one'&&groups[i].item&&groups[i].item.type==='Metric'){
    const item=groups[i++].item;
    tiles.push(metric(prop(item,'label'),prop(item,'value'),prop(item,'detail')||''));
   }
   nodes.push(el('div',{class:'metrics'},...tiles));
  }else{
   nodes.push(renderNode(group.item,handlers));
   i++;
  }
 }
 return nodes;
}
function renderStack(node,handlers){
 const children=Array.isArray(node.children)?node.children:prop(node,'children');
 return el('div',{class:'openui-view'},...renderChildren(children,handlers));
}
function renderNode(node,handlers){
 if(!node||typeof node!=='object')return note('Unsupported OpenUI node','warning');
 const {onNavigate,onFocus}=handlers;
 switch(node.type){
  case 'Stack':return renderStack(node,handlers);
  case 'Text':return el('p',{},prop(node,'text'));
  case 'Note':return note(prop(node,'text'),prop(node,'tone')==='warning'?'warning':'');
  case 'Metric':return metric(prop(node,'label'),prop(node,'value'),prop(node,'detail')||'');
  case 'Table':return renderTable({columns:prop(node,'columns'),rows:prop(node,'rows')});
  case 'Button':{
   const label=prop(node,'label'),action=prop(node,'action'),target=prop(node,'target');
   return button(label,()=>action==='navigate'?onNavigate(target):onFocus(target));
  }
  case 'Observation':{
   const value=prop(node,'value');
   const shown=value===undefined?null:value;
   const method=prop(node,'method');
   const summary=summarizeObservation(method,shown);
   if(!summary.metrics.length)return jsonView(shown,{title:method,open:false});
   const tiles=el('div',{class:'metrics'},...summary.metrics.map(item=>metric(item.label,item.value,'')));
   if(!summary.rest)return tiles;
   return el('div',{},tiles,jsonView(shown,{title:method,open:false}));
  }
  case 'Refused':return note(prop(node,'reason'),'warning');
  default:return note('Unsupported OpenUI node','warning');
 }
}
export function renderOpenUI(tree,handlers={}){
 return tree&&tree.type==='Stack'?renderStack(tree,handlers):renderNode(tree,handlers);
}
export function loadOpenUI(){
 try{
  const raw=localStorage.getItem(STORAGE_KEY);
  if(!raw)return [];
  const parsed=JSON.parse(raw);
  if(!Array.isArray(parsed))return [];
  const kept=[];
  for(const item of parsed){
   if(kept.length>=12)break;
   try{if(validateOpenUIDocument(item)===false)continue;kept.push(item);}catch{continue;}
  }
  return kept;
 }catch{return [];}
}
export function saveOpenUI(doc){
 if(validateOpenUIDocument(doc)===false)throw Error('OpenUI document refused');
 const stored=rememberOpenUI(loadOpenUI(),doc);
 if(!Array.isArray(stored))throw Error('OpenUI library did not return a list');
 localStorage.setItem(STORAGE_KEY,JSON.stringify(stored));
 return stored;
}
export async function runProgram(app,source){
 const parsed=parseOpenUI(source);
 const plan=queryPlan(parsed);
 const answers=new Map();
 const connected=!!(app&&app.bridge&&app.bridge.connected);
 for(const item of plan){
  if(connected){
   try{const envelope=await app.bridge.read(item.method);answers.set(item.id,{ok:true,value:envelope.result});}
   catch(e){answers.set(item.id,{ok:false,message:e.message||'Read failed'});}
  }else answers.set(item.id,{ok:false,message:'Connect to this node to observe it'});
 }
 return realizeOpenUI(parsed,answers);
}
function showProgram(app,out,source){
 const handlers={onNavigate:view=>app.navigate(view),onFocus:id=>app.focus(id)};
 return runProgram(app,source).then(tree=>out.replaceChildren(renderOpenUI(tree,handlers))).catch(e=>out.replaceChildren(note(e.message||'OpenUI program refused','warning')));
}
export function openuiSection(app){
 const list=el('div',{class:'surface-stack'}),out=el('div'),status=el('div');
 const program=el('textarea',{class:'mono',rows:8,'aria-label':'OpenUI program',value:''});
 const patch=el('textarea',{class:'mono',rows:4,'aria-label':'OpenUI patch'});
 const refresh=()=>{
  list.replaceChildren(...loadOpenUI().map((doc,index)=>el('section',{class:'panel'},el('h3',{},doc.title),el('div',{class:'row'},
   button('Preview',()=>{showProgram(app,out,doc.program);}),
   button('Load',()=>{program.value=doc.program;}),
   button('Remove',()=>{try{const next=loadOpenUI().filter((_,i)=>i!==index);localStorage.setItem(STORAGE_KEY,JSON.stringify(next));refresh();}catch(e){toast(e.message||'OpenUI program was not removed','danger');}})
  ))));
 };
 refresh();
 return el('section',{class:'surface-stack','aria-label':'OpenUI programs'},
  el('h3',{},'OpenUI programs'),
  list,
  el('div',{class:'row'},
   button('Preview example',()=>{showProgram(app,out,EXAMPLE_PROGRAM);}),
   button('Save this example',()=>{try{saveOpenUI({schema:OPENUI_SCHEMA,title:'This node',program:EXAMPLE_PROGRAM});refresh();toast('OpenUI example saved');}catch(e){toast(e.message||'OpenUI example was not saved','danger');}}),
   button('Copy OpenUI instructions',async()=>{try{await app.bridge.copy(prompt);toast('OpenUI instructions copied');}catch(e){toast(e.message||'OpenUI instructions were not copied','danger');}})
  ),
  el('section',{class:'panel'},el('h3',{},'Editor'),
   field('Program',program,'OpenUI Lang for this node. A query is a read. A mutation is not run.'),
   el('div',{class:'row'},button('Preview program',()=>{showProgram(app,out,program.value);})),
   field('Patch',patch,'Replaces statements in the program above. The program changes only after the merged text parses.'),
   el('div',{class:'row'},button('Apply patch',()=>{
    const current=program.value;
    try{
     mergeOpenUI(current,patch.value);
     program.value=mergedSource(current,patch.value);
     status.replaceChildren();
    }catch(e){status.replaceChildren(note(e.message||'OpenUI patch was refused','danger'));}
   })),
   status),
  el('section',{class:'panel'},el('h3',{},'Preview'),out));
}
