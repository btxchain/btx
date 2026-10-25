import {el,button,field,note,badge,toast,dialog,jsonView} from './ui.js';
import {sourceRows} from '../core/graph.js';
import {validateSurface} from '../core/surface.js';
import {renderSurface,saveSurface} from './surfaces.js';
export function assistant(app,requestedModel=null){
 const root=el('aside',{class:'assistant','aria-label':'Local BTX assistant'}),select=el('select',{'aria-label':'Verified local assistant model'}),status=el('div'),thread=el('div',{class:'thread',role:'log','aria-live':'polite'}),input=el('textarea',{rows:3,placeholder:'Ask about this node, models, or observed activity…',maxlength:8192,'aria-label':'Question for the local model'});let disposed=false,busy=false;
 const close=()=>{disposed=true;root.remove();app.assistantElement=null;};
 root.append(el('header',{},el('strong',{},'Local assistant'),badge('No cloud'),button('×',close,'icon',{'aria-label':'Close assistant'})));
 const models=sourceRows(app.state.state.sources.listmodels).filter(m=>m.bytes_verified===true&&m.incomplete===false);
 select.append(el('option',{value:''},'Choose a verified, complete local model'),...models.map(m=>{const id=m.model_id||m.id||m.uri||m.share?.uri;return el('option',{value:id,selected:id===requestedModel},m.name||String(id).slice(0,40));}));
 const grant=button('Authorize local session',async()=>{try{if(!select.value)throw Error('Select a verified local model');const g=await app.bridge.agent('grant',{model:select.value});status.replaceChildren(note(`Granted ${g.remaining} questions. Read-only context; expires ${new Date(g.expires_at_ms).toLocaleTimeString()}.`));}catch(e){status.replaceChildren(note(e.message,'danger'));}},'primary');
 root.append(el('section',{class:'setup'},note('Runs the selected model through this node. No wallet or shell tools. Model recommendations are not native evidence.'),select,el('div',{class:'row'},grant,button('Revoke',async()=>{try{await app.bridge.agent('revoke');status.replaceChildren(note('Future turns revoked. Already running native generation may continue.'));}catch(e){toast(e.message,'danger');}},'warning')),status),thread);
 const submit=el('button',{type:'submit',class:'button primary'},'Ask locally');
 const form=el('form',{},input,el('div',{class:'actions'},el('small',{},'Prompt stays on this node'),submit));
 form.addEventListener('submit',async e=>{e.preventDefault();if(busy||!input.value.trim())return;const question=input.value;input.value='';busy=true;submit.disabled=true;const user=el('div',{class:'message user'},question),answer=el('div',{class:'message'},'Waiting for native local generation…');thread.append(user,answer);while(thread.children.length>32)thread.firstChild.remove();thread.scrollTop=thread.scrollHeight;
  try{const reply=await app.bridge.agent('ask',{question});if(disposed)return;answer.replaceChildren(document.createTextNode(reply.text),el('span',{class:'meta'},`LOCAL · ${reply.reads.join(' · ')} · ${reply.remaining} questions remain`));
   if(reply.surface){try{const doc=validateSurface(reply.surface);answer.append(button('Preview proposed read-only view',()=>dialog('Model-proposed interface',el('div',{class:'surface-stack'},renderSurface(doc,app.state.state.sources,v=>app.navigate(v),id=>app.focus(id)),button('Save this exact revision',async()=>{try{const d=await saveSurface(doc);toast(`Saved read-only surface ${d.slice(0,12)}`);}catch(e){toast(e.message,'danger');}})))));}catch(err){answer.append(note(`Surface refused: ${err.message}`,'warning'));}}
   if(reply.suggestions?.length)answer.append(note('Suggested method names only. No arguments or approvals were accepted from the model.'),...reply.suggestions.map(m=>button(`Inspect ${m}`,()=>app.inspectOperation(m),'subtle')));
  }catch(error){if(!disposed)answer.replaceChildren(note(`${error.code||'ASSISTANT'} · ${error.message}. No cloud fallback was used.`,'danger'));}finally{busy=false;if(!disposed){submit.disabled=false;thread.scrollTop=thread.scrollHeight;}}
 });root.append(form);document.body.append(root);app.assistantElement=root;input.focus();return root;
}
