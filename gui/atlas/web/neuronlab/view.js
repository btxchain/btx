import {el,button,heading,note,field,table,jsonView,toast,dialog,metric,badge} from '../components/ui.js';
import {isNative} from '../core/bridge.js';
import {parseJsonExact,plainNumbers} from '../core/json.js';
import {KINDS,FACT_NAMES,operation,millionths,dose,unknownRecipe,defaultDraft,validateDraft,bindingLabel,coordinateKey} from './contract.js';
import {mountScience,SCIENCE_TABS} from './science/view.js';
import {NeuronScene} from './scene.js';
import {RECORDED_FIXTURE} from './recorded-fixture.js';
const parse=text=>plainNumbers(parseJsonExact(text));
const pretty=x=>JSON.stringify(x,null,2);
const oid=()=>crypto.randomUUID();
export function neuronLabView(app){
 let alive=true,model=null,profile=null,models=[],profiles=[],draft=null,lastComparison=null,scene=null,tab='workbench',busy=false;
 let science=null;const scienceState={};
 const root=el('section',{class:'page neuronlab'},heading('Neuron Lab','Inspect, intervene, compare and share exact checkpoint-bound control profiles. Model behavior is not execution authority.'));
 const status=note('Native research worker has not been configured. No experiment is running.','warning'),results=el('div'),body=el('div');
 const toolbar=el('div',{class:'actions nl-toolbar'}),tabs=el('nav',{class:'nl-tabs','aria-label':'NeuronLab sections'});
 const modelSelect=el('select',{'aria-label':'Exact registered model',id:'nl-model'}),profileSelect=el('select',{'aria-label':'Signed profile',id:'nl-profile'});
 const invoke=async(action,payload={},onProgress=null)=>{
  if(!isNative)throw Error('This is a recorded local CPU demonstration. Native execution, signing and network transfer are disabled.');
  const operationId=oid();let unlisten=null;
  if(onProgress)onProgress({type:'operation-start',operation_id:operationId});
  try{
   if(onProgress&&globalThis.__TAURI__?.event?.listen)unlisten=await globalThis.__TAURI__.event.listen('neuronlab-progress',e=>{if(alive&&e.payload?.operation_id===operationId)onProgress({...e.payload.event,operation_id:operationId});});
   return await app.bridge.invoke('atlas_neuronlab',{action,payloadJson:JSON.stringify(payload),operationId});
  }finally{if(unlisten)unlisten();}
 };
 const show=x=>{if(alive)results.replaceChildren(jsonView(x,{open:true,title:'Exact local result / evidence'}));};
 const run=async(fn)=>{if(busy){toast('A local operation is already in progress. Use Stop to interrupt it.','warning');return;}busy=true;status.textContent='Local operation in progress; results are not released until its checks complete.';try{await fn();if(alive)status.textContent='Local operation completed. Inspect the exact result and its qualification limits below.';}catch(e){if(alive){status.textContent=e.message;toast(e.message,'danger');}}finally{busy=false;}};
 async function refresh(){
  if(!isNative)return;
  const s=await invoke('status');if(!alive)return;
  status.textContent=`${s.crypto||'Research worker'} · ${s.publisher?'Publisher initialized':'Initialize a publisher before signing'} · no wallet access · independent identity binding`;
  const mm=await invoke('models'),pp=await invoke('list');if(!alive)return;models=mm.items;profiles=pp.items;fillSelectors();
 }
 function fillSelectors(){
  modelSelect.replaceChildren(el('option',{value:''},'Select exact checkpoint…'),...models.map(m=>el('option',{value:m.id,selected:m.id===model?.id},`${m.binding.architecture} · ${m.id.slice(0,12)}`)));
  profileSelect.replaceChildren(el('option',{value:''},'Select signed profile…'),...profiles.map(p=>el('option',{value:p.id,selected:p.id===profile?.summary?.id},`${p.title} · ${p.trust||'recorded'}`)));
 }
 function setModel(m){model=m;draft=defaultDraft(m.id,m.binding);render();}
 modelSelect.addEventListener('change',()=>{const m=models.find(m=>m.id===modelSelect.value);if(m)setModel(m);});
 profileSelect.addEventListener('change',()=>run(async()=>{const id=profileSelect.value;if(!id)return;profile=await invoke('profile',{profile_id:id,include_tensors:true});if(alive){draft={...defaultDraft(model?.id||'',profile.profile.binding),...Object.fromEntries(['title','description','operations','training_recipe','privacy','license','claims','parent_profiles'].map(k=>[k,profile.profile[k]])),parent_profiles:[profile.summary.id],tensors:profile.editable_tensors||{}};render();}}));
 toolbar.append(modelSelect,profileSelect,button('Configure worker',()=>run(async()=>{show(await invoke('configure'));await refresh();})),button('Initialize publisher',()=>run(async()=>{show(await invoke('initialize'));await refresh();})),button('Register local model',()=>run(async()=>{const r=await invoke('register');show(r);await refresh();const m=models.find(m=>m.id===r.id);if(m){setModel(m);fillSelectors();}})),button('Refresh',()=>run(refresh)),button('Stop',async()=>{try{show(await app.bridge.invoke('atlas_neuronlab_cancel'));}catch(e){toast(e.message,'danger');}},'danger'));
 if(!isNative)toolbar.append(button('Load recorded CPU experiment',()=>{model=RECORDED_FIXTURE.model;profile=RECORDED_FIXTURE.profile;lastComparison=RECORDED_FIXTURE.comparison;models=[model];profiles=[{...profile.summary,trust:'RECORDED_LOCAL_TEST_NOT_LIVE'}];draft={...defaultDraft(model.id,model.binding),...RECORDED_FIXTURE.draft};fillSelectors();status.textContent='RECORDED AUTHORING-TEST DATA • small locally trained transformer • not a live node, not a production LLM';render();},'primary',{id:'nl-recorded'}));
 for(const[id,label]of [['workbench','Workbench'],['profiles','Sharing & trust'],['recipe','Training recipe'],['directions','Directions & lenses'],['studies','Recipe studies'],['evidence','Evidence'],['routing','Context routing'],...SCIENCE_TABS])tabs.append(button(label,()=>{tab=id;render();},'',{dataset:{tab:id}}));
 root.append(toolbar,status,note('Downloading a capsule is not permission to apply it. A signed label such as “calm” is a hypothesis, not a verified psychological or universal neuron property.','warning'),tabs,body,results);
 function render(){
  scene?.dispose();scene=null;science?.dispose();science=null;for(const b of tabs.children)b.classList.toggle('active',b.dataset.tab===tab);body.replaceChildren();
  if(SCIENCE_TABS.some(([id])=>id===tab)){science=mountScience(tab,body,{getModel:()=>model,getProfile:()=>profile,invoke,run,show,app,native:isNative},scienceState);return;}
  if(tab==='workbench')workbench();else if(tab==='profiles')sharing();else if(tab==='recipe')recipe();else if(tab==='directions')directions();else if(tab==='studies')studies();else if(tab==='evidence')evidence();else routing();
 }
 function workbench(){
  const canvas=el('canvas',{class:'nl-canvas',tabindex:0,role:'img','aria-label':'Checkpoint layer coordinates and measured activations'}),inspector=el('div',{class:'panel nl-inspector'}),layout=el('div',{class:'nl-layout'},el('div',{class:'nl-map'},canvas),inspector);
  body.append(layout);scene=new NeuronScene(canvas,{onSelect:c=>{layer.value=String(c.layer);indices.value=String(c.first);coordinate.textContent=coordinateKey(model.binding,c.layer,'mlp_post_activation',c.first)+(c.aggregated?` · displayed bin ${c.first}–${c.last}; edit exact index below`:'');}});
  if(model)scene.setData(model.binding,lastComparison?.arms?.find(a=>a.arm==='positive')?.capture);
  const layer=el('input',{type:'number',min:0,max:model?model.binding.layers-1:0,value:0,id:'nl-layer'}),indices=el('input',{value:'0',id:'nl-units',spellcheck:false}),kind=el('select',{id:'nl-kind'},...KINDS.map(k=>el('option',{value:k,selected:k==='neuron_scale'},k))),coef=el('input',{value:'0',id:'nl-dose',inputmode:'decimal'}),phase=el('select',{},...['both','prefill','decode'].map(x=>el('option',{value:x},x))),coordinate=el('div',{class:'mono nl-coordinate'},model?bindingLabel(model.binding):'No registered checkpoint');
  inspector.append(el('div',{class:'eyebrow'},'Checkpoint-specific coordinates'),coordinate,note('GELU post-activation and SwiGLU post-product coordinates are different hook semantics. Unit number alone is not portable.'),field('Layer',layer),field('Operator',kind),field('Exact units / heads, comma-separated',indices),field('Coefficient (decimal; saved as millionths)',coef),field('Apply during',phase));
  inspector.append(button('Put operator into draft',()=>{try{if(!model)throw Error('Select a model');const k=kind.value,isVector=['residual_add','residual_project_out','sae_feature_add'].includes(k),units=isVector?[]:indices.value.split(',').map(x=>{if(!/^\d+$/.test(x.trim()))throw Error('Indices must be integers');return Number(x.trim());});const o=operation(k,Number(layer.value),units,millionths(coef.value));o.phase=phase.value;if(k==='neuron_clamp')o.bounds_ppm=[-1_000_000,1_000_000];if(k.startsWith('residual_')){o.tensor='direction';o.normalization=k==='residual_add'?'token_l2':'absolute';}if(k==='sae_feature_add')throw Error('Use the exact JSON draft to supply verified SAE tensors and feature identity.');draft.operations=[o];editor.value=pretty(draft);scene.setSelected(o.layer,units[0]||0);toast('Draft changed. This has not applied or signed an intervention.');}catch(e){toast(e.message,'danger');}}));
  const editor=el('textarea',{rows:13,class:'mono',id:'nl-draft',value:pretty(draft||{})}),prompt=el('textarea',{rows:3,value:model?.binding.architecture==='BTXTinyLM'?'1 2 3 4':'Use a public, nonsensitive experimental prompt.',id:'nl-prompt'}),count=el('input',{type:'number',min:1,max:256,value:16});
  body.append(el('section',{class:'panel'},el('h2',{},'Immutable intervention draft'),note('Editing does not mutate weights or activate a profile. The selected signed profile and this draft are separate.'),editor,el('div',{class:'actions'},button('Validate draft locally',()=>{try{if(!model)throw Error('Select model');draft=validateDraft(parse(editor.value),model.binding);show({valid_presentation:true,native_validation_still_required:true});}catch(e){toast(e.message,'danger');}}),button('Sign & save new profile',()=>run(async()=>{if(!model)throw Error('Select model');draft=validateDraft(parse(editor.value),model.binding);const r=await invoke('create',draft);profile=await invoke('profile',{profile_id:r.id});show(r);await refresh();if(alive)render();}),'primary')),field('Counterfactual prompt',prompt),field('Maximum new tokens per arm',count),button('Compare selected signed profile: baseline / + / −',()=>run(async()=>{if(!profile||!model)throw Error('Select a signed profile and registered model');lastComparison=await invoke('compare',{profile_id:profile.summary.id,model_id:model.id,prompt:prompt.value,max_new_tokens:Number(count.value),layer:Number(layer.value),units:indices.value.split(',').map(Number)});if(alive)render();}),'primary')));
  if(lastComparison){
   const grid=el('div',{class:'nl-comparison'});
   for(const arm of lastComparison.arms){const v=el('article',{class:'panel'},badge(arm.arm,arm.arm==='baseline'?'':'cyan'),el('pre',{class:'nl-text'},arm.text),el('small',{class:'mono'},`${arm.elapsed_us} μs · ${arm.token_ids.length} tokens · ${arm.capture?.records.length||0} selected capture records`),button('Inspect measured coordinates',()=>{scene.setData(model.binding,arm.capture);show(arm.capture);}));grid.append(v);}
   body.append(el('h2',{},'Counterfactual outputs'),note(lastComparison.warning||'Exploratory comparison; no semantic or release qualification.'),grid);
   body.append(table(lastComparison.arms.flatMap(a=>(a.capture?.records||[]).slice(0,24).map(r=>({arm:a.arm,...r}))),['arm','layer','site','stage','token','unit','value_millionths'],{pageSize:16}));
  }
 }
 function sharing(){
  const uri=el('input',{placeholder:'btx://…',id:'nl-uri'}),expected=el('input',{placeholder:'Expected 96-hex intervention profile ID',value:profile?.summary?.id||''}),domain=el('input',{value:'operator-assigned-domain'}),generation=el('input',{type:'number',min:0,value:0});
  const distribution=el('section',{class:'panel'},
   el('h2',{},'Data distribution, not automatic adoption'),
   note('The existing BTX verified byte transport carries the SafeTensors capsule. Explicit resource-URI sharing is implemented; a new global intervention directory is not implied. Realm-private publication is refused by this public route.'),
   profile?jsonView(profile.summary):note('Choose a signed profile.'));
  const imports=el('div',{class:'actions'});
  imports.append(
   button('Import capsule file',()=>run(async()=>{show(await invoke('import'));await refresh();})),
   button('Export selected capsule',()=>run(async()=>{if(!profile)throw Error('Select profile');show(await invoke('export',{profile_id:profile.summary.id}));})),
   button('Serve public capsule through BTX',()=>run(async()=>{if(!profile)throw Error('Select profile');show(await invoke('publish',{profile_id:profile.summary.id}));})));
  const retrieval=el('div',{class:'actions'});
  retrieval.append(
   button('Retrieve FREE_ONLY bytes',()=>run(async()=>show(await invoke('acquire',{uri:uri.value})))),
   button('Verify completed checkout & import',()=>run(async()=>{show(await invoke('finish_acquire',{uri:uri.value,profile_id:expected.value}));await refresh();})));
  distribution.append(imports,field('Native BTX resource URI',uri),field('Expected intervention identity (from publisher)',expected),retrieval);
  body.append(distribution);
  body.append(el('section',{class:'panel'},el('h2',{},'Local trust and activation'),field('Publisher trust-domain label (not independent proof)',domain),field('Expected current activation generation',generation),el('div',{class:'actions'},button('Trust selected publisher',()=>run(async()=>{if(!profile)throw Error('Select profile');show(await invoke('trust',{publisher:profile.summary.publisher,domain_label:domain.value}));await refresh();})),button('Revoke publisher',()=>run(async()=>{if(!profile)throw Error('Select profile');show(await invoke('revoke',{publisher:profile.summary.publisher,domain_label:domain.value}));await refresh();}),'danger'),button('Enable for local adapter',()=>run(async()=>{if(!profile||!model)throw Error('Select profile and model');show(await invoke('activate',{profile_id:profile.summary.id,model_id:model.id,expected_generation:Number(generation.value)}));})),button('Disable local intervention',()=>run(async()=>{if(!model)throw Error('Select model');show(await invoke('deactivate',{model_id:model.id}));}))),note('Persistent activation is used only by the explicitly installed BTX_MODEL_GENERATE adapter. It does not alter the default node, wallet, peer permissions, or an independently running inference engine.')));
 }
 function recipe(){
  const area=el('textarea',{rows:24,class:'mono',value:pretty(draft?.training_recipe||unknownRecipe())});
  body.append(el('section',{class:'panel'},el('h2',{},'Training recipe is part of the evidence'),note('Do not infer “trained with dropout” from a library default. Dropout differs by site and training stage. Unknown optimizer, weight decay, corpus or post-training history stays unknown.','warning'),el('p',{},'Compare GELU/SwiGLU, normalization, optimizer, regularization and post-training only within declared cohorts. Configuration declarations and measured experiment settings are labelled separately.'),area,button('Use recipe metadata in the draft',()=>{try{if(!draft)throw Error('Select model');const r=parse(area.value);draft.training_recipe=r;validateDraft(draft,model.binding);toast('Recipe metadata added to draft, not yet signed.');}catch(e){toast(e.message,'danger');}})));
  if(model)body.append(table(FACT_NAMES.map(k=>({fact:k,...(draft?.training_recipe?.facts[k]||{})})),['fact','status','value','source']));
 }
 function directions(){
  const data=el('textarea',{rows:10,class:'mono',placeholder:'{"positive":[[...],[...]],"reference":[[...],[...]],"neutral":[[...],[...]],"variance_ppm":500000}'}),l=el('input',{type:'number',min:0,value:0}),u=el('input',{type:'number',min:0,value:0});
  body.append(el('section',{class:'panel'},el('h2',{},'Distributed directions, not only individual units'),note('Mean-difference extraction with optional neutral-PCA removal. The caller must identify the exact capture corpus; an extracted vector is not guaranteed to encode a named emotion.'),data,button('Extract normalized local direction',()=>run(async()=>{const r=await invoke('direction',parse(data.value));show(r);if(draft&&model){if(r.vector.length!==model.binding.hidden_size)throw Error('Extracted vector width does not match selected model');draft.tensors.direction=r.vector;draft.claims=[{label:'Data-derived contrast direction; semantic interpretation remains a hypothesis',status:'hypothesis',evidence_refs:[r.receipt_id]}];draft.operations=[{...operation('residual_add',0,[],200000),tensor:'direction',normalization:'token_l2'}];toast('Direction added to unsigned draft. Review calibration and provenance before sharing.');}}),'primary')));
  body.append(el('section',{class:'panel'},el('h2',{},'Static projection lens'),field('Layer',l),field('MLP coordinate',u),button('Measure down-column / output projection',()=>run(async()=>{if(!model)throw Error('Select model');show(await invoke('lens',{model_id:model.id,layer:Number(l.value),unit:Number(u.value)}));})),note('A weight projection identifies a candidate relationship, not a causally established circuit.')));
 }
 function studies(){
  const spec=el('textarea',{rows:8,class:'mono',value:pretty({seeds:[0,1,2],dropouts_ppm:[0,100000],activations:['gelu','silu'],weight_decay_ppm:[0,100000],optimizers:['adamw'],steps:40,data_seed:1107})}),planArea=el('div');
  body.append(el('section',{class:'panel'},el('h2',{},'Reproducible training-recipe cohorts'),note('This harness trains small causal transformers on a synthetic modular sequence task. It does not establish what dropout does in modern pretrained LLMs. MLP parameter counts are approximately matched; compute is not identical.','warning'),spec,button('Build immutable sharded study',()=>run(async()=>{const p=await invoke('study_plan',parse(spec.value));show(p);if(!alive)return;planArea.replaceChildren(table(p.work_units.map(w=>({id:w.id,...w.unit})),['id','seed','activation','dropout_ppm','weight_decay_ppm','optimizer'],{pageSize:12}),button('Run first local work unit (native approval)',()=>run(async()=>show(await invoke('study_run',{work:p.work_units[0]}))),'primary'),button('Export work plan',()=>app.bridge.export(pretty(p),'neuronlab-study.json')));}), 'primary'),planArea));
  body.append(note('Exported work units can be assigned to separately authorized peers. Returned runs retain their seed, recipe, model bytes, runtime and task identities. Duplicate work IDs cannot count as independent replications.'));
 }
 function evidence(){
  const input=el('textarea',{rows:10,class:'mono',placeholder:'{"rows":[{"task_id":"case-1","seed":0,"baseline_success":false,"candidate_success":true},...],"suite_hash":"<96 hex>","profile_id":"<96 hex>","trial_budget":1}'});
  const evaluation=el('section',{class:'panel'},el('h2',{},'Measured effects, uncertainty and negative results'),
   note('Paired cluster bootstrap keeps repeated seeds within a task. Multiple signatures on the same sample commitment do not create extra samples. Selectivity, redundancy and superposition are not interchangeable.'),input);
  evaluation.append(button('Evaluate supplied paired observations',()=>run(async()=>show(await invoke('evaluate',parse(input.value))))));
  const actions=el('div',{class:'actions'},
   button('List signed receipts',()=>run(async()=>show(await invoke('receipts')))),
   button('Import evidence receipt',()=>run(async()=>show(await invoke('import_evidence')))),
   button('Inspect local journal',()=>run(async()=>show(await invoke('events')))));
  body.append(evaluation,el('section',{class:'panel'},el('h2',{},'Receipts and local journal'),actions));

 }
 function routing(){
  const policy=el('textarea',{rows:12,class:'mono',value:pretty({schema:'btx.neuronlab.router/1',features:['task_progress','recent_failure_rate'],routes:profile?[{profile_id:profile.summary.id,weights_ppm:[300000,-200000],bias_ppm:0}]:[],fallback:'baseline',minimum_margin_ppm:50000,max_switches:8,policy_epoch:1})}),features=el('textarea',{rows:3,class:'mono',value:'{"task_progress": 0, "recent_failure_rate": 0}'});
  body.append(el('section',{class:'panel'},el('h2',{},'Bounded per-request context routing'),note('Only exact locally approved profiles are eligible. Low-confidence or exhausted-switch decisions choose baseline. Routing never grants tools, data, wallet authority or executable code.'),field('Immutable router policy',policy),field('Normalized numeric features (millionths)',features),el('div',{class:'actions'},button('Preview decision',()=>run(async()=>show(await invoke('router_preview',{policy:parse(policy.value),features_ppm:parse(features.value)})))),button('Save locally reviewed router',()=>run(async()=>show(await invoke('save_router',{policy:parse(policy.value)})))))));
 }
 render();if(isNative)refresh().catch(e=>{if(alive)status.textContent=e.message;});app.cleanup=()=>{alive=false;scene?.dispose();science?.dispose();};return root;
}
