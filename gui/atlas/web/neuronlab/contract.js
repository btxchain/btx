// Independent BTX NeuronLab presentation helpers. No model-supplied executable UI.
export const PROFILE_SCHEMA='btx.neuronlab.profile/1';
export const KINDS=['neuron_add','neuron_scale','neuron_clamp','head_scale','residual_add','residual_project_out','sae_feature_add'];
export const FACT_NAMES=['pretraining_dropout','finetuning_dropout','optimizer','weight_decay','training_tokens','training_data','normalization','activation','post_training'];
export function millionths(text){
 if(typeof text!=='string'||!/^[-+]?(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,6})?$/.test(text))throw Error('Use a decimal with at most six places.');
 const sign=text.startsWith('-')?-1:1,parts=text.replace(/^[-+]/,'').split('.');
 const n=sign*(Number(parts[0])*1_000_000+Number((parts[1]||'').padEnd(6,'0')));
 if(!Number.isSafeInteger(n)||Math.abs(n)>100_000_000)throw Error('Coefficient exceeds the display limit.');return n;
}
export function dose(value){if(!Number.isSafeInteger(value))throw Error('Invalid coefficient');return(value/1e6).toFixed(6).replace(/\.?0+$/,'')||'0';}
export function unknownRecipe(){return{schema:'btx.neuronlab.training-recipe/1',facts:Object.fromEntries(FACT_NAMES.map(k=>[k,{status:'unknown',value:null,source:''}]))};}
export function operation(kind='neuron_scale',layer=0,indices=[0],coefficient=0){return{id:'op-1',kind,layer,indices,coefficient_ppm:coefficient,normalization:'absolute',phase:'both',token_start:0,token_end:-1,tensor:null,calibration:null,bounds_ppm:null,sae:null};}
export function assertOperation(o,b){
 if(!o||!KINDS.includes(o.kind))throw Error('Unsupported intervention operator');
 if(!Number.isInteger(o.layer)||o.layer<0||o.layer>=b.layers)throw Error('Layer is outside this exact checkpoint');
 if(!Number.isInteger(o.coefficient_ppm)||Math.abs(o.coefficient_ppm)>8_000_000)throw Error('Dose outside hard capsule bounds');
 if(!Array.isArray(o.indices)||o.indices.length>256||new Set(o.indices).size!==o.indices.length)throw Error('Invalid indices');
 const limit=o.kind==='head_scale'?b.heads:b.intermediate_size;
 for(const i of o.indices)if(!Number.isInteger(i)||i<0||i>=limit)throw Error('Unit is outside this adapter');
 if(!['both','prefill','decode'].includes(o.phase))throw Error('Invalid phase');
 if(!Number.isInteger(o.token_start)||o.token_start<0||!Number.isInteger(o.token_end)||(o.token_end!==-1&&o.token_end<=o.token_start))throw Error('Invalid token range');
 return o;
}
export function bindingDifferences(a,b){return Object.keys(a).filter(k=>k!=='btx_model_id'&&a[k]!==b[k]);}
export function bindingLabel(b){return`${b.architecture} · ${b.layers} layers · ${b.intermediate_size} MLP coordinates/layer · ${b.activation}`;}
export function coordinateKey(binding,layer,site,unit){if(!Number.isInteger(unit)||unit<0)throw Error('Invalid unit');return`${binding.weights_hash}/${binding.adapter}/${binding.execution_fingerprint||'unqualified'}/${layer}/${site}/${unit}`;}
export function captureValues(capture,layer,stage='post',site='mlp_post_activation'){
 const values=new Map();let omitted=0;
 for(const row of(capture?.records||[]).slice(0,8192)){
  if(row.layer!==layer||row.stage!==stage||row.site!==site)continue;
  if(!Number.isInteger(row.unit)||!Number.isFinite(row.value_millionths)){omitted++;continue;}
  const old=values.get(row.unit);if(old===undefined||Math.abs(row.value_millionths)>Math.abs(old))values.set(row.unit,row.value_millionths);
 }return{values,omitted};
}
export function validateDraft(d,b){
 if(!d||typeof d!=='object'||!Array.isArray(d.operations)||d.operations.length<1||d.operations.length>64)throw Error('Provide 1–64 operations');
 for(const o of d.operations)assertOperation(o,b);
 if(!['private','realm','public'].includes(d.privacy))throw Error('Invalid privacy class');
 if(typeof d.title!=='string'||d.title.length<1||d.title.length>160)throw Error('Invalid profile title');
 const recipe=d.training_recipe;if(!recipe||recipe.schema!=='btx.neuronlab.training-recipe/1')throw Error('Training-recipe metadata required');
 for(const k of FACT_NAMES){const f=recipe.facts?.[k];if(!f||!['unknown','reported','measured_in_this_study'].includes(f.status))throw Error(`Missing recipe fact: ${k}`);if(f.status==='unknown'&&f.value!==null)throw Error('Unknown training facts must stay null');}
 return d;
}
export function defaultDraft(modelId,b){return{model_id:modelId,title:'Untitled local intervention',description:'Checkpoint-specific research profile; behavioral effects are unqualified.',operations:[operation()],tensors:{},training_recipe:unknownRecipe(),privacy:'private',license:'License and redistribution rights not yet reviewed',claims:[],parent_profiles:[]};}
