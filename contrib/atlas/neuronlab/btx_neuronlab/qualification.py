"""Measured per-checkpoint qualification, never architecture-name certification."""
from __future__ import annotations
import importlib.metadata
import platform
import time
import torch
from .codec import require, integer, identity, LabError, sha384, read_file
from .models import ALLOWED, load_local
from .schema import unknown_recipe, operation
from .capsule import tensor_records
from .engine import encode_prompt
from .runtime_io import (forward, weights_digest, vocabulary, device_of, context_limit, ppm, SITES)
from .operators import InterventionSession, Capture
from .decoding import decode


def catalog():
    return {'schema':'btx.neuronlab.adapter-catalog/2',
      'items':[{'architecture':name,'adapter':adapter,'status':'ADAPTER_SOURCE_NOT_CHECKPOINT_QUALIFICATION',
                'weight_format':'SAFE_TENSORS_ONLY','precision':'FP32_REFERENCE',
                'special_limits': 'Linear-attention head hooks require independent support' if 'Qwen3_5' in name else
                                  'OPT projection dimensions are probed, not assumed' if name=='OPTForCausalLM' else
                                  'Hook structure and actual logits must pass local qualification'}
                for name,adapter in sorted(ALLOWED.items())],
      'unsupported':['GGUF','EXL3','vLLM fused kernels','MoE routed experts','custom remote code'],
      'automatic_download':False}


def hook_count(model):
    return sum(len(m._forward_hooks)+len(m._forward_pre_hooks)for m in model.modules())


def profile_for(binding,unit=0):
    records,tensors=tensor_records({})
    return {'schema':'btx.neuronlab.profile/1','title':'Local qualification ablation',
      'description':'Bounded generated qualification operator; not a public behavior profile',
      'binding':binding,'training_recipe':unknown_recipe(),'operations':[operation('neuron_scale',0,[unit],0)],
      'parent_profiles':[],'privacy':'private','license':'Local qualification data','claims':[],
      'created_ms':0,'composition':'ordered/pre-site-norm/v1','tensors':records},tensors


def qualify(root,binding,prompt,*,device='cpu',tolerance_ppm=10,progress=None):
    integer(tolerance_ppm,0,1000)
    start=time.perf_counter_ns();model,tok,adapter,b=load_local(root,binding,device=device)
    ids=encode_prompt(prompt,tok,vocabulary(model))
    require(len(ids)<=128,'QUALIFICATION_BUDGET','Qualification prompts are at most 128 tokens')
    before=weights_digest(model);before_hooks=hook_count(model);checks=[]
    tol=tolerance_ppm/1e6
    def record(name,passed,**details):
        checks.append({'check':name,'status':'PASS' if passed else 'FAIL',**details})
        if progress:progress({'type':'qualification-progress','check':name,'status':checks[-1]['status']})
    raw_ids=torch.tensor([ids],device=device_of(model))
    with torch.inference_mode():
        raw=model(input_ids=raw_ids,attention_mask=torch.ones_like(raw_ids),use_cache=False).logits.detach().float().cpu()
    z,c=forward(model,adapter,ids,capture=[(0,'mlp_post_activation'),(0,'residual_post')])
    record('unmodified_hook_equivalence',bool(torch.allclose(raw,z,atol=tol,rtol=tol)),max_abs_error_millionths=ppm((raw-z).abs().max()))
    record('activation_width',c[0,'mlp_post_activation'].shape[-1]==b['intermediate_size'])
    unit=int(c[0,'mlp_post_activation'][0,-1].abs().argmax())
    profile,tensors=profile_for(b,unit);capture=Capture([0],[unit],max_records=2048)
    with InterventionSession(model,adapter,b,profile,tensors,capture) as session,torch.inference_mode():
        session.before_forward(len(ids),0)
        edited=model(input_ids=raw_ids,attention_mask=torch.ones_like(raw_ids),use_cache=False).logits.detach().float().cpu()
    measured=[x['value_millionths']for x in capture.records if x['site']=='mlp_post_activation' and x['stage']=='post']
    record('declared_neuron_zeroing',bool(measured) and all(x==0 for x in measured))
    record('finite_edited_logits',bool(torch.isfinite(edited).all()))
    reset,_=forward(model,adapter,ids)
    record('post_intervention_baseline_restored',bool(torch.allclose(raw,reset,atol=tol,rtol=tol)))
    # Visit every supported layer/site with identity hooks in one forward pass.
    # Only shapes are retained, not all tensors. Unsupported sites
    # remain explicit, never conflated with a passed full-head qualification.
    hooks=[];identity_edits={}
    for layer in range(b['layers']):
        for site in SITES:
            if site=='embedding' and layer:continue
            try:
                adapter.hook_target(layer,site)
                def inspect(x,layer=layer,site=site):
                    hooks.append({'layer':layer,'site':site,'status':'PASS','shape':list(x.shape),'dtype':str(x.dtype)})
                    return x
                identity_edits[layer,site]=inspect
            except LabError as e:
                hooks.append({'layer':layer,'site':site,'status':'UNSUPPORTED' if e.code=='HEAD_ADAPTER_UNSUPPORTED' else 'FAIL','code':e.code})
    all_hook_logits,_=forward(model,adapter,ids,edits=identity_edits)
    record('all_declared_layer_hooks_identity_equivalence',bool(torch.allclose(raw,all_hook_logits,atol=tol,rtol=tol)),
           visited_sites=len(hooks),max_abs_error_millionths=ppm((raw-all_hook_logits).abs().max()))
    record('hook_registration_cleanup',hook_count(model)==before_hooks)
    cache_record={'check':'incremental_cache_equivalence','status':'NOT_APPLICABLE_NO_CACHE'}
    with torch.inference_mode():
        initial=model(input_ids=raw_ids,attention_mask=torch.ones_like(raw_ids),use_cache=True)
        cache=getattr(initial,'past_key_values',None)
        if cache is not None:
            token=int(initial.logits[0,-1].argmax())
            nextid=torch.tensor([[token]],device=raw_ids.device)
            inc=model(input_ids=nextid,attention_mask=torch.ones((1,len(ids)+1),device=raw_ids.device,dtype=torch.long),past_key_values=cache,use_cache=True).logits[0,-1].float().cpu()
            full=model(input_ids=torch.cat([raw_ids,nextid],-1),use_cache=False).logits[0,-1].float().cpu()
            cache_record={'check':'incremental_cache_equivalence','status':'PASS' if torch.allclose(inc,full,atol=tol,rtol=tol)else'FAIL','max_abs_error_millionths':ppm((inc-full).abs().max())}
    checks.append(cache_record)
    generation=decode(model,tok,adapter,b,ids,sampling={'max_new_tokens':min(8,context_limit(model)-len(ids)),
                      'temperature_ppm':0,'top_p_ppm':1_000_000,'top_k':0,'seed':0,'logprobs':0})
    record('real_generation',len(generation['token_ids'])>0,tokens=len(generation['token_ids']))
    record('weights_unchanged',before==weights_digest(model))
    record('hooks_clean_after_generation',before_hooks==hook_count(model))
    if device=='cuda':torch.cuda.synchronize()
    hardware={'os':platform.system(),'machine':platform.machine(),'device':device,
              'torch':str(torch.__version__),'precision':str(next(model.parameters()).dtype),
              'physical_hosts':1,'independent_operators':1,
              'cuda_device':torch.cuda.get_device_name() if device=='cuda' else None}
    failed=any(x['status']=='FAIL'for x in checks+hooks)
    return {'schema':'btx.neuronlab.qualification/2','binding':b,'hardware':hardware,
            'qualification':'FAIL' if failed else 'LOCAL_CHECKPOINT_PROBE_PASS',
            'scope':'SYNTHETIC_SMALL_MODEL' if tok is None else 'SELECTED_LOCAL_CHECKPOINT',
            'source_model_provenance':'NOT_INFERRED_FROM_ARCHITECTURE',
            'checks':checks,'hook_sites':hooks,'prompt_token_ids':ids,
            'tolerance_ppm':tolerance_ppm,'elapsed_us':(time.perf_counter_ns()-start)//1000,
            'production_release_qualified':False,'cross_device_equivalence':False,
            'qualification_source_sha384':sha384(read_file(__import__('pathlib').Path(__file__),1048576)),
            'limitations':['All supported hook sites were visited on one supplied prompt; intervention operators have separate tests','One host is not a deployment population','No scientific behavioral quality or semantic interpretation is established']}
