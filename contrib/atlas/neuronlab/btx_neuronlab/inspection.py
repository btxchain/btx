"""Live selected activations, token lenses and explicitly noncausal weight links."""
from __future__ import annotations
import numpy as np
import torch
from .codec import require, integer, identity
from .engine import encode_prompt
from .runtime_io import forward, vocabulary, device_of, ppm
from .operators import InterventionSession


def fire_scan(model,tokenizer,adapter,binding,prompt,layers,topk=32):
    require(type(layers)is list and 0<len(layers)<=8 and len(set(layers))==len(layers),'LAYER_BUDGET','Choose 1..8 distinct layers')
    integer(topk,1,64)
    ids=encode_prompt(prompt,tokenizer,vocabulary(model));require(len(ids)<=512,'TOKEN_BUDGET','Activation browser limit is 512 tokens')
    out=[]
    for layer in layers:
        integer(layer,0,binding['layers']-1)
        _,c=forward(model,adapter,ids,capture=[(layer,'mlp_post_activation')])
        a=c[layer,'mlp_post_activation'][0]
        scores=a.abs().mean(0);units=torch.topk(scores,min(topk,a.shape[1])).indices
        for u in units.tolist():
            v=a[:,u]
            out.append({'layer':layer,'unit':u,'mean_abs_millionths':ppm(scores[u]),
                        'max_millionths':ppm(v.max()),'min_millionths':ppm(v.min()),
                        'max_token_index':int(v.argmax()),'min_token_index':int(v.argmin()),
                        'activations_millionths':[ppm(x)for x in v]})
    labels=[str(i) if tokenizer is None else tokenizer.decode([i],skip_special_tokens=False)for i in ids]
    return {'schema':'btx.neuronlab.fire-scan/2','binding':binding,'token_ids':ids,'token_labels':labels,
            'rows':out,'ranking':'MEAN_ABSOLUTE_ACTIVATION_ON_THIS_PROMPT',
            'monosemanticity_measured':False,'site':'mlp_post_activation'}


def steering_lens(model,tokenizer,adapter,binding,prompt,profile,tensors,topk=24,fence=None):
    integer(topk,1,64);ids=encode_prompt(prompt,tokenizer,vocabulary(model))
    z,_=forward(model,adapter,ids,fence=fence)
    data=torch.tensor([ids],device=device_of(model))
    with InterventionSession(model,adapter,binding,profile,tensors,fence=fence) as sess,torch.inference_mode():
        sess.before_forward(len(ids),0)
        changed=model(input_ids=data,attention_mask=torch.ones_like(data),use_cache=False).logits.detach().float().cpu()
    if fence:fence()
    before=torch.log_softmax(z[0,-1].double(),-1);after=torch.log_softmax(changed[0,-1].double(),-1)
    delta=after-before
    kl=float((after.exp()*(after-before)).sum())
    def rows(sign):
        v,i=torch.topk(sign*delta,min(topk,delta.numel()))
        return [{'token':int(idx),'text':str(int(idx)) if tokenizer is None else tokenizer.decode([int(idx)]),
                 'delta_logprob_millionths':ppm(delta[idx]),'baseline_logprob_millionths':ppm(before[idx]),
                 'modified_logprob_millionths':ppm(after[idx])}for idx in i]
    return {'schema':'btx.neuronlab.measured-steer-lens/2','up':rows(1),'down':rows(-1),'kl_modified_to_baseline_millionths':ppm(max(0,kl)),
            'input_ids':ids,'profile_id':identity('BTX/NeuronLab/Profile/1',profile),
            'kind':'MEASURED_NEXT_TOKEN_DISTRIBUTION_EFFECT_ON_THIS_CONTEXT'}


def connection_cone(adapter,binding,layer,unit,*,direction='downstream',depth=3,topk=8):
    integer(layer,0,binding['layers']-1);integer(unit,0,binding['intermediate_size']-1)
    integer(depth,1,8);integer(topk,1,32)
    require(direction=='downstream','CONNECTION_MODE','Static write/read cones are downstream only; use measured reverse patches for necessity')
    col=adapter.down_columns(layer,[unit])[:,0]
    require(float(col.norm())>1e-12,'ZERO_COLUMN','Selected output column has zero norm')
    rows=[]
    for l in range(layer+1,min(binding['layers'],layer+depth+1)):
        block=adapter.layers[l];name=adapter.name
        if name=='torch-gpt2-v1': readers=[('mlp_pre_activation',block.mlp.c_fc.weight.T)]
        elif name=='torch-gptj-v1':readers=[('mlp_pre_activation',block.mlp.fc_in.weight)]
        elif name=='torch-neox-v1':readers=[('mlp_pre_activation',block.mlp.dense_h_to_4h.weight)]
        elif name=='torch-opt-v1':readers=[('mlp_pre_activation',block.fc1.weight)]
        else:
            readers=[('up',block.mlp.up_proj.weight)] if hasattr(block.mlp,'up_proj') else []
            if getattr(block.mlp,'gate_proj',None)is not None:readers.append(('gate',block.mlp.gate_proj.weight))
        require(readers,'STATIC_READER_UNSUPPORTED','No reviewed read projection at this block')
        for channel,w in readers:
            w=w.detach().float();require(w.ndim==2 and w.shape[1]==col.shape[0],'WEIGHT_LAYOUT','Read/write width mismatch')
            score=(w@col)/(w.norm(dim=1)*col.norm()).clamp_min(1e-12)
            for idx in torch.topk(score.abs(),min(topk,len(score))).indices.tolist():
                rows.append({'from_layer':layer,'from_unit':unit,'to_layer':l,'to_unit':idx,'channel':channel,
                             'cosine_millionths':ppm(score[idx]),'edge_kind':'STATIC_WEIGHT_ALIGNMENT'})
    return {'schema':'btx.neuronlab.connection-cone/2','edges':rows,
            'causal':False,'ignores':['activation gates','normalization','attention','context','intermediate computations'],
            'warning':'A connection cone is a hypothesis generator. Launch an actual path/intervention experiment to measure an effect.'}


def extract_rows(model,tokenizer,adapter,binding,prompts,layer,site='residual_post',pooling='last'):
    require(type(prompts)is list and 1<=len(prompts)<=128,'PROMPT_BUDGET','At most 128 source prompts')
    integer(layer,0,binding['layers']-1)
    require(site in {'residual_post','mlp_post_activation'},'SITE','Only declared hidden/MLP representations')
    require(pooling in {'last','mean','tokens'},'POOLING','Unknown representation pooling')
    rows=[];groups=[];token_counts=[]
    for index,prompt in enumerate(prompts):
        ids=encode_prompt(prompt,tokenizer,vocabulary(model));require(len(ids)<=512,'TOKENS','Embedding capture prompt is too long')
        _,captured=forward(model,adapter,ids,capture=[(layer,site)])
        x=captured[layer,site][0].numpy();token_counts.append(len(ids))
        if pooling=='last':x=x[-1:]
        elif pooling=='mean':x=x.mean(0,keepdims=True)
        rows.append(x);groups.append(np.tile(np.array([0,index,0,1],dtype='<u4'),(len(x),1)))
        require(sum(r.nbytes for r in rows)<=128*1024*1024 and sum(len(r)for r in rows)<=16384,'CAPTURE_BUDGET','Representation capture budget exceeded')
    result=np.concatenate(rows).astype('<f4')
    require(len(result)>=2,'EMBEDDINGS','Projection needs at least two captured representations')
    return result,np.concatenate(groups),{'scope':'MEASURED_MODEL_ACTIVATIONS','binding':binding,'site':site,'layer':layer,
      'pooling':pooling,'prompt_set_hash':identity('BTX/NeuronLab/RepresentationPrompts/1',prompts),
      'token_counts':token_counts,'semantic_labels_verified':False}
