"""Request-private incremental decoding and exact conversation formatting."""
from __future__ import annotations
import time
import torch
from .codec import require, keys, integer, identity, sha384, canonical, LabError
from .runtime_io import vocabulary, context_limit, device_of, token_ids, ppm
from .operators import InterventionSession, cache_fingerprint


def format_messages(messages, tokenizer, model, template='hf-chat'):
    require(type(messages) is list and 1 <= len(messages) <= 257, 'HISTORY', 'Bounded message history required')
    for m in messages:
        keys(m, {'role','content'})
        require(m['role'] in {'system','user','assistant'} and type(m['content']) is str, 'HISTORY', 'Only text system/user/assistant messages are accepted')
    require(sum(len(m['content'].encode()) for m in messages)<=131072,'HISTORY_BUDGET','Conversation exceeds byte budget')
    require(messages[-1]['role']=='user','HISTORY_ORDER','Generation must follow a user turn')
    body=messages[1:] if messages[0]['role']=='system' else messages
    require(all(m['role']==('user' if i%2==0 else 'assistant') for i,m in enumerate(body)), 'HISTORY_ORDER','Conversation roles must alternate; only an initial system message is allowed')
    if tokenizer is None:
        require(template=='token-ids','TEMPLATE','Synthetic models require explicit token-ID transcript mode')
        require(all(m['role']!='system' for m in messages),'TEMPLATE','Tiny token transcripts have no system-role embedding')
        try: ids=[int(x) for m in messages for x in m['content'].split()]
        except ValueError as e: raise LabError('TOKEN','Synthetic conversation content is integer token IDs') from e
        description='BTX/token-id-transcript/v1; roles are NOT modeled'
    elif template=='hf-chat':
        require(bool(getattr(tokenizer,'chat_template',None)),'CHAT_TEMPLATE_ABSENT','This tokenizer has no declared chat template. Choose explicit plain mode or a chat checkpoint; no silent fallback.')
        # Tokenizer implementation uses its sandboxed template engine. No tools or
        # arbitrarily chosen template code are supplied by model output.
        ids=tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True)
        if hasattr(ids,'tolist'): ids=ids.tolist()
        if isinstance(ids,dict): ids=ids['input_ids']
        description=str(tokenizer.chat_template)
    else:
        require(template=='plain-transcript','TEMPLATE','Unknown template')
        text='\n\n'.join(f'{m["role"].upper()}: {m["content"]}' for m in messages)+'\n\nASSISTANT: '
        ids=tokenizer.encode(text,add_special_tokens=True)
        description='BTX/plain-transcript/v1; NOT an asserted trained chat format'
    ids=token_ids(ids,vocabulary(model),min(8192,context_limit(model)))
    return ids, {'template':template,'template_sha384':sha384(description.encode()),
                 'messages_hash':identity('BTX/NeuronLab/ConversationMessages/1',messages),
                 'input_ids_hash':identity('BTX/NeuronLab/InputTokens/1',ids), 'input_tokens':len(ids)}


def sampling_spec(spec):
    keys(spec, {'max_new_tokens','temperature_ppm','top_p_ppm','top_k','seed','logprobs'})
    integer(spec['max_new_tokens'],1,256); integer(spec['temperature_ppm'],0,2_000_000)
    integer(spec['top_p_ppm'],1,1_000_000); integer(spec['top_k'],0,1000)
    integer(spec['seed'],0,2**31-1); integer(spec['logprobs'],0,8)
    return spec


def sample(logits,spec,generator):
    z=logits.double().cpu()
    require(z.ndim==1 and torch.isfinite(z).all().item(),'LOGITS','Invalid decoder logits')
    logp=torch.log_softmax(z,-1)
    if spec['temperature_ppm']==0:
        token=int(z.argmax()); sampled_logp=None
    else:
        scores=z/(spec['temperature_ppm']/1e6)
        if spec['top_k']>0:
            threshold=torch.topk(scores,min(spec['top_k'],scores.numel())).values[-1]
            scores=scores.masked_fill(scores<threshold,-torch.inf)
        probs=torch.softmax(scores,-1)
        ordered,idx=torch.sort(probs,descending=True)
        keep=(ordered.cumsum(0)-ordered)<spec['top_p_ppm']/1e6
        ordered=ordered*keep; ordered=ordered/ordered.sum()
        selected=int(torch.multinomial(ordered,1,generator=generator)); token=int(idx[selected])
        sampled_logp=ppm(float(ordered[selected].log()))
    k=min(spec['logprobs'],logp.numel()); vals,ind=torch.topk(logp,k)
    return token,{'token':token,'model_logprob_millionths':ppm(logp[token]),
                  'sampling_logprob_millionths':sampled_logp,
                  'top':[{'token':int(i),'logprob_millionths':ppm(v)}for i,v in zip(ind,vals)]}


def decode(model,tokenizer,adapter,binding,ids,*,profile=None,tensors=None,sampling=None,
           fence=None,cancel=None,progress=None,capture=None):
    spec=sampling_spec(sampling or {'max_new_tokens':32,'temperature_ppm':0,'top_p_ppm':1_000_000,'top_k':0,'seed':0,'logprobs':5})
    ids=token_ids(ids,vocabulary(model),context_limit(model))
    require(len(ids)+spec['max_new_tokens']<=context_limit(model),'CONTEXT','Full history plus requested output exceeds context. Fork/shorten explicitly; no silent truncation.')
    generator=torch.Generator(device='cpu').manual_seed(spec['seed'])
    pid=identity('BTX/NeuronLab/Profile/1',profile) if profile else None
    namespace=cache_fingerprint(binding,pid,f'torch/{torch.__version__}',str(next(model.parameters()).dtype),
                                identity('BTX/NeuronLab/InputTokens/1',ids),'full-history-rebuild/private-turn/v2')
    output=[];records=[];start=time.perf_counter_ns();text='';finish='length'
    eos=getattr(tokenizer,'eos_token_id',None) if tokenizer is not None else None
    eos=set(eos if isinstance(eos,list) else [eos])-{None}
    with InterventionSession(model,adapter,binding,profile,tensors,capture,fence) as session,torch.inference_mode():
        tokens=torch.tensor([ids],device=device_of(model),dtype=torch.long);past=None
        for step in range(spec['max_new_tokens']):
            if cancel: require(not cancel.is_set(),'CANCELLED','Local decode cancelled')
            if fence:fence()
            use_all=past is None
            data=tokens if use_all else tokens[:,-1:]
            session.before_forward(len(ids),0 if use_all else tokens.shape[1]-1)
            result=model(input_ids=data,attention_mask=torch.ones_like(tokens),past_key_values=past,use_cache=True)
            token,record=sample(result.logits[0,-1],spec,generator)
            past=getattr(result,'past_key_values',None)
            output.append(token);records.append(record)
            tokens=torch.cat((tokens,torch.tensor([[token]],device=tokens.device)),dim=-1)
            text=' '.join(map(str,output)) if tokenizer is None else tokenizer.decode(output,skip_special_tokens=True)
            require(len(text.encode())<=65536,'OUTPUT_BUDGET','Decoded text exceeds release budget')
            if progress:
                progress({'type':'generation-token','index':step,'token':token,
                          'text':text[-8192:],'text_prefix_omitted':max(0,len(text)-8192),
                          'model_logprob_millionths':record['model_logprob_millionths'],
                          'provisional':True})
            if token in eos: finish='eos';break
        if fence:fence()
    return {'text':text,'token_ids':output,'token_scores':records,'finish_reason':finish,
            'profile_id':pid,'cache_namespace':namespace,'cache_policy':'NO_CROSS_TURN_OR_CROSS_PROFILE_REUSE',
            'sampling':spec,'elapsed_us':(time.perf_counter_ns()-start)//1000,
            'input_tokens':len(ids),'scope':'SYNTHETIC_TOKEN_MODEL' if tokenizer is None else 'LOCAL_CHECKPOINT',
            'capture':capture.result() if capture else None,'committed':False}
