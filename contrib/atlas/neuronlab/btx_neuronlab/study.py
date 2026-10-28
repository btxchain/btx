"""Factorial training-recipe studies, sharded as immutable work descriptions.

This trains actual small transformers. It does not infer modern-LLM behavior from
these toy results, nor claim that model configuration proves historical training.
"""
from __future__ import annotations
import itertools
import time
import platform
from pathlib import Path
import numpy as np
import torch
import torch.nn.functional as F
from .codec import require, keys, integer, identity, canonical, atomic_write
from .tiny import TinyLM
from .evidence import representation_metrics
from .schema import unknown_recipe


def plan(*, seeds=(0,1,2), dropouts_ppm=(0,100000), activations=('gelu','silu'),
         weight_decay_ppm=(0,100000), optimizers=('adamw',), steps=40, data_seed=1107):
    integer(steps,1,10000);integer(data_seed,0,2**31-1)
    require(1<=len(seeds)<=32 and 1<=len(dropouts_ppm)<=8 and 1<=len(weight_decay_ppm)<=8,'PLAN','Factor budget exceeded')
    require(all(type(x)is int and 0<=x<2**31 for x in seeds),'SEED','Invalid seed')
    for d in dropouts_ppm:integer(d,0,700000)
    for w in weight_decay_ppm:integer(w,0,1000000)
    require(set(activations)<={'gelu','silu'} and set(optimizers)<={'adamw','sgd'},'FACTOR','Unknown factor')
    base={'schema':'btx.neuronlab.study/1','seeds':list(seeds),'dropouts_ppm':list(dropouts_ppm),
          'activations':list(activations),'weight_decay_ppm':list(weight_decay_ppm),'optimizers':list(optimizers),
          'steps':steps,'data_seed':data_seed,'task':'synthetic-modular-language/v1','width':24,'layers':2,'heads':4,
          'comparison_scope':'EXPLORATORY_SMALL_MODEL_ONLY','architecture_matching':'approximately_parameter_matched_not_identical_compute'}
    study_id=identity('BTX/NeuronLab/Study/1',base)
    units=[]
    for seed,drop,act,wd,opt in itertools.product(seeds,dropouts_ppm,activations,weight_decay_ppm,optimizers):
        unit={'study_id':study_id,'seed':seed,'dropout_ppm':drop,'activation':act,'weight_decay_ppm':wd,
              'optimizer':opt,'steps':steps,'data_seed':data_seed,'width':24,'layers':2,'heads':4,'task':base['task']}
        units.append({'id':identity('BTX/NeuronLab/StudyUnit/1',unit),'unit':unit})
    require(len(units)<=512,'PLAN','At most 512 sharded units')
    return {'study_id':study_id,'plan':base,'work_units':units,'automatic_execution':False,'automatic_spend':False}


def _dataset(seed,n=256,length=17,vocab=32):
    g=torch.Generator().manual_seed(seed)
    start=torch.randint(vocab,(n,1),generator=g)
    step=torch.randint(1,5,(n,1),generator=g)
    return (start+step*torch.arange(length)[None])%vocab


def execute(work, output:Path, *, maximum_steps=1000):
    keys(work,{'id','unit'})
    require(identity('BTX/NeuronLab/StudyUnit/1',work['unit'])==work['id'],'WORK_ID','Study unit modified')
    u=work['unit']
    keys(u,{'study_id','seed','dropout_ppm','activation','weight_decay_ppm','optimizer','steps','data_seed','width','layers','heads','task'})
    require(u['task']=='synthetic-modular-language/v1' and u['width']==24 and u['layers']==2 and u['heads']==4,'STUDY_SCOPE','Unknown execution recipe')
    integer(u['steps'],1,maximum_steps);integer(u['dropout_ppm'],0,700000);integer(u['weight_decay_ppm'],0,1000000)
    require(u['activation'] in {'gelu','silu'} and u['optimizer'] in {'adamw','sgd'},'STUDY_SCOPE','Unknown model factor')
    output.mkdir(parents=True,exist_ok=True,mode=0o700)
    started=time.perf_counter_ns()
    # Dedicated data generator and identical data order across model factors.
    train=_dataset(u['data_seed']);heldout=_dataset(u['data_seed']+1,n=64)
    old_threads=torch.get_num_threads()
    try:
        torch.set_num_threads(1)
        with torch.random.fork_rng(devices=[]):
            torch.manual_seed(u['seed'])
            intermediate=96 if u['activation']=='gelu' else 64
            model=TinyLM(intermediate=intermediate,activation=u['activation'],dropout=u['dropout_ppm']/1e6)
            opt=(torch.optim.AdamW(model.parameters(),lr=0.003,weight_decay=u['weight_decay_ppm']/1e6) if u['optimizer']=='adamw'
                 else torch.optim.SGD(model.parameters(),lr=0.03,weight_decay=u['weight_decay_ppm']/1e6))
            model.train();losses=[]
            for step in range(u['steps']):
                start=(step*16)%len(train);batch=train[start:start+16]
                opt.zero_grad(set_to_none=True)
                logits=model(batch[:,:-1]).logits
                loss=F.cross_entropy(logits.reshape(-1,32),batch[:,1:].reshape(-1))
                require(torch.isfinite(loss).item(),'TRAINING_NONFINITE','Training diverged')
                loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),1.0);opt.step()
                losses.append(round(float(loss.detach())*1e6))
            model.eval();captured=[]
            handle=model.blocks[0].mlp.down_proj.register_forward_pre_hook(lambda m,a:captured.append(a[0].detach().cpu()))
            try:
                with torch.no_grad():
                    logits=model(heldout[:,:-1]).logits
                    loss=F.cross_entropy(logits.reshape(-1,32),heldout[:,1:].reshape(-1))
                    accuracy=(logits.argmax(-1)==heldout[:,1:]).float().mean()
            finally:handle.remove()
            # Labels are synthetic token modulo classes, not human semantic concepts.
            acts=captured[0].numpy().reshape(-1,intermediate)
            labels=(heldout[:,:-1].numpy().reshape(-1)%4)
            metrics=representation_metrics(acts,labels)
            model.save(output/'model')
            from .models import model_binding
            binding,_=model_binding(output/'model')
    finally:torch.set_num_threads(old_threads)
    recipe=unknown_recipe()
    for name,value in {'pretraining_dropout':{'all_sites_ppm':u['dropout_ppm']},'optimizer':u['optimizer'],
          'weight_decay':{'millionths':u['weight_decay_ppm']},'activation':u['activation'],
          'training_tokens':u['steps']*16*16,'training_data':{'generator':u['task'],'seed':u['data_seed']},
          'normalization':'LayerNorm','post_training':'none','finetuning_dropout':'not_applicable'}.items():
        recipe['facts'][name]={'status':'measured_in_this_study','value':value,'source':work['id']}
    report={'schema':'btx.neuronlab.study-result/1','work_id':work['id'],'study_id':u['study_id'],
       'factors':u,'binding':binding,'training_recipe':recipe,'training_loss_millionths':losses,
       'heldout_loss_millionths':round(float(loss)*1e6),'heldout_accuracy_ppm':round(float(accuracy)*1e6),
       'parameters':sum(p.numel() for p in model.parameters()),'metrics':metrics,
       'runtime':{'torch':str(torch.__version__),'device':'cpu','platform':platform.system(),'physical_hosts_observed':1},
       'elapsed_us':(time.perf_counter_ns()-started)//1000,
       'limits':['synthetic task','small model','no pretrained-LLM transfer claim','approximately matched parameters','rank is not superposition','no independent evaluator qualification']}
    atomic_write(output/'result.json',canonical(report))
    return report


def aggregate(reports):
    seen=set();rows=[]
    for r in reports:
        require(r['work_id'] not in seen,'DUPLICATE_WORK','Duplicate replication cannot inflate study size')
        seen.add(r['work_id'])
        rows.append({'work_id':r['work_id'],**r['factors'],'loss_millionths':r['heldout_loss_millionths'],
                     'accuracy_ppm':r['heldout_accuracy_ppm'],'parameters':r['parameters'],
                     'rank_millionths':r['metrics']['participation_ratio_millionths']})
    require(len({r['study_id']for r in rows})<=1,'STUDY_MISMATCH','Cannot pool distinct preregistered study designs')
    return {'rows':rows,'scope':'EXPLORATORY_FACTORIAL_DESCRIPTIVE_TABLE','universal_claims':False}
