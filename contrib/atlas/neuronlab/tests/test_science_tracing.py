import copy
import pytest
import torch
from btx_neuronlab.codec import LabError
from btx_neuronlab.models import load_local
from btx_neuronlab.runtime_io import forward,Hooks,weights_digest,restoration,point,metric
from btx_neuronlab.tracing import Experiment,aligned_tokens,trace_grid
from btx_neuronlab.qualification import hook_count,qualify,catalog

DESIGN={'clean_prompt':'1 2 3 4','corrupted_prompt':'4 3 2 1',
        'metric':{'kind':'logit_difference','target':5,'foil':6,'position':-1}}
def cell(layer=1,site='residual_post',token=3,units=None):return {'layer':layer,'site':site,'tokens':[token],'units':units or []}

def test_exact_final_residual_restoration(lab):
    s,m,root=lab;model,tok,ad,b=load_local(root);ex=Experiment(model,tok,ad,b,DESIGN)
    before=weights_digest(model);r=ex.scan([cell()]);row=r['cells'][0]
    assert row['metric_millionths']==r['design']['clean_metric_millionths']
    assert row['restoration_millionths']==1_000_000
    assert weights_digest(model)==before and hook_count(model)==0
    assert r['coverage']['universe_complete'] is False

@pytest.mark.parametrize('direction',['denoise','noise','zero'])
def test_directions_actual_effects(lab,direction):
    _,_,root=lab;model,tok,ad,b=load_local(root);ex=Experiment(model,tok,ad,b,dict(DESIGN,direction=direction))
    r=ex.scan([cell()]);assert len(r['cells'])==1
    if direction in {'denoise','noise'}:assert r['cells'][0]['restoration_millionths']==1_000_000
    else:assert r['cells'][0]['metric_millionths']==0 # all residual coordinates zero before biasless head

@pytest.mark.parametrize('site',['embedding','residual_pre','attention_pre_output','attention_post','mlp_post_activation','mlp_post_output','residual_post'])
def test_each_hook_actual_shape_and_cleanup(lab,site):
    _,_,root=lab;model,tok,ad,b=load_local(root);z,c=forward(model,ad,[1,2,3],capture=[(0,site)])
    assert c[0,site].shape[:2]==(1,3);assert torch.isfinite(z).all();assert hook_count(model)==0

def test_capture_cap_refuses_and_cleans(lab):
    _,_,root=lab;model,_,ad,b=load_local(root)
    with pytest.raises(LabError,match='capture'):forward(model,ad,[1,2,3],capture=[(0,'residual_post')],budget=1)
    assert hook_count(model)==0

def test_bad_shape_nonfinite_edits_cleans(lab):
    _,_,root=lab;model,_,ad,_=load_local(root)
    for edit in [lambda x:x[:,:,:1],lambda x:x*float('nan')]:
        with pytest.raises(LabError):forward(model,ad,[1,2],edits={(0,'residual_post'):edit})
        assert hook_count(model)==0

def test_model_lock_and_fence(lab):
    _,_,root=lab;model,_,ad,_=load_local(root)
    with Hooks(model,ad):
        with pytest.raises(LabError):
            with Hooks(model,ad):pass
    calls=[]
    def fence():calls.append(1);raise LabError('REVOKED','revoked')
    with pytest.raises(LabError):forward(model,ad,[1,2],fence=fence)
    assert calls and hook_count(model)==0

def test_alignment(lab):
    assert aligned_tokens([1,2],[3,4])=={0:0,1:1}
    for map_ in [None,[[0,0],[1,0]],[[3,0]],[]]:
        with pytest.raises(LabError):aligned_tokens([1,2],[3,4,5],map_)
    assert aligned_tokens([1,2],[3,4,5],[[0,0],[1,2]])=={0:0,1:2}

def test_restoration_not_clipped():
    assert restoration(3,0,1)['restoration_millionths']==3_000_000
    assert restoration(-2,0,1)['restoration_millionths']==-2_000_000
    assert restoration(2,1,1)['restoration_millionths'] is None

def test_explicit_gaussian_corruption(lab):
    _,_,root=lab;model,tok,ad,b=load_local(root)
    d=dict(DESIGN,corrupted_prompt=DESIGN['clean_prompt'],corruption={'kind':'embedding_gaussian','positions':[0,1],'std_ppm':100000,'seed':9})
    a=Experiment(model,tok,ad,b,d);q=Experiment(model,tok,ad,b,d)
    assert a.design_id==q.design_id and a.clean_score!=a.corrupt_score
    with pytest.raises(LabError):Experiment(model,tok,ad,b,dict(d,corrupted_prompt='9 2 3 4'))

def test_mediated_path_and_joint(lab):
    _,_,root=lab;model,tok,ad,b=load_local(root);ex=Experiment(model,tok,ad,b,DESIGN)
    r=ex.path(cell(0),cell(1));assert not r['exclusive_graph_path_proven']
    assert isinstance(r['effect_millionths'],int)
    j=ex.interaction(cell(0),cell(1));assert isinstance(j['interaction_millionths'],int)
    with pytest.raises(LabError):ex.path(cell(1),cell(0))
    with pytest.raises(LabError):ex.interaction(cell(0),cell(0,units=[0]))
    with pytest.raises(LabError):ex.path(cell(0),cell(1),[cell(0)])

def test_grid_and_duplicates(lab):
    _,m,_=lab;assert len(trace_grid(m['binding'],[0,1],[0,1,2]))==6
    with pytest.raises(LabError):trace_grid(m['binding'],[0],list(range(4097)))
    _,_,root=lab;mo,to,ad,b=load_local(root)
    with pytest.raises(LabError):Experiment(mo,to,ad,b,DESIGN).scan([cell(),cell()])

def test_qualification_has_scoped_evidence(lab):
    _,m,root=lab;r=qualify(root,m['binding'],'1 2 3 4')
    assert r['qualification']=='LOCAL_CHECKPOINT_PROBE_PASS'
    assert r['scope']=='SYNTHETIC_SMALL_MODEL' and not r['production_release_qualified']
    assert all(c['status']!='FAIL' for c in r['checks'])
    assert len(catalog()['items'])==14
    assert all(x['status']=='ADAPTER_SOURCE_NOT_CHECKPOINT_QUALIFICATION'for x in catalog()['items'])

def test_device_missing_does_not_pass(lab):
    _,m,root=lab
    if not torch.cuda.is_available():
        with pytest.raises(LabError,match='CUDA'):load_local(root,m['binding'],device='cuda')

def test_attention_head_coordinates_use_actual_runtime_width(lab):
    from btx_neuronlab.tracing import replacement
    _,m,_=lab;c=point({'layer':0,'site':'attention_pre_output','tokens':[1],'heads':[1]},m['binding'])
    source=torch.arange(24,dtype=torch.float32).reshape(1,2,12)
    edited=replacement(source,c,{0:0,1:1},head_count=4)(torch.zeros_like(source))
    assert torch.equal(edited[0,1,3:6],source[0,1,3:6])
    assert torch.count_nonzero(edited)==3
    with pytest.raises(LabError):point(dict(c,units=[1]),m['binding'])
    with pytest.raises(LabError):point(dict(c,site='residual_post'),m['binding'])
    with pytest.raises(LabError):replacement(source,c,{0:0,1:1},head_count=5)

def test_actual_attention_head_restoration(lab):
    _,_,root=lab;model,tok,ad,b=load_local(root);ex=Experiment(model,tok,ad,b,DESIGN)
    result=ex.scan([{'layer':1,'site':'attention_pre_output','tokens':[3],'heads':[0],'units':[]}])
    assert isinstance(result['cells'][0]['effect_millionths'],int)
