import copy
import numpy as np
import pytest
import torch
from btx_neuronlab.codec import LabError
from btx_neuronlab.schema import operation
from btx_neuronlab.operators import apply_site,InterventionSession,Capture,cache_fingerprint
from btx_neuronlab.models import load_local
from btx_neuronlab.engine import generate,extract_direction
from conftest import draft

def apply(x,ops,tensors=None):return apply_site(x,ops,tensors or {},torch.arange(x.shape[1]),2,2,maximum_delta_ratio=20)

def test_neuron_add_and_nonmutation():
    x=torch.ones(1,4,4);y=apply(x,[operation('neuron_add',indices=[2],coefficient_ppm=500000)])
    assert torch.all(y[...,2]==1.5);assert torch.all(x==1)

def test_scale_baseline_zero_and_negative():
    x=torch.ones(1,3,4)
    for ppm,expected in [(0,0),(1000000,1),(-2000000,-2)]:
        assert torch.all(apply(x,[operation('neuron_scale',indices=[0],coefficient_ppm=ppm)])[...,0]==expected)

def test_phase_and_token_masks():
    x=torch.ones(1,4,4)
    o=operation('neuron_scale',indices=[0],coefficient_ppm=0,phase='decode',token_start=3)
    y=apply(x,[o]);assert y[0,:,0].tolist()==[1,1,1,0]
    o['phase']='prefill';o['token_start']=0;y=apply(x,[o]);assert y[0,:,0].tolist()==[0,0,1,1]

def test_calibration_units():
    o=operation('neuron_add',indices=[1],coefficient_ppm=500000,normalization='residual_median_downcol',
        calibration={'corpus_hash':'0'*96,'capture_hash':'1'*96,'residual_median_millionths':4_000_000,'down_column_norms_millionths':[2_000_000]})
    assert torch.all(apply(torch.ones(1,2,4),[o])[...,1]==2)

def test_paper_residual_norm_uses_original_not_cascading():
    x=torch.tensor([[[3.,4.,0.,0.]]]);v=torch.tensor([0.,0.,1.,0.])
    o=operation('residual_add',indices=[],coefficient_ppm=200000,tensor='d',normalization='token_l2')
    y=apply(x,[o,dict(o,id='two')],{'d':v});assert y[0,0,2].item()==pytest.approx(2)

def test_head_scale():
    y=apply(torch.ones(1,2,4),[operation('head_scale',indices=[1],coefficient_ppm=0)])
    assert y[0,0].tolist()==[1,1,0,0]

def test_projection_removal():
    x=torch.tensor([[[3.,4.,1.,1.]]]);o=operation('residual_project_out',indices=[],coefficient_ppm=1000000,tensor='d')
    y=apply(x,[o],{'d':torch.tensor([1.,0.,0.,0.])});assert y[0,0].tolist()==[0,4,1,1]

def test_clamp():
    x=torch.ones(1,2,4)*3;o=operation('neuron_clamp',indices=[0],bounds_ppm=[-1_000_000,1_000_000])
    assert torch.all(apply(x,[o])[...,0]==1)

def test_sae_error_preserving_feature_add():
    x=torch.ones(1,2,4);o=operation('sae_feature_add',indices=[],coefficient_ppm=500000,sae={'encoder':'e','decoder':'d','bias':'b','feature':0})
    y=apply(x,[o],{'e':torch.eye(4),'d':torch.eye(4),'b':torch.zeros(4)})
    assert y[0,0].tolist()==[1.5,1,1,1]

def test_operator_order_noncommutes():
    x=torch.ones(1,2,4);a=operation('neuron_add',indices=[0],coefficient_ppm=1_000_000);s=operation('neuron_scale',indices=[0],coefficient_ppm=2_000_000)
    assert not torch.equal(apply(x,[a,s]),apply(x,[s,a]))

def test_nonfinite_and_budget():
    with pytest.raises(LabError):apply(torch.full((1,2,4),float('nan')),[operation()])
    with pytest.raises(LabError):apply_site(torch.zeros(1,2,4),[operation('neuron_add',coefficient_ppm=8000000)],{},torch.arange(2),2,2)

def test_session_cleanup_on_error(lab):
    s,m,root=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'c'});c=s.store.get(r['id'])
    model,_,ad,b=load_local(root)
    with pytest.raises(RuntimeError):
        with InterventionSession(model,ad,b,c.profile,c.tensors) as sess:
            sess.before_forward(3,0)
            assert len(model.blocks[0].mlp.down_proj._forward_pre_hooks)==1
            raise RuntimeError('deliberate')
    assert len(model.blocks[0].mlp.down_proj._forward_pre_hooks)==0
    with InterventionSession(model,ad,b):pass

def test_model_training_mode_not_allowed(lab):
    _,_,root=lab;model,_,ad,b=load_local(root);model.train()
    with pytest.raises(LabError):
        with InterventionSession(model,ad,b):pass

def test_real_captures_change_weights_unchanged(lab):
    s,m,root=lab;r=s.call({'action':'create','payload':draft(m['id'],[operation('neuron_scale',indices=[0,1,2],coefficient_ppm=0)]),'operation_id':'c'});cap=s.store.get(r['id'])
    model,tok,ad,b=load_local(root);before={k:v.clone()for k,v in model.state_dict().items()};c=Capture([0],[0,1,2])
    result=generate(model,tok,ad,b,'1 2 3',profile=cap.profile,tensors=cap.tensors,max_new_tokens=3,capture=c)
    assert result['generated'];assert all(torch.equal(before[k],v)for k,v in model.state_dict().items())
    post=[r for r in c.records if r['site']=='mlp_post_activation'and r['stage']=='post'];assert post and all(r['value_millionths']==0 for r in post)
    pre=[r for r in c.records if r['site']=='mlp_post_activation'and r['stage']=='pre'];assert any(r['value_millionths']!=0 for r in pre)

def test_revocation_before_release_and_cleanup(lab):
    _,_,root=lab;model,tok,ad,b=load_local(root);calls=0
    def fence():
        nonlocal calls;calls+=1
        if calls>=4:raise LabError('REVOKED','test')
    with pytest.raises(LabError):generate(model,tok,ad,b,'1 2',max_new_tokens=4,fence=fence,capture=Capture())
    assert len(model.blocks[0].mlp.down_proj._forward_pre_hooks)==0

def test_direction_extraction_and_degenerate():
    a=np.array([[1.,0.,0.],[1.,.1,0.]]);b=np.zeros((2,3));v,meta=extract_direction(a,b)
    assert np.linalg.norm(v)==pytest.approx(1,abs=1e-6)
    with pytest.raises(LabError):extract_direction(b,b)

def test_cache_namespaces(lab):
    _,m,_=lab;b=m['binding'];a=cache_fingerprint(b,'1'*96,'torch','fp32','0'*96,'both');c=cache_fingerprint(b,'2'*96,'torch','fp32','0'*96,'both')
    assert a!=c
