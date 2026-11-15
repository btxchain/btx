import copy
from pathlib import Path
import pytest
import numpy as np
from btx_neuronlab.codec import LabError,canonical,loads
from btx_neuronlab.store import Store,model_key_for
from btx_neuronlab.transport import publish_plan,acquire_plan,ChunkReceiver,import_checkout
from btx_neuronlab.evidence import paired_evaluation,bh_adjust,deduplicate_attestations
from btx_neuronlab.study import plan,execute,aggregate
from btx_neuronlab.router import choose
from conftest import draft

def make(lab,privacy='public'):
    s,m,_=lab;r=s.call({'action':'create','payload':draft(m['id'],privacy=privacy),'operation_id':'c'})
    return s,m,s.store.get(r['id'])

def test_activation_revoke_and_fence(lab):
    s,m,c=make(lab);r=s.store.activate(c.id,m['binding'],'a',0)
    s.store.check_fence(c.id,m['binding'],r['generation'])
    s.store.set_trust(c.publisher,'local',True,'r')
    assert s.store.active(m['binding']) is None
    with pytest.raises(LabError):s.store.check_fence(c.id,m['binding'],r['generation'])

def test_activation_stale_generation(lab):
    s,m,c=make(lab);s.store.activate(c.id,m['binding'],'a',0)
    with pytest.raises(LabError):s.store.activate(c.id,m['binding'],'b',0)

def test_idempotency_semantics(lab):
    s,m,c=make(lab);a=s.store.activate(c.id,m['binding'],'a',0);b=s.store.activate(c.id,m['binding'],'a',0);assert a==b
    with pytest.raises(LabError):s.store.deactivate(model_key_for(m['binding']),'a')

def test_origin_id_not_execution_identity(lab):
    _,m,_=lab;b=copy.deepcopy(m['binding']);b['btx_model_id']='different-origin-reference'
    assert model_key_for(b)==model_key_for(m['binding'])

def test_second_store_import_never_activates(lab,tmp_path):
    s,m,c=make(lab);r=Store(tmp_path/'receiver')
    try:
        got=r.import_capsule(c.raw,'recv');assert got['trust']=='UNTRUSTED';assert r.active(m['binding'])is None
        with pytest.raises(LabError):r.activate(c.id,m['binding'],'attempt',0)
        r.set_trust(c.publisher,'operator-labelled-not-proved-independent',False,'trust');r.activate(c.id,m['binding'],'ok',0)
        assert r.active(m['binding'])[0].id==c.id
    finally:r.close()

def test_journal_tamper(lab):
    s,_,_=lab;s.store.verify_journal();s.store.db.execute("UPDATE events SET hash=? WHERE seq=1",('f'*96,))
    with pytest.raises(LabError):s.store.verify_journal()

def test_private_publication_denied(lab):
    s,_,c=make(lab,'private')
    with pytest.raises(LabError):publish_plan(s.store,c.id)

def test_public_native_plan(lab):
    s,_,c=make(lab);p=publish_plan(s.store,c.id)
    assert p['method']=='hostmodel';assert p['params'][1]=={'pin':True,'publish':False};assert not p['automatic_activation']

@pytest.mark.parametrize('uri',['https://example.com/a','btx://abc?method=send','btx://abc#secret','btx://abc\n'])
def test_resource_uri_rejections(uri):
    with pytest.raises(LabError):acquire_plan(uri)

def test_chunk_transfer(lab,tmp_path):
    _,m,c=make(lab);r=Store(tmp_path/'receiver')
    try:
        rx=ChunkReceiver(len(c.raw),c.bytes_hash)
        with pytest.raises(LabError):rx.add(1,c.raw[:5])
        for offset in range(0,len(c.raw),113):rx.add(offset,c.raw[offset:offset+113])
        result=rx.finish(r,c.id,'received');assert result['id']==c.id;assert r.active(m['binding'])is None
    finally:r.close()

def test_wrong_checkout_profile(lab,tmp_path):
    s,_,c=make(lab);d=tmp_path/'checkout';d.mkdir();(d/'intervention.safetensors').write_bytes(c.raw)
    with pytest.raises(LabError):import_checkout(s.store,d,'f'*96,'wrong')

def test_statistics_duplicates_and_clusters():
    rows=[{'task_id':str(i),'seed':0,'baseline_success':False,'candidate_success':i%2==0}for i in range(8)]
    r=paired_evaluation(rows,suite_hash='0'*96,profile_id='1'*96,resamples=100)
    assert r['pairs']==8 and r['task_clusters']==8 and r['mean_delta_ppm']==500000
    with pytest.raises(LabError):paired_evaluation(rows+[rows[0]],suite_hash='0'*96,profile_id='1'*96,resamples=100)
    g=deduplicate_attestations([r,r]);assert g[0]['statistical_sample_sets']==1 and g[0]['attestations']==2

def test_bh_monotonic():
    adjusted=bh_adjust([.01,.02,.2,.8]);assert adjusted==sorted(adjusted);assert all(a>=p for a,p in zip(adjusted,[.01,.02,.2,.8]))

def test_sharded_study_and_real_training(tmp_path):
    p=plan(seeds=(1,),dropouts_ppm=(0,),activations=('silu',),weight_decay_ppm=(0,),steps=2)
    r=execute(p['work_units'][0],tmp_path/'run',maximum_steps=4)
    assert r['heldout_loss_millionths']>0;assert (tmp_path/'run/model/model.safetensors').exists()
    assert r['training_recipe']['facts']['pretraining_dropout']['status']=='measured_in_this_study'
    assert aggregate([r])['universal_claims']is False
    with pytest.raises(LabError):aggregate([r,r])

def test_route_is_approved_and_bounded():
    profile='1'*96;p={'schema':'btx.neuronlab.router/1','features':['progress'],
      'routes':[{'profile_id':profile,'weights_ppm':[1000000],'bias_ppm':0}],
      'fallback':'baseline','minimum_margin_ppm':100,'max_switches':1,'policy_epoch':1}
    assert choose(p,{'progress':500000},set())['profile_id']is None
    assert choose(p,{'progress':500000},{profile})['profile_id']==profile
    assert choose(p,{'progress':500000},{profile},switches=1)['profile_id']is None
    assert not choose(p,{'progress':500000},{profile})['grants_added']
