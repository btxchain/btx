import copy
import pytest
import torch
from btx_neuronlab.codec import LabError
from btx_neuronlab.conversations import Conversations,scaled_profile
from btx_neuronlab.decoding import format_messages,decode,sample,sampling_spec
from btx_neuronlab.models import load_local
from btx_neuronlab.schema import operation
from conftest import draft

SAMPLE={'max_new_tokens':3,'temperature_ppm':0,'top_p_ppm':1000000,'top_k':0,'seed':4,'logprobs':3}
def call(s,a,p={},op='read'):return s.call({'action':a,'payload':p,'operation_id':op})
def setup(lab):
    s,m,_=lab;c=call(s,'create',draft(m['id'],[operation('neuron_scale',indices=[0,1],coefficient_ppm=1500000)]),'profile')
    session=call(s,'session_create',{'model_id':m['id'],'profile_id':c['id'],'title':'Three-way','template':'token-ids','system':''},'session')
    return s,m,c,session

def turn(s,d,revision=0):return {'session_id':d['id'],'expected_revision':revision,'messages':{'baseline':'1 2 3','positive':'3 2 1','negative':'2 4 6'},'dose_ppm':1000000,'sampling':SAMPLE}

def test_real_multiturn_independent_histories(lab):
    s,m,c,d=setup(lab);r=call(s,'session_turn',turn(s,d),'turn1')
    assert r['committed'] and set(r['answers'])=={'baseline','positive','negative'}
    assert len({v['cache_namespace'] for v in r['answers'].values()})==3
    p=turn(s,d,1);p['dose_ppm']=500000;r2=call(s,'session_turn',p,'turn2')
    current=call(s,'session_get',{'session_id':d['id']});assert current['revision']==2
    for a in r['answers']:
        assert r2['answers'][a]['input_tokens']==3+len(r['answers'][a]['token_ids'])+3
        assert r2['answers'][a]['cache_namespace']!=r['answers'][a]['cache_namespace']
    assert r2['answers']['baseline']['profile_id'] is None
    assert len(current['turns'])==2

def test_turn_idempotency_and_conflict(lab):
    s,_,_,d=setup(lab);p=turn(s,d);r=call(s,'session_turn',p,'same');assert call(s,'session_turn',p,'same')==r
    p=copy.deepcopy(p);p['dose_ppm']=2000000
    with pytest.raises(LabError,match='reused'):call(s,'session_turn',p,'same')
    with pytest.raises(LabError,match='changed'):call(s,'session_turn',turn(s,d),'stale')

def test_fork_before_turn_does_not_erase_original(lab):
    s,_,_,d=setup(lab);call(s,'session_turn',turn(s,d),'t1')
    fork=call(s,'session_fork',{'session_id':d['id'],'expected_revision':1,'through_turn':0,'title':'Edited branch'},'fork')
    assert fork['id']!=d['id'] and fork['turns']==[] and fork['revision']==0
    assert len(call(s,'session_get',{'session_id':d['id']})['turns'])==1
    call(s,'session_turn',turn(s,fork),'forkturn')
    assert call(s,'session_get',{'session_id':d['id']})['revision']==1

def test_revoke_during_stream_no_commit(lab):
    s,_,c,d=setup(lab);publisher=s.store.get(c['id']).publisher;events=[]
    def emit(e):
        events.append(e)
        if len(events)==1:s.store.set_trust(publisher,'local',True,'revoked-in-turn')
    with pytest.raises(LabError):Conversations(s).turn(turn(s,d),'revoked-turn',emit)
    assert any(e['type']=='generation-token'for e in events)
    assert call(s,'session_get',{'session_id':d['id']})['turns']==[]
    assert call(s,'session_operation',{'operation_id':'revoked-turn'})['status']=='FAILED'

def test_recover_running_status_and_fence(lab):
    s,_,_,d=setup(lab);cs=Conversations(s);cs._claim('lost','semantic',d['id'],0)
    with pytest.raises(LabError):cs._claim('another','semantic2',d['id'],0)
    recovered=call(s,'session_recover',{'operation_id':'lost'},'recover')
    assert recovered['status']=='INTERRUPTED' and not recovered['resend_automatically']
    with pytest.raises(LabError):cs._claim('lost','semantic',d['id'],0)
    call(s,'session_turn',turn(s,d),'new-explicit-turn')

def test_stream_records_provisional_actual_tokens(lab):
    s,_,_,d=setup(lab);events=[];r=Conversations(s).turn(turn(s,d),'stream',events.append)
    for a in ['baseline','positive','negative']:
        es=[e for e in events if e['arm']==a]
        assert [e['token'] for e in es]==r['answers'][a]['token_ids']
        assert all(e['provisional'] for e in es)
    assert not r['provisional_streams_are_retractable']

def test_unsupported_chat_template_never_falls_back(lab):
    _,_,root=lab;model,tok,ad,b=load_local(root)
    class Tokenizer:chat_template=None
    with pytest.raises(LabError,match='no declared'):format_messages([{'role':'user','content':'hi'}],Tokenizer(),model,'hf-chat')
    with pytest.raises(LabError):format_messages([{'role':'user','content':'hi'}],None,model,'plain-transcript')
    with pytest.raises(LabError):format_messages([{'role':'system','content':'1'},{'role':'user','content':'2'}],None,model,'token-ids')

def test_hf_template_explicit_and_roles(lab):
    _,_,root=lab;model,*_=load_local(root)
    class Tokenizer:
        chat_template='fixed-template'
        def apply_chat_template(self,messages,**kwargs):
            assert kwargs=={'tokenize':True,'add_generation_prompt':True};return [1,2,3]
    ids,meta=format_messages([{'role':'user','content':'hello'}],Tokenizer(),model,'hf-chat');assert ids==[1,2,3]
    with pytest.raises(LabError):format_messages([{'role':'assistant','content':'bad'},{'role':'user','content':'hi'}],Tokenizer(),model)

def test_sampling_reproducibility_and_logprobs():
    z=torch.arange(10,dtype=torch.float32);spec=dict(SAMPLE,temperature_ppm=800000,top_p_ppm=950000,top_k=5)
    a=torch.Generator().manual_seed(7);b=torch.Generator().manual_seed(7)
    aa=[sample(z,spec,a)for _ in range(10)];bb=[sample(z,spec,b)for _ in range(10)]
    assert aa==bb;assert all(t>=5 for t,_ in aa);assert all(r['model_logprob_millionths']<=0 for _,r in aa)
    with pytest.raises(LabError):sampling_spec(dict(spec,temperature_ppm=-1))

def test_bounds_and_scaling_exact(lab):
    s,_,c,d=setup(lab);cap=s.store.get(c['id']);p=scaled_profile(cap.profile,500000,True)
    assert p['operations'][0]['coefficient_ppm']==-750000
    with pytest.raises(LabError):scaled_profile(cap.profile,333333)
    p=turn(s,d);p['messages']['baseline']='1 '*600
    with pytest.raises(LabError):call(s,'session_turn',p,'overflow')
    assert call(s,'session_get',{'session_id':d['id']})['revision']==0
