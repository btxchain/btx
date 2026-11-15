import copy,json,struct
import numpy as np
import pytest
from btx_neuronlab.codec import *
from btx_neuronlab.capsule import Capsule,encode
from btx_neuronlab.crypto import MLDSA44
from btx_neuronlab.schema import *
from conftest import draft

@pytest.mark.parametrize('raw',['{"x":1,"x":2}','{"x":1,"\\u0078":2}','[NaN]','[Infinity]','[1e400]','{"a": 1.1}','[true,1e1000]'])
def test_signed_json_rejections(raw):
    with pytest.raises(LabError):loads(raw)

@pytest.mark.parametrize('value',[{'x':'e\u0301'},{'x':2**65},{'x':float('nan')},{'x':'\ud800'}])
def test_canonical_rejections(value):
    with pytest.raises(LabError):canonical(value)

def test_order_and_domain():
    assert canonical({'b':1,'a':2})==canonical({'a':2,'b':1})
    assert identity('a',{'x':1})!=identity('b',{'x':1})

def test_schema_fact_caveat():
    r=unknown_recipe();r['facts']['optimizer']['value']='adamw'
    with pytest.raises(LabError):validate_recipe(r)
    r['facts']['optimizer']={'status':'reported','value':'adamw','source':'author metadata, not independently attested'}
    validate_recipe(r)

def test_real_mldsa_capsule(lab):
    s,m,_=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'create'})
    c=s.store.get(r['id']);assert len(c.signature['signature'])>3000
    assert c.summary()['behavioral_safety']=='NOT_ESTABLISHED_BY_SIGNATURE'
    assert c.profile['tensors']['btx_capsule_marker']['shape']==[1]
    from safetensors.numpy import load
    assert load(c.raw)['btx_capsule_marker'][0]==1
    assert s.store.active(m['binding']) is None

def test_payload_tamper(lab):
    s,m,_=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'c'})
    raw=bytearray(s.store.get(r['id']).raw);raw[-1]^=1
    with pytest.raises(LabError):Capsule(bytes(raw),s.store.crypto)

def test_metadata_tamper(lab):
    s,m,_=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'c'})
    c=s.store.get(r['id']);raw=c.raw.replace(b'Local research profile',b'Other research profile')
    with pytest.raises(LabError):Capsule(raw,s.store.crypto)

def test_signature_domains(lab):
    s,_,_=lab;record={'schema':'example','n':1}
    sig=s.store.crypto.sign(record,s.key,kind='evidence')
    assert s.store.crypto.verify(record,sig,kind='evidence')==sig['publisher']
    with pytest.raises(LabError):s.store.crypto.verify(record,sig)

def test_f32_directions_and_float_semantic_idempotency(lab):
    s,m,_=lab;v=np.zeros(m['binding']['hidden_size']);v[0]=1
    p=draft(m['id'],[operation('residual_add',indices=[],coefficient_ppm=200000,tensor='direction',normalization='token_l2')],{'direction':v.tolist()})
    a=s.call({'action':'create','payload':p,'operation_id':'vector'});b=s.call({'action':'create','payload':p,'operation_id':'vector'})
    assert a==b;assert s.store.get(a['id']).tensors['direction'][0]==1

def test_bad_vector_norm(lab):
    s,m,_=lab;v=[0.0]*m['binding']['hidden_size']
    p=draft(m['id'],[operation('residual_add',indices=[],tensor='direction')],{'direction':v})
    with pytest.raises(LabError):s.call({'action':'create','payload':p,'operation_id':'bad'})

def test_no_code_field(lab):
    s,m,_=lab;p=draft(m['id']);p['operations'][0]['python']='print(1)'
    with pytest.raises(LabError):s.call({'action':'create','payload':p,'operation_id':'badcode'})

def test_archive_offset_and_trailer(lab):
    s,m,_=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'c'});raw=s.store.get(r['id']).raw
    with pytest.raises(LabError):Capsule(raw+b'X',s.store.crypto)
    with pytest.raises(LabError):Capsule(struct.pack('<Q',2**60)+raw[8:],s.store.crypto)

def test_license_and_semantic_hypothesis(lab):
    s,m,_=lab;p=draft(m['id']);p['claims']=[{'label':'one neuron definitely controls honesty','status':'universal','evidence_refs':[]}]
    with pytest.raises(LabError):s.call({'action':'create','payload':p,'operation_id':'claim'})

@pytest.mark.parametrize('field',['weights_hash','config_hash','tokenizer_hash','activation','adapter','representation'])
def test_exact_compatibility_rejects_shape_only(lab,field):
    s,m,_=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'c'});p=s.store.get(r['id']).profile
    b=copy.deepcopy(m['binding']);b[field]='f'*96 if 'hash'in field else 'changed'
    assert not compatibility(p,b)['compatible']
