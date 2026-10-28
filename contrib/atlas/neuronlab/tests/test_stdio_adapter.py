"""Actual private-process tests; not an actual BTX node or physical-network test."""
from pathlib import Path
import json,os,subprocess,sys
import numpy as np
from btx_neuronlab.schema import operation
from conftest import draft
ROOT=Path(__file__).resolve().parents[1]

def process(action,payload,store,operation_id='test'):
    cp=subprocess.run([sys.executable,'-I','-B',str(ROOT/'worker.py'),'--store',str(store)],
       input=json.dumps({'action':action,'payload':payload,'operation_id':operation_id})+'\n',
       capture_output=True,text=True,timeout=30)
    return json.loads(cp.stdout)

def test_worker_unknown_action_fails_closed(tmp_path):
    r=process('execute_shell',{'command':'echo forbidden'},tmp_path/'worker')
    assert not r['ok'] and r['error']['code']=='ACTION'

def test_two_private_processes_import_verify_not_activate(lab,tmp_path):
    s,m,_=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'c'})
    cap=s.store.get(r['id']);path=tmp_path/'transfer.safetensors';path.write_bytes(cap.raw)
    other=tmp_path/'receiver'
    one=process('import',{'path':str(path)},other)
    assert one['ok'] and one['result']['trust']=='UNTRUSTED'
    two=process('profile',{'profile_id':r['id']},other)
    assert two['ok'] and two['result']['summary']['id']==r['id']
    status=process('status',{},other)
    assert status['ok'] and status['result']['active_profiles']==[]

def test_generate_adapter_uses_explicit_local_activation(lab):
    s,m,root=lab;r=s.call({'action':'create','payload':draft(m['id']),'operation_id':'c'})
    s.call({'action':'activate','payload':{'model_id':m['id'],'profile_id':r['id'],'expected_generation':0},'operation_id':'activate'})
    cp=subprocess.run([sys.executable,'-I','-B',str(ROOT/'generate_adapter.py'),'--dir',str(root),'--max-new-tokens','3'],
      input='{"prompt":"1 2 3","max_new_tokens":3}\n',capture_output=True,text=True,timeout=30,
      env={**os.environ,'BTX_NEURONLAB_STORE':str(s.root),'OMP_NUM_THREADS':'1'})
    result=json.loads(cp.stdout)
    assert cp.returncode==0 and result['ok'] and result['profile_id']==r['id']
    assert not result['weight_mutation'] and not result['remote_inference']

def test_vector_fork_roundtrips_bound_tensors(lab):
    s,m,_=lab;v=np.zeros(m['binding']['hidden_size'],dtype=np.float32);v[0]=1
    o=operation('residual_add',indices=[],coefficient_ppm=100000,normalization='token_l2',tensor='direction')
    d=draft(m['id'],[o],{'direction':v.tolist()});r=s.call({'action':'create','payload':d,'operation_id':'v'})
    p=s.call({'action':'profile','payload':{'profile_id':r['id'],'include_tensors':True},'operation_id':'read'})
    assert p['editable_tensors']['direction']==v.tolist()
    d.update(tensors=p['editable_tensors'],title='Forked profile',parent_profiles=[r['id']])
    q=s.call({'action':'create','payload':d,'operation_id':'fork'})
    assert q['id']!=r['id'] and s.store.get(q['id']).profile['parent_profiles']==[r['id']]

def test_model_config_change_refuses_registered_binding(lab):
    from btx_neuronlab.models import load_local
    from btx_neuronlab.codec import LabError
    import pytest
    s,m,root=lab;c=json.loads((root/'config.json').read_text());c['experimental_note']='changed'
    (root/'config.json').write_text(json.dumps(c))
    with pytest.raises(LabError):load_local(root,m['binding'])

def test_direction_receipt_binds_numeric_capture_sources(lab):
    s,_,_=lab
    d=s.call({'action':'direction','payload':{'positive':[[1.,0.,0.],[1.,.1,0.]],'reference':[[0.,0.,0.],[0.,0.,0.]]},'operation_id':'direction'})
    assert len(d['provenance']['positive_capture_hash'])==96
    receipt=s.call({'action':'receipts','payload':{'id':d['receipt_id']},'operation_id':'read-evidence'})
    assert s.store.crypto.verify(receipt['record'],receipt['signature'],kind='evidence')==s._publisher()
