from pathlib import Path
import json
import subprocess
import sys
import copy
import pytest
from btx_neuronlab.codec import LabError
from btx_neuronlab.schema import operation
from btx_neuronlab.models import load_local
from conftest import draft
from test_science_tracing import DESIGN,cell
from test_science_conversations import call

def test_service_trace_resume_and_evidence(lab):
    s,m,_=lab;p=call(s,'trace_plan',{'model_id':m['id'],'design':DESIGN,'cells':[cell(0),cell(1)]},'plan')
    assert p['count']==2
    before=call(s,'trace_get',{'plan_id':p['id']});assert all(x['status']=='NOT_RUN' for x in before['items'])
    r=call(s,'trace_chunk',{'plan_id':p['id'],'offset':0,'count':1},'run0');assert r['completed']==1
    again=call(s,'trace_chunk',{'plan_id':p['id'],'offset':0,'count':1},'resume');assert again['items']==r['items']
    r=call(s,'trace_chunk',{'plan_id':p['id'],'offset':1,'count':1},'run1');assert r['complete']
    assert all(x['receipt_id']for x in call(s,'trace_get',{'plan_id':p['id']})['items'])

def test_service_path_joint_and_activation(lab):
    s,m,_=lab
    for action in ['trace_path','trace_interaction']:
        r=call(s,action,{'model_id':m['id'],'design':DESIGN,'a':cell(0),'b':cell(1)},action);assert len(r['receipt_id'])==96
    r=call(s,'activation_scan',{'model_id':m['id'],'prompt':'1 2 3 4','layers':[0,1],'topk':4},'fire')
    assert len(r['rows'])==8 and len(r['token_ids'])==4
    assert r['monosemanticity_measured'] is False
    c=call(s,'connection_cone',{'model_id':m['id'],'layer':0,'unit':0},'cone');assert c['edges'] and c['causal'] is False
    lens=call(s,'lens',{'model_id':m['id'],'layer':0,'unit':0},'lens');assert lens

def test_sweep_plan_resume_and_real_lens(lab):
    s,m,_=lab;c=call(s,'create',draft(m['id'],[operation('neuron_scale',indices=[0],coefficient_ppm=1500000)]),'create')
    p=call(s,'sweep_plan',{'model_id':m['id'],'profile_id':c['id'],'prompts':['1 2 3','3 2 1'],'doses_ppm':[0,500000,1000000]},'sweep')
    assert p['count']==6
    r=call(s,'sweep_chunk',{'plan_id':p['id'],'offset':0,'count':6},'sweep-run');assert r['complete']
    again=call(s,'sweep_chunk',{'plan_id':p['id'],'offset':0,'count':6},'sweep-resume');assert r==again
    assert all(row['lens']['kind'].startswith('MEASURED_')for row in r['items'])

def test_actual_capture_projection_and_annotation(lab):
    s,m,_=lab;r=call(s,'embeddings_capture',{'model_id':m['id'],'prompts':['1 2 3','4 5 6'],'layer':0,'site':'residual_post','pooling':'tokens','method':'pca','seed':1,'title':'Measured activations'},'capture')
    assert r['rows']==6 and r['provenance']['scope']=='MEASURED_MODEL_ACTIVATIONS'
    a=call(s,'annotation_set',{'model_id':m['id'],'layer':0,'site':'mlp_post_activation','unit':0,'label':'Hypothesis','note':'Not a demonstrated semantic feature'},'label')
    assert a['epistemic_status']=='HUMAN_HYPOTHESIS_NOT_VERIFIED_FEATURE'
    assert call(s,'annotation_get',{'model_id':m['id']})['items']==[a]

def test_qualification_service_not_a_release(lab):
    s,m,_=lab;r=call(s,'model_qualify',{'model_id':m['id'],'prompt':'1 2 3 4'},'q')
    assert r['qualification']=='LOCAL_CHECKPOINT_PROBE_PASS'
    assert not r['production_release_qualified']
    assert call(s,'qualification_list',{'model_id':m['id']})['items'][0]['receipt_id']==r['receipt_id']
    q=call(s,'model_qualify',{'model_id':m['id'],'prompt':'1 2 3 4','device':'cuda'},'qcuda')
    if q['qualification']=='NOT_RUN':assert q['error']['code']=='DEVICE'

def test_strict_science_fields(lab):
    s,m,_=lab
    for action in ['adapter_catalog','embeddings_list','session_list']:
        with pytest.raises(LabError):call(s,action,{'shell':'exec'})
    with pytest.raises(LabError):call(s,'embeddings_page',{'dataset_id':'../../etc/passwd'})
    with pytest.raises(LabError):call(s,'trace_plan',{'model_id':m['id'],'design':DESIGN,'cells':[cell(),cell()]},'dupe')

def test_stdio_stream_actual_frames(lab):
    s,m,_=lab
    p=Path(__file__).resolve().parents[1]/'worker.py'
    req={'action':'model_qualify','payload':{'model_id':m['id'],'prompt':'1 2 3 4'},'operation_id':'frame-test'}
    proc=subprocess.run([sys.executable,'-B',str(p),'--store',str(s.root),'--stream'],input=json.dumps(req)+'\n',text=True,capture_output=True,timeout=25)
    assert proc.returncode==0,proc.stderr
    rows=[json.loads(x)for x in proc.stdout.splitlines()]
    assert len(rows)>3 and rows[-1]['ok'] is True
    assert rows[-1]['result']['qualification']=='LOCAL_CHECKPOINT_PROBE_PASS'
    assert all(r['operation_id']=='frame-test' and r['event']['type']=='qualification-progress'for r in rows[:-1])
