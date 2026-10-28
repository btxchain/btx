#!/usr/bin/env python3
"""Execute an operator-authored local checkpoint matrix. Missing engines remain NOT_RUN.

No downloads. No architecture name is promoted to a qualification. Fails exit 2
when any requested row does not pass. A pass is a local numerical probe only.
"""
from pathlib import Path
import argparse,json,sys,uuid
p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--store',type=Path,required=True);p.add_argument('--matrix',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
sys.path.insert(0,str(a.source))
from btx_neuronlab.codec import loads,keys,require,read_file,LabError,identity
from btx_neuronlab.service import Service
matrix=loads(read_file(a.matrix,1048576));keys(matrix,{'schema','checkpoints'})
require(matrix['schema']=='btx.neuronlab.local-qualification-matrix/1' and type(matrix['checkpoints'])is list and 1<=len(matrix['checkpoints'])<=64,'MATRIX','1..64 explicit checkpoints required')
s=Service(a.store)
def call(action,payload):return s.call({'action':action,'payload':payload,'operation_id':str(uuid.uuid4())})
call('initialize',{});results=[]
try:
 for row in matrix['checkpoints']:
  keys(row,{'path','architecture','prompt','device','expected_weights_hash'},{'tolerance_ppm'})
  try:
   m=call('register',{'path':row['path']})
   require(m['binding']['architecture']==row['architecture'],'ARCHITECTURE','Actual model does not match matrix architecture')
   require(m['binding']['weights_hash']==row['expected_weights_hash'],'WEIGHTS','Actual bytes differ from the pinned matrix checkpoint')
   result=call('model_qualify',{'model_id':m['id'],'prompt':row['prompt'],'device':row['device'],'tolerance_ppm':row.get('tolerance_ppm',10)})
  except LabError as e:result={'qualification':'NOT_RUN' if e.code in {'MODEL_PATH','FILE','ENGINE_ABSENT','DEVICE'}else'FAIL','error':e.as_dict()}
  results.append({'requested_architecture':row['architecture'],'requested_weights_hash':row['expected_weights_hash'],'result':result})
 body={'schema':'btx.neuronlab.local-qualification-matrix-result/1','matrix_id':identity('BTX/NeuronLab/QualificationMatrix/1',matrix),'rows':results,'physical_hosts':1,'independent_release_qualification':False}
 a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(body,indent=2)+'\n')
 print(json.dumps({'report':str(a.out),'passed':sum(x['result'].get('qualification')=='LOCAL_CHECKPOINT_PROBE_PASS'for x in results),'requested':len(results)}))
finally:s.close()
raise SystemExit(0 if all(x['result'].get('qualification')=='LOCAL_CHECKPOINT_PROBE_PASS'for x in results)else 2)
