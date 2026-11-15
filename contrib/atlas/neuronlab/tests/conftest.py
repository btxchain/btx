from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import pytest
import torch
from btx_neuronlab.service import Service
from btx_neuronlab.tiny import TinyLM
from btx_neuronlab.schema import unknown_recipe,operation

torch.set_num_threads(1)

@pytest.fixture
def lab(tmp_path):
    torch.manual_seed(6)
    root=tmp_path/'model';TinyLM().save(root)
    s=Service(tmp_path/'store')
    s.call({'action':'initialize','payload':{},'operation_id':'init'})
    model=s.call({'action':'register','payload':{'path':str(root)},'operation_id':'register'})
    yield s,model,root
    s.close()

def draft(mid,ops=None,tensors=None,privacy='public'):
    return {'model_id':mid,'title':'Local research profile','description':'Test of checkpoint-bound interventions',
        'operations':ops or [operation()], 'tensors':tensors or {}, 'training_recipe':unknown_recipe(),
        'privacy':privacy,'license':'MIT for test capsule only','claims':[],'parent_profiles':[]}
