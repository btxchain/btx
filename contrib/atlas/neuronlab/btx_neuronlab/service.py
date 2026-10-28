"""Bounded private-stdio service used by the native Atlas broker and CLI."""
from __future__ import annotations
import copy
import os
import time
import uuid
from pathlib import Path
from .codec import require, keys, text, digest_text, canonical, loads, identity, sha384, read_file, atomic_write, LabError
from .crypto import MLDSA44
from .capsule import Capsule, encode, tensor_records, MAX_CAPSULE
from .schema import validate_profile, unknown_recipe, validate_recipe
from .store import Store, model_key_for
from .science import SCIENCE_ACTIONS, SCIENCE_READS

READ_ACTIONS={'status','list','models','profile','events','receipts','binding','router_preview'}
ACTIONS=READ_ACTIONS|{'initialize','register','create','import','export','trust','revoke','activate','deactivate',
                    'compare','generate','direction','lens','publish_plan','import_checkout','study_plan','study_run',
                    'evaluate','save_router','run_router','import_evidence'}

READ_ACTIONS |= SCIENCE_READS
ACTIONS |= SCIENCE_ACTIONS

class Service:
    def __init__(self, root, progress=None):
        self.progress = progress
        self.store=Store(Path(root));self.root=self.store.root
        self.key=self.root/'publisher.pem'
    def close(self):self.store.close()
    def _model(self,model_id):
        digest_text(model_id)
        row=self.store.db.execute('SELECT * FROM models WHERE id=?',(model_id,)).fetchone()
        require(row is not None,'MODEL','Register the local model directory first')
        return dict(row)|{'binding':loads(row['binding_json']),'recipe':loads(row['recipe_json'])}
    def _publisher(self):
        require(self.key.exists(),'IDENTITY','Initialize a local research identity first')
        pub=self.store.crypto.public_key(self.key)
        return sha384(b'BTX/NeuronLab/Publisher/1\0'+pub)
    def _check_trust(self,cap):
        require(self.store.trust_status(cap.publisher)=='LOCALLY_TRUSTED_PUBLISHER','REVOKED_OR_UNTRUSTED','Profile publisher is not locally trusted')
    def _receipt(self,kind,body):
        record={'schema':'btx.neuronlab.evidence/1','kind':kind,'body':body,'created_ms':int(time.time()*1000)}
        rid=identity('BTX/NeuronLab/Evidence/1',record)
        signature=self.store.crypto.sign(record,self.key,kind='evidence')
        envelope={'id':rid,'record':record,'signature':signature}
        atomic_write(self.root/'evidence'/f'{rid}.json',canonical(envelope))
        return envelope
    def call(self,request):
        keys(request,{'action','payload','operation_id'})
        a=request['action'];p=request['payload'];op_id=request['operation_id']
        require(a in ACTIONS,'ACTION','Unknown NeuronLab action')
        require(type(p)is dict,'PAYLOAD','Payload must be an object')
        text(op_id,96)
        if a in SCIENCE_ACTIONS:
            from .science import dispatch
            return dispatch(self,a,p,op_id,self.progress)
        if a=='status':
            keys(p,set())
            return {'schema':'btx.neuronlab.status/1','version':'0.2.0','publisher':self._publisher()if self.key.exists()else None,
              'crypto':'ML-DSA-44','wallet_access':False,'network_access':'NONE_IN_WORKER',
              'native_identity_binding':'SEPARATE_RESEARCH_KEY_NOT_AUTOMATIC_PIT_ROOT',
              'runtime':'torch; optional offline transformers','architectures':__import__('btx_neuronlab.models',fromlist=['ALLOWED']).ALLOWED,
              'qualification':'SOURCE_CANDIDATE; consult shipped execution reports',
              'active_profiles':[dict(r) for r in self.store.db.execute('SELECT model_key,profile_id,generation,enabled FROM activations WHERE enabled=1 LIMIT 64')],
              'journal':self.store.verify_journal()}
        if a=='initialize':
            keys(p,set())
            if not self.key.exists():self.store.crypto.generate(self.key)
            publisher=self._publisher()
            return self.store.set_trust(publisher,'local-owner',False,op_id)
        if a=='models':
            keys(p,set())
            return {'items':[{'id':r['id'],'binding':loads(r['binding_json']),'recipe':loads(r['recipe_json'])}for r in self.store.db.execute('SELECT * FROM models ORDER BY id LIMIT 100')]}
        if a=='register':
            keys(p,{'path'},{'btx_model_id'})
            from .models import model_binding
            root=Path(p['path']).absolute();binding,c=model_binding(root,p.get('btx_model_id'))
            mid=model_key_for(binding);recipe=unknown_recipe()
            def act():
                self.store.db.execute('INSERT INTO models VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET path=excluded.path', (mid,str(root),canonical(binding).decode(),canonical(recipe).decode()))
                self.store._event('LOCAL_MODEL_REGISTERED',{'model_id':mid})
                return {'id':mid,'binding':binding,'training_recipe':recipe,'configuration_declarations':{
                    k:(str(c[k]) if type(c[k]) is float else c[k]) for k in ['activation_function','hidden_act','resid_pdrop','attn_pdrop','embd_pdrop','dropout_ppm'] if k in c},
                    'warning':'Configuration declarations are not proof of historical training settings'}
            return self.store.mutate(op_id,{'kind':'register','id':mid,'root':str(root)},act)
        if a=='binding':
            keys(p,{'model_id'})
            return {k:v for k,v in self._model(p['model_id']).items()if k in {'id','binding','recipe'}}
        if a=='list':
            keys(p,set(),{'limit','after'})
            return self.store.list(p.get('limit',100),p.get('after',''))
        if a=='profile':
            keys(p,{'profile_id'},{'include_tensors'})
            cap=self.store.get(p['profile_id'])
            result={'summary':cap.summary(),'profile':cap.profile,'trust':self.store.trust_status(cap.publisher)}
            if p.get('include_tensors',False):
                require(p['include_tensors'] is True,'SCHEMA','include_tensors must be true')
                require(sum(t.size for t in cap.tensors.values())<=65536,'EDIT_TENSOR_LIMIT','Use the offline capsule API for larger tensors; graphical editing is bounded to 65,536 coefficients')
                result['editable_tensors']={k:v.tolist() for k,v in cap.tensors.items() if k!='btx_capsule_marker'}
            return result
        if a=='create':
            keys(p,{'model_id','title','description','operations','tensors','training_recipe','privacy','license','claims','parent_profiles'})
            model=self._model(p['model_id']);validate_recipe(p['training_recipe'])
            profile={'schema':'btx.neuronlab.profile/1','title':p['title'],'description':p['description'],
                'binding':model['binding'],'training_recipe':p['training_recipe'],'operations':p['operations'],
                'parent_profiles':p['parent_profiles'],'privacy':p['privacy'],'license':p['license'],'claims':p['claims'],
                'created_ms':int(time.time()*1000),'composition':'ordered/pre-site-norm/v1','tensors':{}}
            self._publisher()
            records,_=tensor_records(p['tensors'])
            semantic={'kind':'create','payload':dict(p,tensors=records)}
            def act():
                raw=encode(profile,p['tensors'],self.store.crypto,self.key)
                cap=Capsule(raw,self.store.crypto)
                old=self.store.db.execute('SELECT publisher FROM capsules WHERE id=?',(cap.id,)).fetchone()
                if old:
                    require(old['publisher']==cap.publisher,'PUBLISHER_CONFLICT','Profile publisher conflict')
                else:
                    atomic_write(self.root/'capsules'/f'{cap.id}.safetensors',raw)
                    self.store.db.execute('INSERT INTO capsules VALUES(?,?,?,?,?)',(cap.id,cap.publisher,cap.bytes_hash,cap.profile['title'],int(time.time()*1000)))
                    self.store._event('PROFILE_AUTHORED_NOT_ACTIVATED',{'profile':cap.id,'publisher':cap.publisher})
                return {'id':cap.id,'signature_valid':True,'activation':'NOT_AUTHORIZED','trust':self.store.trust_status(cap.publisher)}
            return self.store.mutate(op_id,semantic,act)
        if a=='import':
            keys(p,{'path'})
            return self.store.import_capsule(read_file(Path(p['path']),MAX_CAPSULE),op_id)
        if a=='export':
            keys(p,{'profile_id','path'})
            cap=self.store.get(p['profile_id'])
            atomic_write(Path(p['path']),cap.raw,replace=False)
            return {'id':cap.id,'bytes':len(cap.raw),'sha384':cap.bytes_hash,'saved':True}
        if a in {'trust','revoke'}:
            keys(p,{'publisher','domain_label'})
            return self.store.set_trust(p['publisher'],p['domain_label'],a=='revoke',op_id)
        if a=='activate':
            keys(p,{'profile_id','model_id','expected_generation'})
            from .models import model_binding
            m=self._model(p['model_id']);b,_=model_binding(Path(m['path']),m['binding']['btx_model_id'])
            return self.store.activate(p['profile_id'],b,op_id,p['expected_generation'])
        if a=='deactivate':
            keys(p,{'model_id'})
            return self.store.deactivate(p['model_id'],op_id)
        if a=='compare':
            keys(p,{'profile_id','model_id','prompt','max_new_tokens','layer','units'})
            from .engine import compare
            cap=self.store.get(p['profile_id']);self._check_trust(cap);m=self._model(p['model_id'])
            result=compare(m['path'],cap,p['prompt'],max_new_tokens=p['max_new_tokens'],selected_layer=p['layer'],selected_units=p['units'],fence=lambda:self._check_trust(cap))
            self._check_trust(cap)
            # Prompt is not exported. Captures/output remain a private local receipt.
            receipt=self._receipt('local-counterfactual-comparison',result)
            return {'receipt_id':receipt['id'],**result,'publication':'PRIVATE_BY_DEFAULT'}
        if a=='generate':
            keys(p,{'profile_id','model_id','prompt','max_new_tokens'})
            from .models import load_local
            from .engine import generate
            cap=self.store.get(p['profile_id']);self._check_trust(cap);m=self._model(p['model_id'])
            model,tok,adapter,b=load_local(Path(m['path']),m['binding'])
            return generate(model,tok,adapter,b,p['prompt'],profile=cap.profile,tensors=cap.tensors,max_new_tokens=p['max_new_tokens'],fence=lambda:self._check_trust(cap))
        if a=='direction':
            keys(p,{'positive','reference'},{'neutral','variance_ppm'})
            from .engine import extract_direction
            vector,meta=extract_direction(p['positive'],p['reference'],neutral=p.get('neutral'),variance_ppm=p.get('variance_ppm',500000))
            receipt=self._receipt('direction-extraction',meta)
            return {'vector':vector.tolist(),'provenance':meta,'receipt_id':receipt['id'],'weight_mutation':False}
        if a=='lens':
            keys(p,{'model_id','layer','unit'})
            from .models import load_local
            from .engine import down_projection_lens
            m=self._model(p['model_id']);model,_,adapter,b=load_local(Path(m['path']),m['binding'])
            return down_projection_lens(adapter,p['layer'],p['unit'],adapter.output_weight())
        if a=='publish_plan':
            keys(p,{'profile_id'})
            from .transport import publish_plan
            return publish_plan(self.store,p['profile_id'])
        if a=='import_checkout':
            keys(p,{'path','profile_id'})
            from .transport import import_checkout
            return import_checkout(self.store,Path(p['path']),p['profile_id'],op_id)
        if a=='study_plan':
            keys(p,set(),{'seeds','dropouts_ppm','activations','weight_decay_ppm','optimizers','steps','data_seed'})
            from .study import plan
            result=plan(**p)
            atomic_write(self.root/'studies'/f"{result['study_id']}.json",canonical(result))
            return result
        if a=='study_run':
            keys(p,{'work'})
            from .study import execute
            require(type(p['work'])is dict and 'id'in p['work'],'WORK','Work unit required');digest_text(p['work']['id'])
            result=execute(p['work'],self.root/'studies'/p['work']['id'],maximum_steps=200)
            receipt=self._receipt('training-recipe-study',result)
            return {'receipt_id':receipt['id'],**result}
        if a=='evaluate':
            keys(p,{'rows','suite_hash','profile_id'},{'trial_budget','alpha_ppm','resamples','seed'})
            from .evidence import paired_evaluation
            result=paired_evaluation(**p)
            receipt=self._receipt('paired-evaluation',result)
            return {'receipt_id':receipt['id'],**result}
        if a=='events':
            keys(p,set(),{'after','limit'})
            return self.store.events(p.get('after',0),p.get('limit',100))
        if a=='receipts':
            keys(p,set(),{'id'})
            if 'id'in p:
                digest_text(p['id'])
                return loads(read_file(self.root/'evidence'/f"{p['id']}.json",1_048_576))
            names=sorted(self.root.joinpath('evidence').glob('*.json'))
            return {'ids':[f.stem for f in names[:100]],'omitted':max(0,len(names)-100)}
        if a=='import_evidence':
            keys(p,{'path'})
            e=loads(read_file(Path(p['path']),1_048_576));keys(e,{'id','record','signature'})
            require(identity('BTX/NeuronLab/Evidence/1',e['record'])==e['id'],'EVIDENCE_ID','Evidence ID mismatch')
            pub=self.store.crypto.verify(e['record'],e['signature'],kind='evidence')
            atomic_write(self.root/'evidence'/f"{e['id']}.json",canonical(e))
            return {'id':e['id'],'publisher':pub,'signature_valid':True,'independent_evaluation':'NOT_ESTABLISHED'}
        if a=='save_router':
            keys(p,{'policy'})
            from .router import validate_router
            policy=validate_router(p['policy']);rid=identity('BTX/NeuronLab/Router/1',policy)
            for route in policy['routes']:self._check_trust(self.store.get(route['profile_id']))
            atomic_write(self.root/'routers'/f'{rid}.json',canonical(policy))
            return {'id':rid,'installed_locally':True,'automatic_application':False}
        if a=='router_preview':
            keys(p,{'policy','features_ppm'},{'previous','switches'})
            from .router import choose
            approved=set()
            for r in p['policy'].get('routes',[]):
                try:
                    self._check_trust(self.store.get(r['profile_id']));approved.add(r['profile_id'])
                except LabError:pass
            return choose(p['policy'],p['features_ppm'],approved,previous=p.get('previous'),switches=p.get('switches',0))
        if a=='run_router':
            keys(p,{'router_id','features_ppm','model_id','prompt','max_new_tokens'})
            from .router import choose
            digest_text(p['router_id']);policy=loads(read_file(self.root/'routers'/f"{p['router_id']}.json",1_048_576))
            require(identity('BTX/NeuronLab/Router/1',policy)==p['router_id'],'ROUTER_ID','Router changed')
            approved=set()
            for r in policy['routes']:
                try:self._check_trust(self.store.get(r['profile_id']));approved.add(r['profile_id'])
                except LabError:pass
            decision=choose(policy,p['features_ppm'],approved)
            from .models import load_local
            from .engine import generate
            m=self._model(p['model_id']);model,tok,adapter,b=load_local(Path(m['path']),m['binding'])
            cap=self.store.get(decision['profile_id'])if decision['profile_id']else None
            answer=generate(model,tok,adapter,b,p['prompt'],profile=cap.profile if cap else None,tensors=cap.tensors if cap else None,
                max_new_tokens=p['max_new_tokens'],fence=(lambda:self._check_trust(cap))if cap else None)
            return {'decision':decision,'answer':answer,'authority_change':False}
        raise LabError('ACTION','Action has no implementation')
