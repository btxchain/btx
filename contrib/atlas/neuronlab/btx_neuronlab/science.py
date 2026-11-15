"""Versioned Atlas scientific workbench API, using the existing private worker.

Execution stays local. Plans/figures/receipts are not model activation authority,
financial mandates, or native BTX swarm scheduling records.
"""
from __future__ import annotations
import copy
from pathlib import Path
import tempfile
import numpy as np
from .codec import (keys,require,integer,text,digest_text,canonical,loads,identity,
                    read_file,atomic_write,LabError)
from .models import load_local
from .conversations import Conversations,scaled_profile
from .embeddings import Embeddings
from .tracing import Experiment

SCIENCE_READS={'adapter_catalog','embeddings_list','embeddings_page','session_list','session_get',
               'session_operation','trace_get','qualification_list','annotation_get','sweep_get'}
SCIENCE_COMPUTE={'embeddings_import','embeddings_capture','embeddings_neighbors','session_turn',
                 'trace_chunk','trace_path','trace_interaction','model_qualify','activation_scan',
                 'measured_lens','connection_cone','sweep_chunk'}
SCIENCE_ACTIONS=SCIENCE_READS|SCIENCE_COMPUTE|{'session_create','session_fork','session_recover',
                    'trace_plan','annotation_set','sweep_plan'}


def initialize(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS science_plans(id TEXT PRIMARY KEY,kind TEXT NOT NULL,body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS science_results(plan_id TEXT NOT NULL,cell_id TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(plan_id,cell_id));
    CREATE TABLE IF NOT EXISTS science_qualifications(id TEXT PRIMARY KEY,model_id TEXT NOT NULL,body TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS science_annotations(coordinate TEXT PRIMARY KEY,body TEXT NOT NULL);
    ''')


def plan_get(s,plan_id,kind):
    digest_text(plan_id);row=s.store.db.execute('SELECT kind,body FROM science_plans WHERE id=?',(plan_id,)).fetchone()
    require(row is not None and row['kind']==kind,'PLAN','Unknown scientific work plan')
    plan=loads(row['body'])
    require(identity('BTX/NeuronLab/ScientificPlan/2',plan)==plan_id,'PLAN_CHANGED','Scientific plan changed')
    return plan


def model(s,model_id,device='cpu'):
    m=s._model(model_id)
    return load_local(Path(m['path']),m['binding'],device=device)


def scientific_fence(s,cap):
    s._check_trust(cap)
    row=s.store.db.execute('SELECT sequence FROM trust WHERE publisher=?',(cap.publisher,)).fetchone();sequence=row[0]
    def check():
        s._check_trust(cap)
        now=s.store.db.execute('SELECT sequence FROM trust WHERE publisher=?',(cap.publisher,)).fetchone()
        require(now is not None and now[0]==sequence,'TRUST_CHANGED','Trust changed during this experiment')
    return check


def save_plan(s,kind,body,opid):
    pid=identity('BTX/NeuronLab/ScientificPlan/2',body)
    def act():
        s.store.db.execute('INSERT OR IGNORE INTO science_plans VALUES(?,?,?)',(pid,kind,canonical(body).decode()))
        s.store._event('SCIENTIFIC_PLAN_RECORDED',{'id':pid,'kind':kind,'local_only':True})
        return {'id':pid,'count':len(body['cells']),'privacy':'PRIVATE_LOCAL_PLAN','independent_preregistration':False}
    return s.store.mutate(opid,{'kind':'science-plan','id':pid},act)


def dispatch(s,a,p,opid,progress=None):
    initialize(s.store.db)
    if a.startswith('session_'):
        sessions=Conversations(s)
        if a=='session_create':return sessions.create(p,opid)
        if a=='session_fork':return sessions.fork(p,opid)
        if a=='session_turn':return sessions.turn(p,opid,progress)
        if a=='session_recover':return sessions.recover(p,opid)
        if a=='session_list':keys(p,set());return sessions.list()
        if a=='session_get':keys(p,{'session_id'});return sessions.get(p['session_id'])
        if a=='session_operation':
            keys(p,{'operation_id'});text(p['operation_id'],96)
            r=s.store.db.execute('SELECT status,result FROM science_turns WHERE operation_id=?',(p['operation_id'],)).fetchone()
            require(r is not None,'OPERATION','Unknown turn operation')
            return {'status':r['status'],'result':loads(r['result'])if r['result']else None,'automatic_retry':False}
    if a=='adapter_catalog':
        keys(p,set());from .qualification import catalog
        return catalog()
    if a=='model_qualify':
        keys(p,{'model_id','prompt'},{'device','tolerance_ppm'})
        from .qualification import qualify
        m=s._model(p['model_id']);s._publisher()
        try:result=qualify(Path(m['path']),m['binding'],p['prompt'],device=p.get('device','cpu'),tolerance_ppm=p.get('tolerance_ppm',10),progress=progress)
        except LabError as e:
            result={'schema':'btx.neuronlab.qualification/2','binding':m['binding'],
                    'qualification':'NOT_RUN' if e.code in {'ENGINE_ABSENT','DEVICE'}else 'FAIL',
                    'error':e.as_dict(),'production_release_qualified':False}
        receipt=s._receipt('checkpoint-qualification',result)
        s.store.db.execute('INSERT OR REPLACE INTO science_qualifications VALUES(?,?,?)',
                            (receipt['id'],m['id'],canonical(result).decode()))
        return {'receipt_id':receipt['id'],**result}
    if a=='qualification_list':
        keys(p,set(),{'model_id'})
        if 'model_id'in p:digest_text(p['model_id'])
        rows=s.store.db.execute('SELECT * FROM science_qualifications WHERE (? IS NULL OR model_id=?) ORDER BY rowid DESC LIMIT 100',(p.get('model_id'),p.get('model_id'))).fetchall()
        return {'items':[{'receipt_id':r['id'],'model_id':r['model_id'],**loads(r['body'])}for r in rows]}
    if a.startswith('embeddings_'):
        e=Embeddings(s.root)
        if a=='embeddings_list':keys(p,set());return e.list()
        if a=='embeddings_page':
            keys(p,{'dataset_id'},{'offset','limit','stride'});return e.page(p['dataset_id'],p.get('offset',0),p.get('limit',4096),p.get('stride',1))
        if a=='embeddings_neighbors':
            keys(p,{'dataset_id','row'},{'k','metric'});return e.neighbors(p['dataset_id'],p['row'],p.get('k',16),p.get('metric','cosine'),progress)
        if a=='embeddings_import':
            keys(p,{'path','title','method','seed'});s._publisher()
            result=e.build(Path(p['path']),title=p['title'],method=p['method'],seed=p['seed'],progress=progress)
            receipt=s._receipt('embedding-projection',result);return {'receipt_id':receipt['id'],**result}
        if a=='embeddings_capture':
            keys(p,{'model_id','prompts','layer','site','pooling','method','seed','title'})
            from .inspection import extract_rows
            mod,tok,adapter,b=model(s,p['model_id']);s._publisher()
            vectors,groups,source=extract_rows(mod,tok,adapter,b,p['prompts'],p['layer'],p['site'],p['pooling'])
            with tempfile.TemporaryDirectory(prefix='.capture-',dir=s.root) as d:
                path=Path(d)/'capture.npy';np.save(path,vectors,allow_pickle=False)
                result=e.build(path,title=p['title'],method=p['method'],seed=p['seed'],groups=groups,provenance=source,progress=progress)
            receipt=s._receipt('model-representation-projection',result);return {'receipt_id':receipt['id'],**result}
    if a=='trace_plan':
        keys(p,{'model_id','design','cells'})
        from .runtime_io import point
        m=s._model(p['model_id'])
        require(type(p['cells'])is list and 1<=len(p['cells'])<=4096,'PLAN_BUDGET','Trace plans contain 1..4096 explicit cells')
        cells=[point(c,m['binding'])for c in p['cells']]
        require(len({identity('BTX/NeuronLab/CausalCell/1',c)for c in cells})==len(cells),'DUPLICATE_CELL','Duplicate trace cells')
        # Design remains exact and is fully validated before any model is executed.
        keys(p['design'],{'clean_prompt','corrupted_prompt','metric'},{'alignment','corruption','direction'})
        return save_plan(s,'trace',{'kind':'trace','model_id':m['id'],'binding':m['binding'],'design':p['design'],'cells':cells},opid)
    if a=='trace_chunk':
        keys(p,{'plan_id','offset','count'})
        plan=plan_get(s,p['plan_id'],'trace');integer(p['offset'],0,len(plan['cells'])-1);integer(p['count'],1,64)
        cells=plan['cells'][p['offset']:p['offset']+p['count']]
        pending=[c for c in cells if not s.store.db.execute('SELECT 1 FROM science_results WHERE plan_id=? AND cell_id=?',
            (p['plan_id'],identity('BTX/NeuronLab/CausalCell/1',c))).fetchone()]
        if pending:
            mod,tok,adapter,b=model(s,plan['model_id']);s._publisher()
            require(b==plan['binding'],'MODEL_CHANGED','Recreate trace plan for the changed model')
            ex=Experiment(mod,tok,adapter,b,plan['design']);result=ex.scan(pending,progress)
            receipt=s._receipt('causal-trace-chunk',{'plan_id':p['plan_id'],**result})
            with s.store.db:
                for row in result['cells']:
                    s.store.db.execute('INSERT OR IGNORE INTO science_results VALUES(?,?,?)',(p['plan_id'],row['cell_id'],canonical(dict(row,receipt_id=receipt['id'])).decode()))
        return dispatch(s,'trace_get',{'plan_id':p['plan_id'],'offset':p['offset'],'limit':p['count']},opid,progress)
    if a in {'trace_get','sweep_get'}:
        keys(p,{'plan_id'},{'offset','limit'})
        kind='trace' if a=='trace_get'else'sweep';plan=plan_get(s,p['plan_id'],kind)
        offset=integer(p.get('offset',0),0,len(plan['cells']));limit=integer(p.get('limit',64),1,256)
        rows=[]
        for c in plan['cells'][offset:offset+limit]:
            cid=identity('BTX/NeuronLab/CausalCell/1',c) if kind=='trace'else c['id']
            r=s.store.db.execute('SELECT body FROM science_results WHERE plan_id=? AND cell_id=?',(p['plan_id'],cid)).fetchone()
            rows.append(loads(r['body']) if r else {'cell':c,'cell_id':cid,'status':'NOT_RUN'})
        done=s.store.db.execute('SELECT COUNT(*) FROM science_results WHERE plan_id=?',(p['plan_id'],)).fetchone()[0]
        return {'plan_id':p['plan_id'],'items':rows,'completed':done,'planned':len(plan['cells']),
                'complete':done==len(plan['cells']),'next_offset':offset+limit if offset+limit<len(plan['cells'])else None,
                'scope':'ONLY_THE_DECLARED_PLAN_NOT_A_COMPLETE_MODEL_EXPLANATION'}
    if a in {'trace_path','trace_interaction'}:
        keys(p,{'model_id','design','a','b'},{'frozen'})
        mod,tok,adapter,b=model(s,p['model_id']);s._publisher();ex=Experiment(mod,tok,adapter,b,p['design'])
        result=ex.path(p['a'],p['b'],p.get('frozen'))if a=='trace_path'else ex.interaction(p['a'],p['b'])
        receipt=s._receipt(a,result);return {'receipt_id':receipt['id'],**result}
    if a=='activation_scan':
        keys(p,{'model_id','prompt','layers'},{'topk'})
        from .inspection import fire_scan
        mod,tok,adapter,b=model(s,p['model_id']);s._publisher()
        result=fire_scan(mod,tok,adapter,b,p['prompt'],p['layers'],p.get('topk',32))
        receipt=s._receipt('live-activation-scan',result);return {'receipt_id':receipt['id'],**result}
    if a=='connection_cone':
        keys(p,{'model_id','layer','unit'},{'depth','topk'})
        from .inspection import connection_cone
        mod,tok,adapter,b=model(s,p['model_id'])
        return connection_cone(adapter,b,p['layer'],p['unit'],depth=p.get('depth',3),topk=p.get('topk',8))
    if a=='measured_lens':
        keys(p,{'model_id','profile_id','prompt'},{'topk'})
        from .inspection import steering_lens
        cap=s.store.get(p['profile_id']);fence=scientific_fence(s,cap);s._publisher()
        mod,tok,adapter,b=model(s,p['model_id'])
        result=steering_lens(mod,tok,adapter,b,p['prompt'],cap.profile,cap.tensors,p.get('topk',24),fence)
        fence();receipt=s._receipt('measured-steer-lens',result);return {'receipt_id':receipt['id'],**result}
    if a=='annotation_set':
        keys(p,{'model_id','layer','site','unit','label','note'})
        m=s._model(p['model_id']);integer(p['layer'],0,m['binding']['layers']-1);integer(p['unit'],0,131071)
        require(p['site']in {'mlp_post_activation','residual_post','attention_pre_output'},'SITE','Unknown annotation site')
        text(p['label'],96);text(p['note'],2048)
        key=identity('BTX/NeuronLab/Coordinate/2',{k:p[k]for k in ['model_id','layer','site','unit']})
        d={**p,'epistemic_status':'HUMAN_HYPOTHESIS_NOT_VERIFIED_FEATURE','coordinate_id':key}
        def act():
            s.store.db.execute('INSERT OR REPLACE INTO science_annotations VALUES(?,?)',(key,canonical(d).decode()));return d
        return s.store.mutate(opid,{'kind':'annotation','body':d},act)
    if a=='annotation_get':
        keys(p,{'model_id'});digest_text(p['model_id'])
        rows=s.store.db.execute('SELECT body FROM science_annotations ORDER BY coordinate LIMIT 4096').fetchall()
        return {'items':[d for r in rows if (d:=loads(r[0]))['model_id']==p['model_id']]}
    if a=='sweep_plan':
        keys(p,{'model_id','profile_id','prompts','doses_ppm'})
        m=s._model(p['model_id']);cap=s.store.get(p['profile_id']);s._check_trust(cap)
        require(type(p['prompts'])is list and 1<=len(p['prompts'])<=64,'PROMPTS','Sweep prompts capped at 64')
        for prompt in p['prompts']:require(type(prompt)is str and 0<len(prompt.encode())<=8192,'PROMPT','Invalid sweep prompt')
        require(type(p['doses_ppm'])is list and 1<=len(p['doses_ppm'])<=16,'DOSES','At most 16 declared doses')
        for dose in p['doses_ppm']:integer(dose,0,4_000_000)
        require(len(set(p['doses_ppm']))==len(p['doses_ppm']),'DOSES','Duplicate doses refused')
        cells=[]
        for i,prompt in enumerate(p['prompts']):
            for dose in p['doses_ppm']:
                c={'prompt_index':i,'prompt':prompt,'dose_ppm':dose};c['id']=identity('BTX/NeuronLab/SweepCell/2',c);cells.append(c)
        return save_plan(s,'sweep',{'kind':'sweep','model_id':m['id'],'binding':m['binding'],'profile_id':cap.id,'cells':cells},opid)
    if a=='sweep_chunk':
        keys(p,{'plan_id','offset','count'})
        plan=plan_get(s,p['plan_id'],'sweep');integer(p['offset'],0,len(plan['cells'])-1);integer(p['count'],1,16)
        cap=s.store.get(plan['profile_id']);fence=scientific_fence(s,cap);s._publisher()
        mod,tok,adapter,b=model(s,plan['model_id']);require(b==plan['binding'],'MODEL_CHANGED','Sweep model changed')
        from .inspection import steering_lens
        for c in plan['cells'][p['offset']:p['offset']+p['count']]:
            if s.store.db.execute('SELECT 1 FROM science_results WHERE plan_id=? AND cell_id=?',(p['plan_id'],c['id'])).fetchone():continue
            prof=scaled_profile(cap.profile,c['dose_ppm'])
            lens=steering_lens(mod,tok,adapter,b,c['prompt'],prof,cap.tensors,8,fence)
            body={'cell_id':c['id'],'prompt_index':c['prompt_index'],'dose_ppm':c['dose_ppm'],'lens':lens}
            receipt=s._receipt('dose-sweep-cell',body);fence()
            s.store.db.execute('INSERT OR IGNORE INTO science_results VALUES(?,?,?)',(p['plan_id'],c['id'],canonical(dict(body,receipt_id=receipt['id'])).decode()))
        return dispatch(s,'sweep_get',{'plan_id':p['plan_id'],'offset':p['offset'],'limit':p['count']},opid,progress)
    raise LabError('SCIENCE_ACTION','Unknown scientific command')
