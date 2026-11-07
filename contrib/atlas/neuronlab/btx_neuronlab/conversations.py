"""Durable three-arm conversations. Claims/CAS protect parallel or stale requests.

No model-authored text is an action. Live token events are provisional and cannot
be recalled from a user's memory; only complete fenced turns enter the history.
"""
from __future__ import annotations
import copy
import time
from .codec import require, keys, integer, text, digest_text, canonical, loads, identity, LabError
from .models import load_local
from .schema import compatibility, validate_profile
from .decoding import decode, format_messages, sampling_spec

ARMS=('baseline','positive','negative')


def scaled_profile(profile,scale,negative=False):
    integer(scale,0,4_000_000,'dose multiplier')
    p=copy.deepcopy(profile)
    for op in p['operations']:
        if op['kind']!='neuron_clamp':
            n=op['coefficient_ppm']*scale
            require(n%1_000_000==0,'DOSE_PRECISION','Dose product cannot be represented exactly in millionths')
            op['coefficient_ppm']=(n//1_000_000)*(-1 if negative else 1)
    validate_profile(p);return p


class Conversations:
    def __init__(self,service):
        self.s=service;self.db=service.store.db
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS science_sessions(id TEXT PRIMARY KEY,revision INTEGER NOT NULL,document TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS science_turns(operation_id TEXT PRIMARY KEY,semantic TEXT NOT NULL,session_id TEXT NOT NULL,status TEXT NOT NULL,result TEXT);
        CREATE UNIQUE INDEX IF NOT EXISTS science_one_running ON science_turns(session_id) WHERE status='RUNNING';
        ''')
    def get(self,sid):
        digest_text(sid);row=self.db.execute('SELECT document FROM science_sessions WHERE id=?',(sid,)).fetchone()
        require(row is not None,'SESSION','Unknown scientific session');return loads(row[0])
    def list(self):
        rows=self.db.execute('SELECT id,revision,document FROM science_sessions ORDER BY rowid DESC LIMIT 100').fetchall()
        return {'items':[{'id':r['id'],'revision':r['revision'],'title':loads(r['document'])['title'],
                          'turn_count':len(loads(r['document'])['turns'])}for r in rows]}
    def create(self,p,opid):
        keys(p,{'model_id','profile_id','title','template','system'})
        text(p['title'],160);require(p['template'] in {'hf-chat','plain-transcript','token-ids'},'TEMPLATE','Invalid transcript mode')
        require(type(p['system'])is str and len(p['system'].encode())<=8192,'HISTORY','Bounded system text required')
        require(p['template']!='token-ids' or not p['system'],'TEMPLATE','Token-ID model has no system-role semantics')
        m=self.s._model(p['model_id']);cap=self.s.store.get(p['profile_id']);self.s._check_trust(cap)
        require(compatibility(cap.profile,m['binding'])['compatible'],'INCOMPATIBLE','Profile must match exact registered checkpoint')
        sid=identity('BTX/NeuronLab/Session/2',{'operation_id':opid,'request':p})
        def act():
            d={'schema':'btx.neuronlab.conversation/2','id':sid,'revision':0,'title':p['title'],
               'model_id':p['model_id'],'profile_id':p['profile_id'],'binding':m['binding'],
               'template':p['template'],'system':p['system'],'turns':[],
               'parent':None,'privacy':'PRIVATE_LOCAL_HISTORY','created_ms':int(time.time()*1000)}
            self.db.execute('INSERT INTO science_sessions VALUES(?,?,?)',(sid,0,canonical(d).decode()))
            return d
        return self.s.store.mutate(opid,{'kind':'science-session-create','request':p},act)
    def fork(self,p,opid):
        keys(p,{'session_id','expected_revision','through_turn','title'}, {'profile_id'})
        old=self.get(p['session_id']);integer(p['expected_revision'],0,2**31-1)
        require(old['revision']==p['expected_revision'],'STALE_REVISION','Session changed since review')
        integer(p['through_turn'],0,len(old['turns']));text(p['title'],160)
        profile=p.get('profile_id',old['profile_id']);cap=self.s.store.get(profile);self.s._check_trust(cap)
        require(compatibility(cap.profile,old['binding'])['compatible'],'INCOMPATIBLE','Fork profile uses a different model')
        sid=identity('BTX/NeuronLab/SessionFork/2',{'operation_id':opid,'request':p})
        def act():
            latest=self.get(p['session_id']);require(latest['revision']==p['expected_revision'],'STALE_REVISION','Source session changed')
            d=dict(old,id=sid,revision=0,title=p['title'],profile_id=profile,turns=copy.deepcopy(old['turns'][:p['through_turn']]),
                   parent={'id':old['id'],'revision':old['revision'],'through_turn':p['through_turn']},created_ms=int(time.time()*1000))
            self.db.execute('INSERT INTO science_sessions VALUES(?,?,?)',(sid,0,canonical(d).decode()));return d
        return self.s.store.mutate(opid,{'kind':'science-session-fork','request':p},act)
    def _claim(self,opid,semantic,sid,revision):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT * FROM science_turns WHERE operation_id=?',(opid,)).fetchone()
            if row:
                require(row['semantic']==semantic,'IDEMPOTENCY_CONFLICT','Turn operation ID reused with different input')
                self.db.execute('COMMIT')
                if row['status']=='COMPLETED':return loads(row['result'])
                raise LabError('TURN_'+row['status'],'Existing operation is '+row['status']+'; inspect/recover instead of duplicating')
            d=self.get(sid);require(d['revision']==revision,'STALE_REVISION','Session changed since review')
            require(not self.db.execute("SELECT 1 FROM science_turns WHERE session_id=? AND status='RUNNING'",(sid,)).fetchone(),'SESSION_BUSY','Another turn owns this session')
            self.db.execute('INSERT INTO science_turns VALUES(?,?,?,\'RUNNING\',NULL)',(opid,semantic,sid))
            self.db.execute('COMMIT');return None
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
    def turn(self,p,opid,progress=None):
        keys(p,{'session_id','expected_revision','messages','dose_ppm','sampling'},{'capture_layer','capture_units','device'})
        integer(p['expected_revision'],0,2**31-1);sampling_spec(p['sampling']);integer(p['dose_ppm'],0,4_000_000)
        keys(p['messages'],set(ARMS))
        for message in p['messages'].values():require(type(message)is str and 0<len(message.encode())<=16384,'MESSAGE','Each arm needs a bounded explicit user message')
        d=self.get(p['session_id']);require(len(d['turns'])<128,'TURN_BUDGET','Fork or archive this conversation before continuing')
        cap=self.s.store.get(d['profile_id']);self.s._check_trust(cap)
        m=self.s._model(d['model_id'])
        semantic=identity('BTX/NeuronLab/TurnRequest/2',p)
        cached=self._claim(opid,semantic,d['id'],p['expected_revision'])
        if cached is not None:return cached
        trustrow=self.db.execute('SELECT sequence FROM trust WHERE publisher=?',(cap.publisher,)).fetchone()
        trustseq=trustrow[0] if trustrow else None
        def fence():
            self.s._check_trust(cap)
            row=self.db.execute('SELECT sequence FROM trust WHERE publisher=?',(cap.publisher,)).fetchone()
            require(row is not None and row[0]==trustseq,'TRUST_CHANGED','Publisher trust changed during the turn')
            row=self.db.execute('SELECT status FROM science_turns WHERE operation_id=?',(opid,)).fetchone()
            require(row is not None and row[0]=='RUNNING','CANCELLED','Turn was cancelled or recovered')
        try:
            model,tok,adapter,b=load_local(m['path'],d['binding'],device=p.get('device','cpu'))
            answers={};formats={}
            for arm in ARMS:
                messages=([{'role':'system','content':d['system']}] if d['system'] else [])
                for turn in d['turns']:
                    messages += [{'role':'user','content':turn['user'][arm]}, {'role':'assistant','content':turn['answers'][arm]['text']}]
                messages += [{'role':'user','content':p['messages'][arm]}]
                ids,formats[arm]=format_messages(messages,tok,model,d['template'])
                prof=None if arm=='baseline' else scaled_profile(cap.profile,p['dose_ppm'],arm=='negative')
                from .operators import Capture
                capture=Capture([p.get('capture_layer',0)],p.get('capture_units',[0]),max_records=1024)
                def emit(event,arm=arm):
                    if progress:progress(dict(event,arm=arm,session_id=d['id']))
                answers[arm]=decode(model,tok,adapter,b,ids,profile=prof,tensors=cap.tensors if prof else None,
                                    sampling=p['sampling'],fence=fence,progress=emit,capture=capture)
            fence()
            body={'schema':'btx.neuronlab.turn-result/2','session_id':d['id'],'revision':d['revision']+1,
                  'turn_index':len(d['turns']),'answers':answers,'formats':formats,'dose_ppm':p['dose_ppm'],
                  'input_messages_hash':identity('BTX/NeuronLab/TurnMessages/1',p['messages']),
                  'provisional_streams_are_retractable':False,'privacy':'PRIVATE_LOCAL_HISTORY'}
            # Sign after final fence, then CAS commit. A crash can leave an orphaned
            # private evidence file but never a half-appended conversation.
            receipt=self.s._receipt('multiturn-counterfactual',body)
            result={'receipt_id':receipt['id'],**body,'committed':True}
            self.db.execute('BEGIN IMMEDIATE')
            try:
                fence();latest=self.get(d['id'])
                require(latest['revision']==p['expected_revision'],'STALE_REVISION','Concurrent session edit rejected')
                latest['revision']+=1
                latest['turns'].append({'user':p['messages'],'answers':{k:{'text':v['text'],'token_ids':v['token_ids'],'profile_id':v['profile_id'],'finish_reason':v['finish_reason']}for k,v in answers.items()},
                                        'dose_ppm':p['dose_ppm'],'receipt_id':receipt['id'],'formats':formats})
                self.db.execute('UPDATE science_sessions SET revision=?,document=? WHERE id=? AND revision=?',
                                (latest['revision'],canonical(latest).decode(),d['id'],p['expected_revision']))
                self.db.execute("UPDATE science_turns SET status='COMPLETED',result=? WHERE operation_id=?",(canonical(result).decode(),opid))
                self.db.execute('COMMIT')
            except BaseException:self.db.execute('ROLLBACK');raise
            return result
        except BaseException as exc:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            self.db.execute("UPDATE science_turns SET status='FAILED',result=? WHERE operation_id=? AND status='RUNNING'",
                            (canonical({'code':getattr(exc,'code','EXECUTION_FAILED'),'committed':False}).decode(),opid))
            raise
    def recover(self,p,opid):
        keys(p,{'operation_id'})
        text(p['operation_id'],96)
        # Explicitly cancels/reconciles an indeterminate worker. A still-running
        # worker sees the status change at its next token and final commit fence.
        def act():
            row=self.db.execute('SELECT * FROM science_turns WHERE operation_id=?',(p['operation_id'],)).fetchone()
            require(row is not None,'OPERATION','Unknown turn operation')
            if row['status']=='RUNNING':self.db.execute("UPDATE science_turns SET status='INTERRUPTED' WHERE operation_id=?",(p['operation_id'],))
            return {'operation_id':p['operation_id'],'status':'INTERRUPTED' if row['status']=='RUNNING' else row['status'],'resend_automatically':False}
        return self.s.store.mutate(opid,{'kind':'recover-turn','request':p},act)
