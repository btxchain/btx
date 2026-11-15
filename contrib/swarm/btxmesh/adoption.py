"""Locally reversible model activation. Quality, signature and runtime gates differ.

A channel record does not authorize software execution or private data release.
Only the reference SafeTensors decoder is qualified by the tests in this package;
production engines must supply their own read-only prepare/check and activate hooks.
"""
from pathlib import Path
from .codec import encode,decode,digest,byte_id,fixed_id
from .storage import Database,private_dir,atomic_write,ProcessLock
from .identity import verify
from .evaluation import qualify_report
from .errors import require,MeshError


def verify_certificate(certificate,candidate,reports,policy,keys,members,revoked):
    original={k:candidate[k] for k in ('family','checkpoint','parents','recipe','kind','niche','license_id','data_grant_ids')}
    require(digest('BTX/CandidateCheckpoint/1',{'author':candidate['author'],**original})==candidate['id'],'CANDIDATE_ID')
    expected=digest('BTX/PromotionCertificate/1',{k:v for k,v in certificate.items() if k!='id'})
    require(expected==certificate['id'],'CERTIFICATE_ID')
    require(certificate['candidate']==candidate['id'] and certificate['family']==candidate['family'],'CANDIDATE_BINDING')
    require(certificate['channel']==candidate['niche']+'/stable','CHANNEL_OBJECTIVE')
    require(set(certificate['reports'])=={r['id'] for r in reports},'CERTIFICATE_REPORTS')
    roots=set();domains=set();sample=None
    for report in reports:
        peer=report['evaluator'];require(peer in keys and peer in members and peer not in revoked,'EVALUATOR_REVOKED_OR_UNKNOWN')
        require(peer!=candidate['author'] and peer not in roots,'EVALUATOR_INDEPENDENCE')
        require(report['candidate']==candidate['id'],'EVALUATION_CANDIDATE')
        env=report.get('authorization');require(env is not None,'SIGNED_EVIDENCE_REQUIRED')
        body=env['body'];payload=body['payload']
        # Verify archival signatures without interpreting authentication TTL as
        # an expiry of the underlying research result. Revocation is checked now.
        require(body['protocol']=='BTX-SWARM/1' and body['suite']=='ML-DSA-44' and body['sender']==peer and payload['kind']=='evaluation.publish','EVIDENCE_DOMAIN')
        require(verify(keys[peer],b'BTX-SWARM/1\x00'+encode(body),env['signature'])==peer,'EVIDENCE_SIGNATURE')
        signed=payload['body']
        require(all(report[k]==v for k,v in signed.items()),'EVIDENCE_BINDING')
        require(digest('BTX/EvaluationReport/1',{'evaluator':peer,**signed})==report['id'],'REPORT_ID')
        qualify_report(signed,policy);roots.add(peer);domains.add(members[peer]['domain'])
        require('evaluator' in members[peer]['roles'] or 'admin' in members[peer]['roles'],'EVALUATOR_ROLE')
        if sample is None:sample=report['sample_commitment']
        require(sample==report['sample_commitment'],'SAMPLE_COMMITMENT')
    require(len(roots)>=policy['min_evaluators'] and len(domains)>=policy['min_domains'],'EVALUATION_QUORUM')
    return {'certificate':certificate['id'],'quality_scope':'DECLARED_EVALUATION_ONLY','independent_roots':len(roots),'domains':len(domains)}


class Adopter:
    def __init__(self,data):
        self.root=private_dir(Path(data));self.lock=ProcessLock(self.root/'adopter.lock');self.db=Database(self.root/'adoption.sqlite3')
        self.db.db.execute('CREATE TABLE IF NOT EXISTS deployments(key TEXT PRIMARY KEY,body TEXT)')
    def state(self,family,channel):
        row=self.db.db.execute('SELECT body FROM deployments WHERE key=?',(family+':'+channel,)).fetchone()
        return decode(row[0].encode()) if row else None
    def stage(self,store,realm,channel,certificate_id,*,expected_previous=None):
        require(channel['state'] in {'CANARY','ACTIVE'},'CHANNEL_NOT_STAGED')
        require(channel['certificate']==certificate_id,'CERTIFICATE_BINDING');fixed_id(channel['family']);fixed_id(channel['checkpoint'])
        old=self.state(channel['family'],channel['name'])
        require((old.get('active') if old else None)==expected_previous,'LOCAL_ADOPTION_STALE')
        require(old is None or channel['sequence']>old['sequence'],'LOCAL_SEQUENCE')
        model_dir=private_dir(self.root/'models'/channel['checkpoint'])
        store.export_file(realm,channel['checkpoint'],model_dir/'model.safetensors')
        from .runtime import Decoder,generate
        model=Decoder.from_checkpoint((model_dir/'model.safetensors').read_bytes());generate(model,[0,1],max_new_tokens=1)
        body={'family':channel['family'],'channel':channel['name'],'sequence':channel['sequence'],'certificate':certificate_id,'staged':channel['checkpoint'],'active':old.get('active') if old else None,'previous':old.get('previous') if old else None,'state':'STAGED','canary_passed':False}
        with self.db.tx() as c:c.execute('INSERT OR REPLACE INTO deployments VALUES(?,?)',(channel['family']+':'+channel['name'],encode(body).decode()))
        return body
    def activate(self,family,channel,sequence,*,verified_certificate,canary_passed):
        require(canary_passed is True,'LOCAL_CANARY_FAILED')
        body=self.state(family,channel);require(body is not None and body['sequence']==sequence and body['state'] in {'STAGED','ACTIVE'},'LOCAL_SEQUENCE')
        require(verified_certificate['certificate']==body['certificate'],'CERTIFICATE_BINDING')
        if body['state']=='STAGED':body.update(previous=body['active'],active=body['staged'],state='ACTIVE',canary_passed=True)
        # SQLite is authoritative. The pointer is a repairable advisory export,
        # never the runtime's source of activation authority.
        pointer=self.root/(digest('BTX/LocalChannelPointer/1',{'family':family,'channel':channel})+'.json')
        with self.db.tx() as c:c.execute('UPDATE deployments SET body=? WHERE key=?',(encode(body).decode(),family+':'+channel))
        atomic_write(pointer,encode({**body,'advisory_only':True}))
        return body
    def rollback(self,family,channel,reason,*,expected_active):
        body=self.state(family,channel)
        if body and body.get('rollback_of')==expected_active and body['state']=='ROLLED_BACK':return body
        require(body and body['previous'] and body['active']==expected_active,'LOCAL_ROLLBACK_UNAVAILABLE')
        body.update(active=body['previous'],previous=body['active'],state='ROLLED_BACK',reason=reason,rollback_of=expected_active)
        with self.db.tx() as c:c.execute('UPDATE deployments SET body=? WHERE key=?',(encode(body).decode(),family+':'+channel))
        pointer=self.root/(digest('BTX/LocalChannelPointer/1',{'family':family,'channel':channel})+'.json')
        atomic_write(pointer,encode({**body,'advisory_only':True}))
        return body
    def close(self):self.db.close();self.lock.close()
