"""Train -> real paired evaluation -> signed evidence -> graduate -> local adopt.

All identities run on one test host. This is engineering qualification, not proof
of external administrative independence or improvement on general coding tasks.
"""
import copy
import time
import torch
import pytest
from btxmesh.identity import Identity
from btxmesh.storage import Database
from btxmesh.state import State,default_policy
from btxmesh.codec import digest,byte_id,encode
from btxmesh.runtime import Decoder,DecoderConfig
from btxmesh.training import Trainer
from btxmesh.blobs import BlobStore
from btxmesh.adoption import Adopter,verify_certificate
from btxmesh.errors import MeshError
from support import H


def test_trained_descendant_signed_evidence_and_reversible_local_activation(tmp_path):
    torch.set_num_threads(1);torch.manual_seed(29)
    owner=Identity(tmp_path/'owner');reviewers=[Identity(tmp_path/f'reviewer-{i}') for i in range(3)]
    db=Database(tmp_path/'control.sqlite');state=State(db,[owner.id]);index=0
    def call(identity,kind,body):
        nonlocal index
        index+=1;payload={'kind':kind,'id':str(index),'body':body}
        cmd={**payload,'actor':identity.id,'time_ms':int(time.time()*1000),'authorization':identity.envelope(payload)}
        with db.tx() as c:r=state.apply(c,cmd,index,1)
        assert 'error' not in r,r
        return r
    store=BlobStore(tmp_path/'blobs');adopter=Adopter(tmp_path/'adopter')
    try:
        model=Decoder(DecoderConfig(vocab=16,width=16,layers=1,heads=2,context=32));base=model.checkpoint()
        generator=torch.Generator().manual_seed(391)
        prompts=torch.randint(0,16,(256,8),generator=generator);targets=(prompts[:,-1]+1)%16
        suite={'domain':'synthetic modulo successor','cases':[{'id':str(i),'prompt':p.tolist(),'target':int(t)} for i,(p,t) in enumerate(zip(prompts,targets))]}
        assert len({tuple(x['prompt']) for x in suite['cases']})==256
        suite_id=byte_id(encode(suite));holdout=H('predeclared-public-synthetic-acceptance-not-secret')
        policy=default_policy(suite_id,holdout);policy.update(min_examples=256,max_trials=4,canary_min=1,min_domains=3)
        realm=call(owner,'realm.create',{'name':'evolution-test','nonce':'1','owner_domain':'owner','policy':policy})['id']
        store.provision_realm(realm);base_id=store.put_bytes(realm,base)['artifact']
        family=call(owner,'family.register',{'realm':realm,'genesis_checkpoint':base_id,'origin':'synthetic-test','license_id':H('license'),'nonce':'2','name':'reference'})['id']
        trainer=Trainer(model,seed=9);trainer.train(torch.arange(4096)%16,64,batch_size=8,sequence=8)
        trained=model.checkpoint();cp=store.put_bytes(realm,trained)['artifact'];assert cp!=base_id
        candidate=call(owner,'candidate.submit',{'family':family,'checkpoint':cp,'parents':[],'recipe':H('training-recipe'),'kind':'base','niche':'general','license_id':H('license'),'data_grant_ids':[]})
        reports=[];members={}
        for index_,reviewer in enumerate(reviewers):
            members[reviewer.id]=call(owner,'member.grant',{'realm':realm,'peer':reviewer.id,'roles':['evaluator'],'domain':'test-domain-'+str(index_),'max_slots':1,'max_vram_bytes':0})
            parent=Decoder.from_checkpoint(base);child=Decoder.from_checkpoint(trained)
            with torch.no_grad():
                a=parent(prompts)[0][:,-1].argmax(-1)==targets;b=child(prompts)[0][:,-1].argmax(-1)==targets
            counts={x+y:int(((a==int(x))&(b==int(y))).sum()) for x in '01' for y in '01'}
            reports.append(call(reviewer,'evaluation.publish',{'candidate':candidate['id'],'suite_id':suite_id,'holdout_commitment':holdout,'counts':counts,'regressions_ppm':{'safety':0,'general':0},'reproducible':True,'environment_id':H('same-test-host-not-independent-infrastructure'),'sample_commitment':byte_id(encode(suite))}))
        cert_id=call(owner,'candidate.graduate',{'candidate':candidate['id'],'reports':[r['id'] for r in reports],'channel':'general/stable'})['certificate']
        cert=state.get(db.db,'certificate',cert_id);keys={r.id:r.public for r in reviewers}
        verified=verify_certificate(cert,candidate,reports,policy,keys,members,set())
        with pytest.raises(MeshError,match='EVALUATOR_REVOKED_OR_UNKNOWN'):verify_certificate(cert,candidate,reports,policy,keys,members,{reviewers[0].id})
        altered=copy.deepcopy(reports);altered[0]['counts']={**altered[0]['counts'],'01':altered[0]['counts']['01']+1}
        with pytest.raises(MeshError,match='EVIDENCE_BINDING'):verify_certificate(cert,candidate,altered,policy,keys,members,set())
        channel=call(owner,'channel.stage',{'certificate':cert_id,'expected_sequence':0})
        adopter.stage(store,realm,channel,cert_id)
        active=adopter.activate(family,'general/stable',1,verified_certificate=verified,canary_passed=True)
        assert active['active']==cp
        # Repeated delivery is idempotent, including after authoritative DB commit.
        assert adopter.activate(family,'general/stable',1,verified_certificate=verified,canary_passed=True)==active
        call(owner,'canary.observe',{'family':family,'channel':'general/stable','sequence':1,'success':True,'receipt_id':H('local-runtime-canary')})
        assert call(owner,'channel.activate',{'family':family,'channel':'general/stable','expected_sequence':1})['state']=='ACTIVE'
    finally:adopter.close();store.close();db.close()
