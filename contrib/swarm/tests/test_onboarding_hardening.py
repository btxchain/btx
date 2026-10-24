import argparse
import asyncio
import json
import time
from pathlib import Path
import pytest
from btxmesh.codec import encode
from btxmesh.daemon import initialize, SwarmNode
from btxmesh.cli import dispatch
from btxmesh.discovery import DiscoveryBook,CatalogWatcher,neighbors
from btxmesh.storage import Database,private_dir,atomic_write
from btxmesh.identity import Identity
from btxmesh.invitations import bundle
from btxmesh.engines import clean_environment
from btxmesh.worker import Worker
from btxmesh.errors import MeshError
from btxmesh.state import default_policy
from support import H,free_port,wait_leader,call


def test_canonical_private_directory_refuses_parent_symlink(tmp_path):
    destination=tmp_path/'real';destination.mkdir();alias=tmp_path/'alias';alias.symlink_to(destination,target_is_directory=True)
    with pytest.raises(MeshError,match='SYMLINK'):private_dir(alias/'child')
    assert not (destination/'child').exists()


def test_engine_child_does_not_inherit_provider_secrets(monkeypatch):
    for key in ('OPENAI_API_KEY','AWS_SECRET_ACCESS_KEY','HF_TOKEN','RPCPASSWORD','LD_PRELOAD','PYTHONPATH'):
        monkeypatch.setenv(key,'must-not-reach-child')
    clean=clean_environment({'OMP_NUM_THREADS':'1','HF_HUB_OFFLINE':'1'})
    assert 'must-not-reach-child' not in clean.values()
    with pytest.raises(MeshError,match='ENGINE_ENVIRONMENT'):clean_environment({'API_KEY':'hidden'})


def test_auto_listener_uses_route_hint_not_public_reachability(tmp_path,monkeypatch):
    monkeypatch.setattr('btxmesh.daemon.automatic_host',lambda:('0.0.0.0','10.1.2.3'))
    identity,cfg=initialize(tmp_path/'a',port=39448)
    assert cfg['bind_host']=='0.0.0.0'
    assert cfg['peers'][identity.id]['endpoint']=='https://10.1.2.3:39448'
    assert cfg['resource_policy']['idle_contribution'] is False
    _,again=initialize(tmp_path/'a',host='127.0.0.1',port=39449)
    assert again==cfg   # Never rewrite an existing operator configuration.


def test_catalog_default_observer_and_public_visibility(tmp_path):
    db=Database(tmp_path/'discovery.db');book=DiscoveryBook(db,{})
    catalog=tmp_path/'catalog.json';artifact=H('a');model=H('m')
    atomic_write(catalog,encode({'models':[{'artifact_id':artifact,'model_id':model,'bytes_verified':True,'incomplete':False}]}))
    watcher=CatalogWatcher(catalog,book)
    result=watcher.poll();assert len(result)==1 and result[0]['role']=='observer'
    assert not result[0]['idle_compute_authorized'] and not book.public_lineages()
    assert watcher.poll()==[]
    registered=book.join_artifact({'artifact_id':artifact,'model_id':model,'bytes_verified':True,'incomplete':False},{artifact:{'lineage_id':H('family'),'visibility':'public'}})
    assert registered['lineage_assurance']=='VERIFIED_MAPPING' and book.public_lineages()==[H('family')]
    db.close()


def test_query_pagination_never_changes_scope(machine):
    realm=machine.realm()
    with machine.db.tx() as c:
        for index in range(11):machine.state.put(c,'sample',str(index).zfill(2),{'realm':realm,'value':index})
    rows=[];cursor=None
    while True:
        page,cursor=machine.state.page(machine.db.db,'sample',realm,limit=3,cursor=cursor)
        rows+=page
        if cursor is None:break
    assert [r['value'] for r in rows]==list(range(11))
    _,cursor=machine.state.page(machine.db.db,'sample',realm,limit=3)
    with pytest.raises(MeshError,match='QUERY_CURSOR_SCOPE'):machine.state.page(machine.db.db,'sample',H('other'),cursor=cursor)
    with pytest.raises(MeshError,match='SCAN_RANGE_INCOMPLETE'):machine.state.scan(machine.db.db,'sample',realm,limit=10)


def test_dataset_authorization_revocation_fences_release():
    realm,artifact,checkpoint=H('realm'),H('data'),H('weights')
    policy={'idle_contribution':True,'data_grants':{'g':{'realm':realm,'artifact':artifact,'expires_ms':int(time.time()*1000)+60000,'permissions':['TRAIN','RELEASE_DERIVATIVE']}}}
    class Governor:
        def policy(self):return policy
    worker=Worker.__new__(Worker);worker.realm=realm;worker.governor=Governor()
    payload={'dataset_artifact':artifact,'data_grant_id':'g'}
    worker.release_gate(payload,checkpoint)
    policy['data_grants']['g']['permissions']=['TRAIN']
    with pytest.raises(MeshError,match='DERIVATIVE_RELEASE_DENIED'):worker.release_gate(payload,checkpoint)
    policy['data_grants']['g']['revoked']=True
    with pytest.raises(MeshError,match='DATA_GRANT_REVOKED'):worker.release_gate(payload,checkpoint)


def test_real_cli_invitation_join_and_default_no_compute(tmp_path):
    async def scenario():
        owner_dir,worker_dir=tmp_path/'owner',tmp_path/'worker'
        owner,cfg=initialize(owner_dir,host='127.0.0.1',port=free_port())
        recipient,wcfg=initialize(worker_dir,host='127.0.0.1',port=free_port())
        node=SwarmNode(owner_dir,discovery=False)
        await node.start()
        try:
            await wait_leader([node])
            realm=(await call(node,'realm.create',{'name':'CLI realm','nonce':'cli','owner_domain':'a','policy':default_policy(H('suite'),H('holdout'))}))['id']
            target=tmp_path/'recipient.json';atomic_write(target,encode(bundle(recipient,wcfg['peers'][recipient.id]['endpoint'])))
            invitation=tmp_path/'invitation.json'
            args=argparse.Namespace(data=str(owner_dir),action='invite',realm=realm,peer_bundle=str(target),output=str(invitation),roles='worker,trainer',trust_domain='independent-b',slots=1,vram_bytes=0,expires_hours=1)
            issued=await dispatch(args);assert not issued['worker_resources_authorized']
            args=argparse.Namespace(data=str(worker_dir),action='join',invitation=str(invitation),issuer=owner.id)
            joined=await dispatch(args);assert joined['joined']==realm and not joined['idle_compute']
            with pytest.raises(MeshError,match='COMPUTE_NOT_AUTHORIZED'):Worker(worker_dir,realm)
            with pytest.raises(MeshError,match='INVITE_REPLAY'):await dispatch(args)
            # Both individual signing secrets remain in their own identity directories.
            assert 'PRIVATE KEY' not in invitation.read_text()
        finally:await node.close()
    asyncio.run(scenario())
