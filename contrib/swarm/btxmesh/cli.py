"""Operator CLI. Invitations are recipient sealed; mutations use a private socket.

Global option --data belongs before the subcommand. No command broadcasts money.
"""
import argparse
import asyncio
import json
import os
import time
from pathlib import Path
import aiohttp
from .codec import encode, decode, digest, fixed_id, integer
from .storage import atomic_write, local_socket, ProcessLock
from .errors import MeshError, require
from .daemon import initialize
from .invitations import bundle, check_bundle, make_invitation, open_invitation


async def local_request(data,path,payload=None,service='swarm'):
    token=(data/('local.token' if service=='swarm' else 'paynet.token')).read_text()
    connector=aiohttp.UnixConnector(path=str(local_socket(data,service)))
    async with aiohttp.ClientSession(connector=connector,timeout=aiohttp.ClientTimeout(total=120)) as session:
        async with session.request('GET' if payload is None else 'POST','http://localhost'+path,data=encode(payload) if payload is not None else None,headers={'Authorization':'Bearer '+token}) as r:
            raw=await r.content.read(4*1024*1024+1);require(len(raw)<=4*1024*1024,'RESPONSE_LIMIT')
            result=decode(raw,4*1024*1024)
            if r.status!=200 or 'error' in result:raise MeshError(result.get('error','LOCAL_HTTP'),result.get('detail',''))
            return result


async def command(data,kind,body,id=None):
    return await local_request(data,'/command',{'kind':kind,'id':id or os.urandom(24).hex(),'body':body})


def config_edit(data,fn):
    with_lock=ProcessLock(data/'config-edit.lock')
    try:
        path=data/'config.json';cfg=decode(path.read_bytes());fn(cfg);atomic_write(path,encode(cfg));return cfg
    finally:with_lock.close()


async def dispatch(args):
    data=Path(args.data).expanduser().resolve()
    if args.action=='init':
        identity,cfg=initialize(data,args.host,args.port)
        return {'node_id':identity.id,'endpoint':cfg['peers'][identity.id]['endpoint'],'membership':'OBSERVER_BY_DEFAULT','automatic_spend_atoms':'0'}
    if args.action=='identity':
        identity,cfg=initialize(data)
        result=bundle(identity,args.endpoint or cfg['peers'][identity.id]['endpoint'])
        if args.output:atomic_write(Path(args.output),encode(result));return {'public_bundle':str(Path(args.output))}
        return result
    if args.action=='status':return await local_request(data,'/status')
    if args.action=='stop':return await local_request(data,'/stop',{})
    if args.action=='command':return await command(data,args.method,decode(Path(args.json).read_bytes()),args.id)
    if args.action=='query':
        payload={'kind':args.kind,'limit':args.limit}
        if args.realm:payload['realm']=args.realm
        if args.key:payload['key']=args.key
        if args.cursor:payload['cursor']=args.cursor
        return await local_request(data,'/query',payload)
    if args.action=='result':return await local_request(data,'/result/'+args.id)
    if args.action=='create':
        from .state import default_policy
        p=default_policy(fixed_id(args.suite_id),fixed_id(args.holdout))
        return await command(data,'realm.create',{'name':args.name,'nonce':os.urandom(24).hex(),'owner_domain':args.trust_domain,'policy':p})
    if args.action=='import':return await local_request(data,'/import',{'realm':fixed_id(args.realm),'path':str(Path(args.path).resolve())})
    if args.action=='invite':
        from .identity import Identity
        identity=Identity(data/'identity');target=decode(Path(args.peer_bundle).read_bytes());peer=check_bundle(target)
        roles=args.roles.split(',');require(set(roles)<= {'observer','worker','trainer','evaluator'},'INVITE_ROLES')
        cfg=config_edit(data,lambda c:c['peers'].update({peer['identity']:peer}))
        # Authoritative membership and transport identity are separate checks.
        await command(data,'member.grant',{'realm':args.realm,'peer':peer['identity'],'roles':roles,'domain':args.trust_domain,'max_slots':args.slots,'max_vram_bytes':args.vram_bytes})
        key=None
        if set(roles)&{'worker','trainer','evaluator'}:
            path=data/'blobs'/'keys'/fixed_id(args.realm)
            require(path.exists(),'REALM_KEY_UNAVAILABLE');key=path.read_bytes().hex()
        payload={'realm':args.realm,'roles':roles,'peers':cfg['peers'],'voters':cfg['voters'],'bootstrap_roots':cfg['bootstrap_roots'],'realm_key':key}
        sealed=make_invitation(identity,target,payload,args.expires_hours*3600)
        atomic_write(Path(args.output),encode(sealed));return {'invitation':args.output,'recipient':peer['identity'],'expires_hours':args.expires_hours,'worker_resources_authorized':False}
    if args.action=='join':
        identity,cfg=initialize(data)
        seen_path=data/'invitation-nonces.json';seen=set(decode(seen_path.read_bytes()) if seen_path.exists() else [])
        inv=decode(Path(args.invitation).read_bytes());joined=open_invitation(identity,inv,fixed_id(args.issuer),seen)
        require(set(joined)=={'realm','roles','peers','voters','bootstrap_roots','realm_key'},'INVITE_PAYLOAD')
        require(set(joined['voters'])<=set(joined['peers']),'VOTER_KEYS_REQUIRED');realm=fixed_id(joined['realm'])
        # Only the invitation issuer's explicit pinned authority admits these identities.
        require(args.issuer in joined['voters'],'INVITE_AUTHORITY')
        with_lock=ProcessLock(data/'join-edit.lock')
        try:
            path=data/'joined.json';all_joined=decode(path.read_bytes()) if path.exists() else {}
            all_joined[realm]={k:joined[k] for k in ('peers','voters','bootstrap_roots','roles')}
            if joined['realm_key'] is not None:
                key=bytes.fromhex(joined['realm_key']);require(len(key)==32,'REALM_KEY')
                kp=data/'realm-keys.json';keys=decode(kp.read_bytes()) if kp.exists() else {}
                require(realm not in keys or keys[realm]==key.hex(),'KEY_REPLACEMENT_FORBIDDEN');keys[realm]=key.hex();atomic_write(kp,encode(keys))
            atomic_write(path,encode(all_joined));atomic_write(seen_path,encode(sorted(seen)))
        finally:with_lock.close()
        return {'joined':realm,'roles':joined['roles'],'idle_compute':cfg['resource_policy']['idle_contribution'],'payment_authority':False}
    if args.action=='contribute':
        integer(args.slots,0,64);integer(args.cpu_threads,1,256);integer(args.vram_bytes,0,2**44);integer(args.max_steps,1,4096)
        def change(c):
            c['resource_policy'].update(idle_contribution=args.mode=='on',slots=args.slots,cpu_threads=args.cpu_threads,vram_bytes=args.vram_bytes,max_steps_per_job=args.max_steps)
        cfg=config_edit(data,change)
        return {'resource_policy':cfg['resource_policy'],'private_data_training':False,'automatic_spend_atoms':'0'}
    if args.action=='worker':
        from .worker import Worker
        worker=Worker(data,fixed_id(args.realm));return await worker.run(once=args.once)
    if args.action=='probe':
        from .engines import capabilities
        return capabilities()
    raise MeshError('CLI_ACTION')


def main():
    p=argparse.ArgumentParser(description='BTX swarm runtime; local administration, no monetary signing')
    p.add_argument('--data',default=str(Path.home()/'.btx'/'modelnet'/'swarm'))
    sub=p.add_subparsers(dest='action',required=True)
    q=sub.add_parser('init');q.add_argument('--host',default='auto');q.add_argument('--port',type=int,default=29448)
    q=sub.add_parser('identity');q.add_argument('--endpoint');q.add_argument('--output')
    for name in ('status','stop','probe'):sub.add_parser(name)
    q=sub.add_parser('create');q.add_argument('--name',required=True);q.add_argument('--suite-id',required=True);q.add_argument('--holdout',required=True);q.add_argument('--trust-domain',required=True)
    q=sub.add_parser('command');q.add_argument('method');q.add_argument('--json',required=True);q.add_argument('--id')
    q=sub.add_parser('query');q.add_argument('kind');q.add_argument('--realm');q.add_argument('--key');q.add_argument('--limit',type=int,default=256);q.add_argument('--cursor')
    q=sub.add_parser('result');q.add_argument('id')
    q=sub.add_parser('import');q.add_argument('path');q.add_argument('--realm',required=True)
    q=sub.add_parser('invite');q.add_argument('--realm',required=True);q.add_argument('--peer-bundle',required=True);q.add_argument('--output',required=True);q.add_argument('--roles',default='observer');q.add_argument('--trust-domain',required=True);q.add_argument('--slots',type=int,default=1);q.add_argument('--vram-bytes',type=int,default=0);q.add_argument('--expires-hours',type=int,default=24)
    q=sub.add_parser('join');q.add_argument('invitation');q.add_argument('--issuer',required=True)
    q=sub.add_parser('contribute');q.add_argument('mode',choices=['on','off']);q.add_argument('--slots',type=int,default=1);q.add_argument('--cpu-threads',type=int,default=1);q.add_argument('--vram-bytes',type=int,default=0);q.add_argument('--max-steps',type=int,default=128)
    q=sub.add_parser('worker');q.add_argument('--realm',required=True);q.add_argument('--once',action='store_true')
    args=p.parse_args()
    try:result=asyncio.run(dispatch(args));print(json.dumps(result,indent=2,ensure_ascii=False))
    except (MeshError,OSError,ValueError,aiohttp.ClientError) as e:
        print(json.dumps({'error':getattr(e,'code','CLI_FAILURE'),'detail':str(e)[:300]}));raise SystemExit(2)

if __name__=='__main__':main()
