"""BTX swarm sidecar: default discovery and subscriptions, isolated from btxd.

The local management socket is not published on the peer network. Control uses
pinned mTLS and signed commands. Tensor traffic uses separate bounded endpoints.
"""
import argparse
import asyncio
import contextlib
import json
import os
import signal
import time
from pathlib import Path
from urllib.parse import urlparse
from aiohttp import web
from .codec import encode,decode,byte_id,fields,integer,digest
from .identity import Identity,verify_envelope
from .storage import Database,private_dir,atomic_write,ProcessLock,local_socket
from .state import State
from .raft import Raft
from .blobs import BlobStore,PIECE_BYTES
from .transport import PeerTransport,errors,bounded_body
from .discovery import DiscoveryBook,CatalogWatcher,LanDiscovery
from .errors import MeshError,require
from .invitations import bundle,check_bundle


def automatic_host():
    """Choose an IPv4 route interface; UDP connect does not send a packet.

    A route address is only a discovery hint, never proof of WAN reachability.
    Explicit --host preserves operator control on multihomed and air-gapped hosts.
    """
    import socket
    import ipaddress
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            host = probe.getsockname()[0]
            ip = ipaddress.ip_address(host)
            if not ip.is_loopback and not ip.is_unspecified and not ip.is_multicast:
                return "0.0.0.0", host
    except OSError:
        pass
    return "127.0.0.1", "127.0.0.1"


def initialize(data:Path,host="auto",port=29448):
    data=private_dir(Path(data));identity=Identity(data/"identity")
    cfg_path=data/"config.json"
    if not cfg_path.exists():
        integer(port, 1, 65535)
        bind_host, advertised_host = automatic_host() if host == "auto" else (host, host)
        require(advertised_host not in {"0.0.0.0", "::"}, "ADVERTISED_HOST_REQUIRED")
        address = "[" + advertised_host + "]" if ":" in advertised_host else advertised_host
        endpoint=f"https://{address}:{port}"
        own=check_bundle(bundle(identity,endpoint))
        cfg={"version":1,"node_id":identity.id,"bind_host":bind_host,"port":port,"voters":[identity.id],"bootstrap_roots":[identity.id],
             "peers":{identity.id:own},"resource_policy":{"idle_contribution":False,"slots":1,"vram_bytes":0,"cpu_threads":1,"max_steps_per_job":128,"allowed_executors":["torch.train","torch.rollout","torch.evaluate","dataset.verify"]},
             "storage_bytes":32*1024**3}
        atomic_write(cfg_path,encode(cfg))
    return identity,decode(cfg_path.read_bytes())


class SwarmNode:
    def __init__(self,data:Path,*,catalog=None,discovery=True):
        self.data=Path(data);self.identity,self.config=initialize(self.data)
        self.id=self.identity.id
        self.process_lock=ProcessLock(self.data/"daemon.lock")
        require(self.config["node_id"]==self.id,"NODE_IDENTITY")
        require(self.id in self.config["voters"],"NODE_ROLE", "non-voting workers use btx-swarm worker")
        require(set(self.config["voters"])<=set(self.config["peers"]),"PEER_CONFIGURATION")
        self.db=Database(self.data/"control.sqlite3")
        self.state=State(self.db,self.config["bootstrap_roots"])
        self.transport=PeerTransport(self.identity,self.config["peers"])
        self.raft=Raft(self.db,self.id,self.config["voters"],self.transport.rpc,self.state)
        self.blobs=BlobStore(self.data/"blobs",self.config["storage_bytes"])
        self.book=DiscoveryBook(Database(self.data/"discovery.sqlite3"),self.config["peers"])
        self.watcher=CatalogWatcher(Path(catalog) if catalog else self.data.parent/"catalog.json",self.book,self.data/"lineage-mappings.json")
        self.stop=asyncio.Event();self.discovery=LanDiscovery(self.identity,self.book,self.config["peers"][self.id]["endpoint"],self.stop) if discovery else None
        self.runner=None;self.local_runner=None;self.background=[];self.start_time=int(time.time()*1000)
        self.auto_workers={};self.worker_retry={};self.status_errors=[];self.cfg_stamp=(self.data/"config.json").stat().st_mtime_ns
        self.token_path=self.data/"local.token"
        if not self.token_path.exists():atomic_write(self.token_path,os.urandom(32).hex().encode())
        self.local_token=self.token_path.read_text()
    def local_auth(self,request):
        import hmac
        require(hmac.compare_digest(request.headers.get("Authorization",""),"Bearer "+self.local_token),"LOCAL_AUTH")
    async def command(self,actor,payload,authorization=None):
        fields(payload,{"kind","id","body"})
        require(not payload["kind"].startswith("__"),"METHOD")
        cmd={**payload,"actor":actor,"time_ms":int(time.time()*1000)}
        if authorization:cmd["authorization"]=authorization
        if self.raft.role!="leader":
            leader=self.raft.leader
            require(leader is not None,"NOT_LEADER","election")
            env=authorization
            require(env is not None,"NOT_LEADER",leader)
            return await self.transport.command(leader,env)
        result=await self.raft.propose(cmd)
        if payload["kind"]=="realm.create" and "id" in result:self.blobs.provision_realm(result["id"])
        return result
    async def peer_command(self,request):
        relay=self.transport.auth(request)
        env=decode(await bounded_body(request))
        keys={id:p["public_key"] for id,p in self.config["peers"].items()}
        verified=await asyncio.to_thread(verify_envelope,env,keys)
        actor=verified["sender"]
        require(relay==actor or relay in self.config["voters"],"RELAY_AUTH")
        result=await self.command(actor,verified["payload"],env)
        return web.Response(body=encode(result),content_type="application/json")
    async def local_command(self,request):
        self.local_auth(request);payload=decode(await bounded_body(request))
        env=await asyncio.to_thread(self.identity.envelope,payload)
        result=await self.command(self.id,payload,env)
        return web.Response(body=encode(result),content_type="application/json")
    async def raft_request(self,request):
        peer=self.transport.auth(request);method=request.match_info["method"]
        limit=64*1024*1024 if method=="snapshot" else 1024*1024
        payload=decode(await bounded_body(request,limit),limit)
        result=await self.raft.handle(peer,method,payload)
        return web.Response(body=encode(result),content_type="application/json")
    def access(self,actor,realm,write=False):
        self.state.member(self.db.db,realm,actor,{"worker","trainer","evaluator","admin"})
    async def manifest_get(self,request):
        actor=self.transport.auth(request);realm=request.match_info["realm"];self.access(actor,realm)
        result=self.blobs.manifest(realm,request.match_info["id"])
        return web.Response(body=encode(result,4*1024*1024),content_type="application/json")
    async def piece_get(self,request):
        actor=self.transport.auth(request);realm=request.match_info["realm"];self.access(actor,realm)
        # The lease spans construction and writing, not merely a lookup response.
        with self.blobs.lease_piece(realm,request.match_info["id"]) as data:
            response=web.StreamResponse(status=200,headers={"Content-Type":"application/octet-stream","Content-Length":str(len(data))})
            await response.prepare(request)
            for i in range(0,len(data),65536):await response.write(data[i:i+65536])
            await response.write_eof();return response
    async def piece_put(self,request):
        actor=self.transport.auth(request);realm=request.match_info["realm"];self.access(actor,realm,True)
        data=await bounded_body(request,PIECE_BYTES)
        id=self.blobs.put_piece(realm,data,request.match_info["id"])
        return web.Response(body=encode({"digest":id,"bytes":len(data)}),content_type="application/json")
    async def manifest_put(self,request):
        actor=self.transport.auth(request);realm=request.match_info["realm"];self.access(actor,realm,True)
        m=decode(await bounded_body(request,4*1024*1024),4*1024*1024)
        self.blobs.accept_manifest(realm,m)
        for _ in self.blobs.stream(realm,m["artifact"]):pass
        return web.Response(body=encode({"artifact":m["artifact"],"verified":True}),content_type="application/json")
    async def query(self,request):
        actor=self.transport.auth(request);p=decode(await bounded_body(request))
        fields(p,{"realm","kind"},{"key","parent","limit","cursor"})
        require(p["kind"] in {"realm","member","family","subscription","presence","job","allocation","kv","candidate","evaluation","certificate","channel","canary","cohort","cohort_update","cohort_round"},"QUERY_KIND")
        self.state.member(self.db.db,p["realm"],actor)
        if p["kind"]=="kv":self.access(actor,p["realm"])
        if "key" in p:
            row=self.state.get(self.db.db,p["kind"],p["key"],False)
            require(row is not None and row.get("realm")==p["realm"],"UNAVAILABLE")
            results=[row]; cursor=None
        else:results,cursor=self.state.page(self.db.db,p["kind"],p["realm"],p.get("parent"),p.get("limit",256),p.get("cursor"))
        return web.Response(body=encode({"records":results,"next_cursor":cursor,"consistency":"LOCAL_COMMITTED_MAY_LAG","applied":self.raft.number("applied"),"snapshot_isolated":False}),content_type="application/json")
    async def local_query(self,request):
        self.local_auth(request);p=decode(await bounded_body(request))
        fields(p,{"kind"},{"realm","key","parent","limit","cursor"})
        require(p["kind"] in {"realm","member","family","subscription","presence","job","allocation","kv","candidate","evaluation","certificate","channel","canary","cohort","cohort_update","cohort_round"},"QUERY_KIND")
        if "key" in p:results=[self.state.get(self.db.db,p["kind"],p["key"])]; cursor=None
        else:results,cursor=self.state.page(self.db.db,p["kind"],p.get("realm"),p.get("parent"),p.get("limit",256),p.get("cursor"))
        return web.Response(body=encode({"records":results,"next_cursor":cursor,"consistency":"LOCAL_COMMITTED_MAY_LAG","snapshot_isolated":False}),content_type="application/json")
    async def local_status(self,request):
        self.local_auth(request)
        result={"node_id":self.id,"role":self.raft.role,"leader":self.raft.leader,"term":self.raft.number("term"),"commit":self.raft.number("commit"),"applied":self.raft.number("applied"),
                "discovery":self.discovery.status if self.discovery else "TEST_DISABLED","catalog":self.watcher.status,"resource_policy":self.config["resource_policy"],
                "storage_bytes":self.blobs.usage(),"errors":self.status_errors[-5:],"automatic_spend_atoms":"0","payment_authority":False,
                "native_pq1_qualified":False,"runtime_version":"0.1.0"}
        return web.Response(body=encode(result),content_type="application/json")
    async def local_result(self,request):
        self.local_auth(request);id=request.match_info["id"]
        result=self.state.result(self.db.db,id)
        return web.Response(body=encode({"known":result is not None,"result":result[1] if result else None}),content_type="application/json")
    async def local_import(self,request):
        self.local_auth(request);p=decode(await bounded_body(request));fields(p,{"realm","path"})
        path=Path(p["path"]);require(path.is_file() and not path.is_symlink(),"IMPORT_PATH")
        self.blobs.provision_realm(p["realm"])
        with path.open("rb") as f:result=self.blobs.put_stream(p["realm"],f)
        return web.Response(body=encode(result,4*1024*1024),content_type="application/json")
    async def local_stop(self,request):
        self.local_auth(request);self.stop.set();return web.Response(body=b'{"stopping":true}',content_type="application/json")
    async def maintenance(self):
        parent=int(os.environ.get("BTX_SWARM_PARENT_PID",str(os.getppid())))
        while not self.stop.is_set():
            try:
                await asyncio.to_thread(self.watcher.poll)
                self.reload_peers()
                await self.reconcile_workers()
                if self.raft.number("applied")-self.raft.number("snap_index")>=20000:await self.raft.snapshot()
            except (MeshError,OSError) as e:self.status_errors.append(str(e)[:200])
            if os.environ.get("BTX_SWARM_PARENT_WATCH")=="1" and os.getppid()!=parent:self.stop.set()
            if self.raft.task and self.raft.task.done():
                exc=self.raft.task.exception()
                if exc:self.status_errors.append("FATAL_RAFT:"+str(exc)[:160]);self.stop.set()
            try:await asyncio.wait_for(self.stop.wait(),1)
            except asyncio.TimeoutError:pass
    async def reconcile_workers(self):
        # The global operator budget, not discovery, authorizes background work.
        cfg=decode((self.data/"config.json").read_bytes())
        eligible=set()
        if cfg["resource_policy"]["idle_contribution"]:
            jp=self.data/"joined.json";joined=decode(jp.read_bytes()) if jp.exists() else {}
            eligible.update(r for r,j in joined.items() if set(j["roles"])&{"worker","trainer"})
            for family in self.state.scan(self.db.db,"family"):
                try:self.state.member(self.db.db,family["realm"],self.id,{"worker","trainer"})
                except MeshError:continue
                eligible.add(family["realm"])
        for realm,(worker,task) in list(self.auto_workers.items()):
            if realm not in eligible:worker.stop.set()
            if task.done():
                try:task.result()
                except Exception as e:self.status_errors.append("WORKER:"+str(e)[:160])
                self.auto_workers.pop(realm);self.worker_retry[realm]=time.monotonic()+30
        for realm in eligible-set(self.auto_workers):
            if self.worker_retry.get(realm,0)>time.monotonic():continue
            from .worker import Worker
            worker=Worker(self.data,realm)
            self.auto_workers[realm]=(worker,asyncio.create_task(worker.run()))
    def reload_peers(self):
        path=self.data/"config.json";stamp=path.stat().st_mtime_ns
        if stamp==self.cfg_stamp:return
        cfg=decode(path.read_bytes())
        require(cfg["voters"]==self.config["voters"] and cfg["node_id"]==self.id,"VOTER_RECONFIGURATION_UNSUPPORTED")
        require(set(cfg["voters"])<=set(cfg["peers"]),"VOTER_KEYS_REQUIRED")
        from .transport import cert_pin
        for id,p in cfg["peers"].items():
            require(id==p["identity"],"PEER_IDENTITY")
            if id not in self.transport.peers:
                self.transport.server_ssl.load_verify_locations(cadata=p["certificate"])
        self.transport.peers=cfg["peers"]
        self.transport.client_ssl={id:self.identity.tls([p["certificate"]],False) for id,p in cfg["peers"].items()}
        self.transport.pins={id:cert_pin(p["certificate"]) for id,p in cfg["peers"].items()}
        self.book.pinned=cfg["peers"];self.config=cfg;self.cfg_stamp=stamp
    async def start(self):
        await self.transport.start()
        app=web.Application(middlewares=[errors],client_max_size=64*1024*1024)
        app.router.add_post("/raft/{method}",self.raft_request);app.router.add_post("/command",self.peer_command);app.router.add_post("/query",self.query)
        app.router.add_get("/blobs/{realm}/{id}/manifest",self.manifest_get);app.router.add_post("/blobs/{realm}/manifest",self.manifest_put)
        app.router.add_get("/pieces/{realm}/{id}",self.piece_get);app.router.add_put("/pieces/{realm}/{id}",self.piece_put)
        self.runner=web.AppRunner(app,access_log=None);await self.runner.setup()
        await web.TCPSite(self.runner,self.config["bind_host"],self.config["port"],ssl_context=self.transport.server_ssl).start()
        local=web.Application(middlewares=[errors]);local.router.add_get("/status",self.local_status);local.router.add_post("/command",self.local_command)
        local.router.add_post("/query",self.local_query);local.router.add_get("/result/{id}",self.local_result)
        local.router.add_post("/import",self.local_import);local.router.add_post("/stop",self.local_stop)
        self.local_runner=web.AppRunner(local,access_log=None);await self.local_runner.setup()
        if os.name=="posix":
            sock=local_socket(self.data)
            if sock.exists():
                # Only a socket inside this private directory may be replaced.
                import stat
                require(stat.S_ISSOCK(sock.lstat().st_mode),"LOCAL_SOCKET_PATH");sock.unlink()
            await web.UnixSite(self.local_runner,str(sock)).start();os.chmod(sock,0o600)
        else:
            # Windows ACL/named-pipe packaging is an explicit qualification gap.
            raise MeshError("WINDOWS_LOCAL_IPC_UNQUALIFIED")
        self.raft.start();self.background.append(asyncio.create_task(self.maintenance()))
        if self.discovery:self.background.append(asyncio.create_task(self.discovery.start()))
        return self
    async def close(self):
        self.stop.set()
        for worker,_ in self.auto_workers.values():worker.stop.set()
        if self.discovery:await self.discovery.close()
        await asyncio.gather(*self.background,return_exceptions=True)
        await asyncio.gather(*(task for _,task in self.auto_workers.values()),return_exceptions=True)
        if self.raft.task:
            with contextlib.suppress(Exception):await self.raft.stop()
        if self.local_runner:await self.local_runner.cleanup()
        if self.runner:await self.runner.cleanup()
        await self.transport.close();self.blobs.close();self.book.db.close();self.db.close();self.process_lock.close()


async def serve(args):
    data=Path(args.data)
    initialize(data,args.host,args.port)
    node=SwarmNode(data,catalog=args.catalog)
    loop=asyncio.get_running_loop()
    for sig in (signal.SIGTERM,signal.SIGINT):
        with contextlib.suppress(NotImplementedError):loop.add_signal_handler(sig,node.stop.set)
    try:
        await node.start()
        print(json.dumps({"service":"btx-swarmd","node_id":node.id,"data":str(data),"automatic_spend_atoms":"0"}),flush=True)
        await node.stop.wait()
    finally:await node.close()


def main():
    p=argparse.ArgumentParser(description="BTX default swarm sidecar; monetary consensus unchanged")
    p.add_argument("--data",default=str(Path.home()/".btx"/"modelnet"/"swarm"));p.add_argument("--catalog")
    p.add_argument("--host",default="auto");p.add_argument("--port",type=int,default=29448)
    args=p.parse_args()
    try:asyncio.run(serve(args))
    except (MeshError,OSError) as e:print(json.dumps({"error":getattr(e,"code","DAEMON_START"),"detail":str(e)}),flush=True);raise SystemExit(2)

if __name__=="__main__":main()
