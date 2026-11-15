"""Non-voting worker: signed control client, finite subprocess jobs, safe draining.

One identity can participate in multiple realms without acquiring monetary keys.
Input/output artifacts are digest checked; resource grants are not execution proof.
"""
import asyncio
import contextlib
import os
import signal
import sys
import time
from pathlib import Path
from .codec import encode,decode,fields,byte_id,digest
from .errors import require,MeshError
from .identity import Identity
from .storage import atomic_write,private_dir,ProcessLock
from .blobs import BlobStore
from .transport import PeerTransport
from .engines import clean_environment
from .governor import Governor


class Worker:
    def __init__(self,data:Path,realm:str,*,allow_idle=None):
        self.data=Path(data);self.identity=Identity(self.data/"identity");self.config=decode((self.data/"config.json").read_bytes())
        self.realm=realm
        jp=self.data/"joined.json"
        joined=decode(jp.read_bytes()).get(realm) if jp.exists() else None
        if joined:
            for key in ("peers","voters","bootstrap_roots"):self.config[key]=joined[key]
        self.policy=self.config["resource_policy"]
        require(self.policy["idle_contribution"] if allow_idle is None else allow_idle,"COMPUTE_NOT_AUTHORIZED")
        self.workdir=private_dir(self.data/"worker"/realm);self.lock=ProcessLock(self.workdir/"worker.lock")
        self.governor=Governor(self.data);self.governor.reconcile()
        self.store=BlobStore(self.workdir/"blobs",self.config["storage_bytes"])
        keys_path=self.data/"realm-keys.json"
        if keys_path.exists():
            for r,key in decode(keys_path.read_bytes()).items():self.store.provision_realm(r,bytes.fromhex(key))
        self.store.provision_realm(realm)
        self.transport=PeerTransport(self.identity,self.config["peers"])
        self.leader=self.config["voters"][0];self.generation=os.urandom(24).hex();self.stop=asyncio.Event();self.tasks=set();self.current={};self.processes={}
    def grant(self,kind,id,artifact,permission=None):
        if not isinstance(id,str):return False
        # Reload for every gate, including after execution and before publication.
        policy=self.governor.policy()
        g=policy.get(kind+"_grants",{}).get(id,{})
        return (not g.get("revoked",False) and g.get("realm")==self.realm
                and g.get("artifact")==artifact
                and g.get("expires_ms",0)>int(time.time()*1000)
                and (permission is None or permission in g.get("permissions",[])))
    def release_gate(self,payload,checkpoint):
        require(self.governor.policy()["idle_contribution"],"COMPUTE_NOT_AUTHORIZED")
        if "dataset_artifact" in payload:
            require(self.grant("data",payload.get("data_grant_id"),payload["dataset_artifact"],"TRAIN"),"DATA_GRANT_REVOKED")
            require(self.grant("data",payload.get("data_grant_id"),payload["dataset_artifact"],"RELEASE_DERIVATIVE"),"DERIVATIVE_RELEASE_DENIED")
        if payload.get("data_class")!="PUBLIC_SYNTHETIC" and "tokens" in payload:
            require(self.grant("cache",payload.get("cache_grant_id"),checkpoint,"RELEASE_CACHE"),"CACHE_RELEASE_DENIED")
    async def start(self):await self.transport.start();await self.publish_presence();return self
    async def command(self,kind,body,id=None):
        payload={"kind":kind,"body":body,"id":id or os.urandom(24).hex()}
        # A fresh authentication envelope can retry an identical semantic command ID.
        for attempt in range(len(self.config["voters"])+2):
            env=await asyncio.to_thread(self.identity.envelope,payload)
            try:
                result=await self.transport.command(self.leader,env)
                if "error" in result:raise MeshError(result["error"],result.get("detail",""))
                return result
            except MeshError as e:
                if e.code=="NOT_LEADER" and e.detail in self.config["voters"]:self.leader=e.detail
                elif e.code in {"NOT_LEADER","LEADERSHIP_CHANGED","COMMIT_UNKNOWN","PEER_HTTP"}:
                    self.leader=self.config["voters"][attempt%len(self.config["voters"])]
                else:raise
            except (OSError,asyncio.TimeoutError):self.leader=self.config["voters"][attempt%len(self.config["voters"])]
            await asyncio.sleep(.1)
        raise MeshError("CONTROL_UNAVAILABLE")
    async def query(self,kind,key=None):
        p={"realm":self.realm,"kind":kind,"limit":256}
        if key is not None:p["key"]=key
        rows=[];seen=set()
        while True:
            page=decode(await self.transport.raw(self.leader,"POST","/query",body=encode(p)))
            rows.extend(page["records"])
            require(len(rows)<=100000,"WORKER_QUERY_LIMIT")
            cursor=page.get("next_cursor")
            if cursor is None:return rows
            require(cursor not in seen,"QUERY_CURSOR_LOOP");seen.add(cursor);p["cursor"]=cursor
    async def publish_presence(self):
        return await self.command("presence.publish",{"realm":self.realm,"generation":self.generation,"slots":self.policy["slots"],"vram_bytes":self.policy["vram_bytes"],"runtimes":self.policy["allowed_executors"],"expires_ms":int(time.time()*1000)+60000,"checkpoint_ids":[]})
    async def fetch(self,id):
        try:
            for _ in self.store.stream(self.realm,id):pass
        except MeshError:await self.transport.fetch_artifact(self.leader,self.store,self.realm,id)
    async def upload(self,id):
        m=self.store.manifest(self.realm,id)
        for p in m["pieces"]:
            data=self.store.read_piece(self.realm,p["digest"])
            await self.transport.raw(self.leader,"PUT",f'/pieces/{self.realm}/{p["digest"]}',body=data)
        return decode(await self.transport.raw(self.leader,"POST",f"/blobs/{self.realm}/manifest",body=encode(m,4*1024*1024)))
    async def kill(self,process):
        if process.returncode is None:
            if os.name=="posix":os.killpg(process.pid,signal.SIGTERM)
            else:process.terminate()
            try:await asyncio.wait_for(process.wait(),5)
            except asyncio.TimeoutError:
                if os.name=="posix":os.killpg(process.pid,signal.SIGKILL)
                else:process.kill()
                await process.wait()
    async def execute(self,job):
        work=private_dir(self.workdir/job["lease"]);process=None;finished=False;reserved=False;cache_cfg=None
        from . import tensors
        from .kv import KVCache,fingerprint,prefix_should_transfer
        try:
            payload=job["payload"];op=job["executor"];ceiling=self.governor.host_ceiling();host_bytes=0
            if op!="dataset.verify":
                from .runtime import checkpoint_config,admit_workload,workload_shape
                await self.fetch(job["checkpoint"])
                self.store.export_file(self.realm,job["checkpoint"],work/"model.safetensors")
                cfg=checkpoint_config((work/"model.safetensors").read_bytes())
                suite=None
                if op=="torch.evaluate" and "suite_artifact" in payload:
                    await self.fetch(payload["suite_artifact"])
                    self.store.export_file(self.realm,payload["suite_artifact"],work/"suite.json")
                    suite=decode((work/"suite.json").read_bytes())
                batch,sequence=workload_shape(op,payload,suite)
                host_bytes=admit_workload(cfg,batch,sequence,ceiling=ceiling,training=op=="torch.train")
            self.policy=self.governor.acquire(job["lease"],self.realm,job["vram_bytes"],host_bytes=host_bytes);reserved=True
            require(op in self.policy["allowed_executors"],"EXECUTOR_POLICY")
            for key,name in (("dataset_artifact","dataset.safetensors"),("parent_artifact","parent.safetensors"),("suite_artifact","suite.json")):
                if key in payload:
                    if key=="dataset_artifact":require(self.grant("data",payload.get("data_grant_id"),payload[key],"TRAIN"),"DATA_GRANT")
                    await self.fetch(payload[key]);self.store.export_file(self.realm,payload[key],work/name)
            request={"executor":op,"payload":payload,"checkpoint":job["checkpoint"],"cpu_threads":self.policy["cpu_threads"],"max_steps":self.policy["max_steps_per_job"],"host_bytes":ceiling}
            # Exact compatible prefix reuse is automatic for explicitly trusted producers.
            # Public/synthetic jobs may share; private input needs its own grant.
            share=payload.get("data_class")=="PUBLIC_SYNTHETIC" or self.grant("cache",payload.get("cache_grant_id"),job["checkpoint"],"REUSE_CACHE")
            if op in ("torch.rollout","inference") and share:
                from .runtime import checkpoint_kv_config
                cache_cfg=checkpoint_kv_config((work/"model.safetensors").read_bytes());fp=fingerprint(cache_cfg)
                trusted=set(self.config.get("cache_producers",self.config["voters"]))|{self.identity.id}
                for locator in sorted(await self.query("kv"),key=lambda x:-x["tokens"]):
                    n=locator["tokens"];tokens=payload["tokens"]
                    if locator["peer"] not in trusted or locator["fingerprint"]!=fp or n>len(tokens) or locator["expires_ms"]<=int(time.time()*1000):continue
                    if locator["prefix_key"]!=self.store.prefix_key(self.realm,fp,tokens[:n]):continue
                    try:
                        # choose_execution's local-recompute result skips the copy.
                        # The remaining path reads CPU artifacts and does not start an engine.
                        if not prefix_should_transfer(locator):continue
                        await self.transport.fetch_artifact(locator["holder"],self.store,self.realm,locator["artifact"])
                        manifest=decode(self.store.read_bytes(self.realm,locator["artifact"]))
                        for page in manifest["pages"]:await self.transport.fetch_artifact(locator["holder"],self.store,self.realm,page["artifact"])
                        past=KVCache(self.store).load(self.realm,cache_cfg,tokens[:n],locator["artifact"])
                        # Recompute the final input token if the cache spans the full input;
                        # the standard KV handle does not carry trusted logits.
                        used=min(n,len(tokens)-1)
                        if used<1:continue
                        ts={f"{i}.{name}":t[:,:,:used,:] for i,pair in enumerate(past) for name,t in zip(("k","v"),pair)}
                        atomic_write(work/"past.safetensors",tensors.dumps(ts));request["cached_prefix_tokens"]=used;break
                    except MeshError:continue
            atomic_write(work/"request.json",encode(request))
            env=clean_environment({"OMP_NUM_THREADS":str(self.policy["cpu_threads"]),"MKL_NUM_THREADS":str(self.policy["cpu_threads"]),"HF_HUB_OFFLINE":"1"})
            # An installed module is preferred. Development worktrees use a pinned
            # local package directory as cwd, never a model-provided module path.
            package_root=Path(__file__).resolve().parent.parent
            process=await asyncio.create_subprocess_exec(sys.executable,"-m","btxmesh.executor","--request",str(work/"request.json"),"--output",str(work/"response.json"),cwd=package_root,env=env,stdin=asyncio.subprocess.DEVNULL,stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,start_new_session=os.name=="posix")
            self.processes[job["lease"]]=process;self.governor.started(job["lease"],process.pid)
            while process.returncode is None:
                try:await asyncio.wait_for(process.wait(),timeout=1)
                except asyncio.TimeoutError:
                    if self.stop.is_set() or not self.governor.policy()["idle_contribution"]:
                        with contextlib.suppress(Exception):self.governor.cancel(job["lease"])
                        await self.kill(process);raise MeshError("WORKER_STOPPED")
                    # Renew returns only after a current-term majority commits it.
                    await self.command("work.renew",{"job":job["id"],"lease":job["lease"]})
            response=decode((work/"response.json").read_bytes())
            require(process.returncode==0 and "error" not in response,"EXECUTION_FAILED",response.get("detail",""))
            result_path=(work/response["artifact_file"]).resolve();require(result_path.parent==work.resolve(),"RESULT_PATH")
            with result_path.open("rb") as f:m=self.store.put_stream(self.realm,f)
            self.release_gate(payload,job["checkpoint"])
            await self.command("work.renew",{"job":job["id"],"lease":job["lease"]})
            await self.upload(m["artifact"])
            if cache_cfg is not None and "prefix_cache_file" in response:
                ts=tensors.loads((work/response["prefix_cache_file"]).read_bytes())
                cache=[(ts[f"{i}.k"],ts[f"{i}.v"]) for i in range(cache_cfg["layers"])]
                handle=KVCache(self.store).save(self.realm,cache_cfg,payload["tokens"],cache,ttl_ms=300000)
                self.release_gate(payload,job["checkpoint"])
                for page in handle["pages"]:await self.upload(page["artifact"])
                await self.upload(handle["id"])
                await self.command("kv.announce",{"realm":self.realm,"fingerprint":handle["fingerprint"],"prefix_key":handle["prefix_key"],"artifact":handle["id"],"bytes":sum(p["bytes"] for p in handle["pages"]),"expires_ms":handle["expires_ms"],"producer_build":cache_cfg["runtime_build"],"tokens":len(payload["tokens"]),"holder":self.leader})
                response["report"]["kv_handle"]=handle["id"]
            if "checkpoint_state_file" in response:
                state_path=(work/response["checkpoint_state_file"]).resolve();require(state_path.parent==work.resolve(),"RESULT_PATH")
                with state_path.open("rb") as f:state_m=self.store.put_stream(self.realm,f)
                self.release_gate(payload,job["checkpoint"])
                await self.upload(state_m["artifact"]);response["report"]["training_state_artifact"]=state_m["artifact"]
            self.release_gate(payload,job["checkpoint"])
            await self.command("work.finish",{"job":job["id"],"lease":job["lease"],"result_id":m["artifact"],"evidence":response["report"]},id="finish:"+job["lease"])
            finished=True
            return {"job":job["id"],"result_id":m["artifact"],"evidence":response["report"]}
        finally:
            if process:await self.kill(process)
            self.processes.pop(job["lease"],None)
            if reserved:self.governor.release(job["lease"],quiescent=True)
            if not finished:
                # An unacknowledged quiescence is retained in the coordinator ledger;
                # local completion does not silently release a distributed allocation.
                with contextlib.suppress(Exception):await self.command("work.quiesce",{"lease":job["lease"],"generation":self.generation})
    async def claim(self,job_id):
        job=await self.command("work.claim",{"realm":self.realm,"job":job_id,"generation":self.generation,"nonce":os.urandom(24).hex()})
        return await self.execute(job)
    async def run(self,once=False):
        await self.start();last=0
        try:
            while not self.stop.is_set():
                if time.monotonic()-last>20:await self.publish_presence();last=time.monotonic()
                jobs=await self.query("job")
                ready=[j for j in jobs if j["state"]=="QUEUED" and j["executor"] in self.policy["allowed_executors"] and j["deadline_ms"]>int(time.time()*1000)]
                ready.sort(key=lambda j:(-j["priority"],j["deadline_ms"],j["id"]))
                completed=[]
                outcomes=await asyncio.gather(*(self.claim(job["id"]) for job in ready[:self.policy["slots"]]),return_exceptions=True)
                for outcome in outcomes:
                    if isinstance(outcome,MeshError) and outcome.code in {"DEPENDENCY_WAIT","TASK_UNAVAILABLE","SLOTS_EXHAUSTED","DEVICE_SLOTS","ATTEMPT_LIMIT"}:continue
                    if isinstance(outcome,BaseException):raise outcome
                    completed.append(outcome)
                if once:return completed
                try:await asyncio.wait_for(self.stop.wait(),.5)
                except asyncio.TimeoutError:pass
        finally:await self.close()
    async def close(self):
        self.stop.set()
        for p in list(self.processes.values()):await self.kill(p)
        await self.transport.close();self.store.close();self.governor.close();self.lock.close()
