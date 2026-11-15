"""Auto-selected integrations with established engines, not replacement GPU kernels.

Generated switches are implementation details: operators choose budgets and trust
policy, not independent feature flags. A plan is not an executed hardware test.
"""
import asyncio
import importlib.util
import importlib.metadata
import json
import os
import shutil
import sys
from dataclasses import dataclass,asdict
from pathlib import Path
from urllib.parse import urlparse
import aiohttp
from .codec import byte_id,digest,encode,integer
from .errors import require,MeshError
from .storage import atomic_write


def installed(name):
    try:return importlib.util.find_spec(name) is not None
    except (ImportError,ValueError,ModuleNotFoundError):return False


def capabilities():
    modules={n:installed(n) for n in ("torch","vllm","sglang","lmcache","nixl","mooncake","hivemind","transformers")}
    versions={}
    for n,yes in modules.items():
        if yes:
            try:versions[n]=importlib.metadata.version(n)
            except importlib.metadata.PackageNotFoundError:versions[n]="package metadata unavailable"
    gpu=[]
    if modules["torch"]:
        import torch
        if torch.cuda.is_available():
            for i in range(torch.cuda.device_count()):
                p=torch.cuda.get_device_properties(i)
                gpu.append({"index":i,"name":p.name,"vram_bytes":p.total_memory,"capability":list(torch.cuda.get_device_capability(i))})
    return {"modules":modules,"versions":versions,"gpus":gpu,"hardware_qualified":False,"auto_acceleration":True}


@dataclass
class EnginePlan:
    engine:str
    argv:list[str]
    environment:dict
    features:list[str]
    qualified:bool=False
    qualification:str="GENERATED_NOT_EXECUTED"
    def json(self):return asdict(self)


def plan_engine(engine:str,model_dir:Path,workdir:Path,*,host="127.0.0.1",port=29501,host_cache_gib=4,gpu_memory_percent=80,available=None):
    available=available or capabilities()["modules"]
    path=Path(model_dir).resolve();require(path.is_dir(),"MODEL_DIRECTORY")
    require((path/"config.json").is_file(),"MODEL_CONFIG")
    require(host in ("127.0.0.1","::1"),"ENGINE_PRIVATE_BIND")
    integer(port,1024,65535);integer(host_cache_gib,1,1024);integer(gpu_memory_percent,10,95)
    workdir=Path(workdir);workdir.mkdir(parents=True,exist_ok=True)
    env={"HF_HUB_OFFLINE":"1","TRANSFORMERS_OFFLINE":"1","DO_NOT_TRACK":"1"}
    if engine=="auto":
        engine="vllm" if available.get("vllm") else ("sglang" if available.get("sglang") else "torch")
    if engine=="vllm":
        require(available.get("vllm"),"ENGINE_UNAVAILABLE")
        args=[sys.executable,"-m","vllm.entrypoints.openai.api_server","--model",str(path),"--host",host,"--port",str(port),"--gpu-memory-utilization",str(gpu_memory_percent/100),"--enable-prefix-caching"]
        features=["exact_prefix","continuous_batching"]
        if available.get("lmcache"):
            cfg=workdir/"lmcache.yaml"
            atomic_write(cfg,f"chunk_size: 256\nlocal_cpu: true\nmax_local_cpu_size: {host_cache_gib}\n".encode())
            env["LMCACHE_CONFIG_FILE"]=str(cfg)
            args += ["--kv-transfer-config",json.dumps({"kv_connector":"LMCacheConnectorV1","kv_role":"kv_both"},separators=(",",":"))]
            features += ["lmcache_connector","host_kv_tier"]
        return EnginePlan(engine,args,env,features)
    if engine=="sglang":
        require(available.get("sglang"),"ENGINE_UNAVAILABLE")
        args=[sys.executable,"-m","sglang.launch_server","--model-path",str(path),"--host",host,"--port",str(port),"--mem-fraction-static",str(gpu_memory_percent/100),"--enable-hierarchical-cache"]
        return EnginePlan(engine,args,env,["radix_prefix","hierarchical_kv","continuous_batching"])
    raise MeshError("ENGINE_PLAN_UNAVAILABLE","reference Torch decoder is an in-process executor; unsupported engines are not pretended ready")


def clean_environment(extra):
    # An allowlist is essential: a blacklist misses cloud/provider credentials.
    allowed={"PATH","HOME","USER","LOGNAME","LANG","LC_ALL","LC_CTYPE",
             "TMPDIR","TMP","TEMP","SYSTEMROOT","WINDIR","TZ",
             "CUDA_VISIBLE_DEVICES","HIP_VISIBLE_DEVICES","ROCR_VISIBLE_DEVICES",
             "NVIDIA_VISIBLE_DEVICES","NVIDIA_DRIVER_CAPABILITIES",
             "OMP_NUM_THREADS","MKL_NUM_THREADS","OPENBLAS_NUM_THREADS"}
    keep={k:v for k,v in os.environ.items() if k in allowed}
    permitted_extra=allowed|{"HF_HUB_OFFLINE","TRANSFORMERS_OFFLINE","DO_NOT_TRACK","LMCACHE_CONFIG_FILE"}
    require(set(extra)<=permitted_extra,"ENGINE_ENVIRONMENT")
    keep.update(extra)
    return keep


class EngineProcess:
    def __init__(self,plan:EnginePlan):self.plan=plan;self.process=None
    async def start(self):
        require(self.process is None,"ENGINE_ALREADY_RUNNING")
        self.process=await asyncio.create_subprocess_exec(*self.plan.argv,env=clean_environment(self.plan.environment),stdin=asyncio.subprocess.DEVNULL,start_new_session=os.name=="posix")
        return {"pid":self.process.pid,"state":"STARTING","hardware_qualified":False}
    async def stop(self):
        if self.process is None:return
        if self.process.returncode is None:
            if os.name=="posix":
                import signal;os.killpg(self.process.pid,signal.SIGTERM)
            else:self.process.terminate()
            try:await asyncio.wait_for(self.process.wait(),20)
            except asyncio.TimeoutError:
                if os.name=="posix":os.killpg(self.process.pid,signal.SIGKILL)
                else:self.process.kill()
                await self.process.wait()
        # Memory leases may now be released for this managed process, not on timeout alone.
        return {"physical_quiescent":True,"returncode":self.process.returncode}


class InferenceClient:
    def __init__(self,endpoint:str,model_name:str,*,approved_endpoints:set[str],allow_private:bool=False):
        require(endpoint in approved_endpoints,"PROVIDER_NOT_AUTHORIZED")
        parsed=urlparse(endpoint)
        require(parsed.scheme=="https" or (parsed.scheme=="http" and parsed.hostname in ("127.0.0.1","::1","localhost")),"PROVIDER_TLS")
        require(parsed.username is None and parsed.password is None,"URL_CREDENTIALS")
        self.endpoint,self.model,self.allow_private=endpoint.rstrip("/"),model_name,allow_private
    async def complete(self,prompt:str,max_tokens=256,*,private=False):
        require(not private or self.allow_private,"PRIVATE_PROMPT_GRANT")
        integer(max_tokens,1,32768);require(len(prompt.encode())<=4*1024*1024,"PROMPT_LIMIT")
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300)) as session:
            async with session.post(self.endpoint+"/v1/completions",json={"model":self.model,"prompt":prompt,"max_tokens":max_tokens,"temperature":0},allow_redirects=False) as resp:
                require(resp.status==200,"INFERENCE_HTTP",str(resp.status))
                require(resp.content_length is None or resp.content_length<=16*1024*1024,"INFERENCE_BODY")
                raw=await resp.content.read(16*1024*1024+1);require(len(raw)<=16*1024*1024,"INFERENCE_BODY")
                result=json.loads(raw)
                require(isinstance(result.get("choices"),list) and len(result["choices"])>=1,"INFERENCE_SCHEMA")
                return {"text":result["choices"][0]["text"],"model":result.get("model",self.model),"raw_digest":byte_id(raw),"cached_tokens_reported":result.get("usage",{}).get("prompt_tokens_details",{}).get("cached_tokens",0)}
