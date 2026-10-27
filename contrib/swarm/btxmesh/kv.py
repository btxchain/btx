"""Exact, block-paged KV manifests and real tensor transfer through BlobStore.

High-speed GPU transfer is supplied by engine connectors, not by serializing
these CPU tensors into JSON. Cross-model approximate reuse is never automatic.
"""
import time
from .codec import encode,decode,digest,fixed_id,fields,integer
from .errors import MeshError,require
from . import tensors

FINGERPRINT_FIELDS={"checkpoint","architecture","tokenizer","adapter_ids","adapter_order","dtype","layout","runtime_build","position_encoding","attention_mask","quantization","tenant_epoch","layers","kv_heads","head_dim"}


def fingerprint(config):
    fields(config,FINGERPRINT_FIELDS)
    for k in ("checkpoint","architecture","tokenizer","runtime_build"):fixed_id(config[k])
    for k in ("layers","kv_heads","head_dim"):integer(config[k],1,4096)
    integer(config["tenant_epoch"],0,2**63-1)
    require(config["layout"]=="BHTD" and config["dtype"] in {"F32","F16","BF16"},"KV_LAYOUT")
    require(config["attention_mask"]=="causal","KV_MASK")
    require(isinstance(config["adapter_ids"],list) and len(config["adapter_ids"])<=64,"KV_ADAPTERS")
    for id in config["adapter_ids"]:fixed_id(id)
    require(sorted(config["adapter_order"])==list(range(len(config["adapter_ids"]))),"KV_ADAPTER_ORDER")
    return digest("BTX/KVFingerprint/1",config)


class KVCache:
    def __init__(self,store,page_tokens=16):
        integer(page_tokens,1,4096);self.store=store;self.page_tokens=page_tokens
    def validate_tensors(self,config,kv,length):
        import torch
        require(len(kv)==config["layers"],"KV_LAYER_COUNT")
        expected_dtype={"F32":torch.float32,"F16":torch.float16,"BF16":torch.bfloat16}[config["dtype"]]
        for k,v in kv:
            require(k.shape==v.shape and list(k.shape)==[1,config["kv_heads"],length,config["head_dim"]],"KV_SHAPE")
            require(k.dtype==v.dtype==expected_dtype,"KV_DTYPE")
            require(bool(torch.isfinite(k).all()) and bool(torch.isfinite(v).all()),"KV_NONFINITE")
    def save(self,realm,config,tokens:list[int],kv,ttl_ms=60000,prior=None):
        fp=fingerprint(config);integer(len(tokens),1,1048576)
        require(all(type(t) is int and 0<=t<2**31 for t in tokens),"TOKEN_IDS")
        integer(ttl_ms,1,3600000);self.validate_tensors(config,kv,len(tokens))
        prefix=self.store.prefix_key(realm,fp,tokens)
        pages=[]
        for start in range(0,len(tokens),self.page_tokens):
            end=min(start+self.page_tokens,len(tokens));reused=None
            if prior and prior["fingerprint"]==fp and prior["realm"]==realm:
                for p in prior["pages"]:
                    if p["start"]==start and p["end"]==end and p["prefix_key"]==self.store.prefix_key(realm,fp,tokens[:end]):
                        reused=p;break
            if reused:pages.append(reused);continue
            ts={f"{i}.{name}":tensor[:,:,start:end,:] for i,pair in enumerate(kv) for name,tensor in zip(("k","v"),pair)}
            raw=tensors.dumps(ts,{"fingerprint":fp,"start":str(start),"end":str(end)})
            artifact=self.store.put_bytes(realm,raw)["artifact"]
            pages.append({"start":start,"end":end,"artifact":artifact,"bytes":len(raw),"prefix_key":self.store.prefix_key(realm,fp,tokens[:end])})
        manifest={"version":1,"realm":realm,"fingerprint":fp,"prefix_key":prefix,"tokens":len(tokens),"pages":pages,"config":config,"expires_ms":int(time.time()*1000)+ttl_ms}
        id=self.store.put_bytes(realm,encode(manifest))["artifact"]
        return {"id":id,**manifest}
    def load(self,realm,config,tokens,handle):
        import torch
        raw=self.store.read_bytes(realm,handle,max_bytes=1024*1024);m=decode(raw)
        fields(m,{"version","realm","fingerprint","prefix_key","tokens","pages","config","expires_ms"})
        fp=fingerprint(config)
        require(m["version"]==1 and m["realm"]==realm and m["fingerprint"]==fp and m["config"]==config,"KV_INCOMPATIBLE")
        require(m["tokens"]==len(tokens) and m["prefix_key"]==self.store.prefix_key(realm,fp,tokens),"KV_PREFIX")
        require(m["expires_ms"]>int(time.time()*1000),"CACHE_EXPIRED")
        layers=[([],[]) for _ in range(config["layers"])];cursor=0
        require(1<=len(m["pages"])<=65536,"KV_PAGES")
        for page in m["pages"]:
            fields(page,{"start","end","artifact","bytes","prefix_key"})
            require(page["start"]==cursor and cursor<page["end"]<=len(tokens),"KV_PAGE_GAP")
            require(page["end"]-cursor<=self.page_tokens,"KV_PAGE_SIZE")
            require(page["prefix_key"]==self.store.prefix_key(realm,fp,tokens[:page["end"]]),"KV_PREFIX")
            raw=self.store.read_bytes(realm,page["artifact"])
            require(len(raw)==page["bytes"],"KV_PAGE_BYTES")
            header=tensors.inspect(raw)
            require(header.get("__metadata__",{})=={"fingerprint":fp,"start":str(cursor),"end":str(page["end"])},"KV_METADATA")
            ts=tensors.loads(raw)
            require(set(ts)=={f"{i}.{suffix}" for i in range(config["layers"]) for suffix in ("k","v")},"KV_TENSORS")
            kv=[(ts[f"{i}.k"],ts[f"{i}.v"]) for i in range(config["layers"])]
            self.validate_tensors(config,kv,page["end"]-cursor)
            for dest,(k,v) in zip(layers,kv):dest[0].append(k);dest[1].append(v)
            cursor=page["end"]
        require(cursor==len(tokens),"KV_INCOMPLETE")
        return [(torch.cat(k,dim=2),torch.cat(v,dim=2)) for k,v in layers]
    def try_load(self,*args):
        try:return self.load(*args)
        except MeshError:return None


def prefix_should_transfer(locator):
    """Whether a remote prefix is worth moving, from choose_execution.

    RECOMPUTE_LOCAL does not transfer. The decision does not attach an engine.
    """
    decision=choose_execution(prefill_ms=locator.get("prefill_ms",0),remote_queue_ms=locator.get("remote_queue_ms",0),local_queue_ms=locator.get("local_queue_ms",0),bytes_to_move=locator["bytes"],bandwidth_bps=locator.get("bandwidth_bps",1),rtt_ms=locator.get("rtt_ms",0),decode_remote_ms=locator.get("decode_remote_ms",0),decode_local_ms=locator.get("decode_local_ms",0))
    return decision["choice"]!="RECOMPUTE_LOCAL"


def choose_execution(*,prefill_ms:int,remote_queue_ms:int,local_queue_ms:int,bytes_to_move:int,bandwidth_bps:int,rtt_ms:int,decode_remote_ms:int=0,decode_local_ms:int=0):
    for n in (prefill_ms,remote_queue_ms,local_queue_ms,bytes_to_move,rtt_ms,decode_remote_ms,decode_local_ms):integer(n,0,2**63-1)
    integer(bandwidth_bps,1,2**63-1)
    choices={"RECOMPUTE_LOCAL":local_queue_ms+prefill_ms+decode_local_ms,
             "TRANSFER_KV":local_queue_ms+rtt_ms+(bytes_to_move*8*1000+bandwidth_bps-1)//bandwidth_bps+decode_local_ms,
             "ROUTE_TO_OWNER":remote_queue_ms+rtt_ms+decode_remote_ms}
    winner=min(choices,key=lambda k:(choices[k],k))
    return {"choice":winner,"estimates_ms":choices,"measured_benchmark":False}
