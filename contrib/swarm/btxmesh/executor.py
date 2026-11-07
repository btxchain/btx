"""Finite built-in execution subprocess. No uploaded Python/pickle/dynamic models.

The caller manages and waits for this process group before declaring quiescence.
Private input files are prepared locally from verified artifacts, not arbitrary URLs.
"""
import argparse
import json
import os
from pathlib import Path
from .codec import encode,decode,fields,integer,byte_id
from .errors import MeshError,require
from .storage import atomic_write


def execute(request:dict,output:Path):
    from . import tensors
    root=output.parent.resolve()
    def input_file(name):
        p=(root/name).resolve();require(p.parent==root and p.is_file() and not p.is_symlink(),"EXECUTOR_INPUT");return p
    op=request["executor"];p=request["payload"]
    # Dataset verification is decided here, before any checkpoint is materialized.
    if op=="dataset.verify":
        data=input_file("dataset.safetensors").read_bytes();tensors.inspect(data)
        atomic_write(root/"result.json",encode({"verified_tensor_artifact":byte_id(data),"license_review":"SEPARATE"}))
        return {"artifact_file":"result.json","report":{"bytes":len(data)}}
    if op not in ("torch.train","torch.rollout","inference","torch.evaluate"):raise MeshError("EXECUTOR_UNAVAILABLE",op)
    import torch
    from .runtime import Decoder,generate,checkpoint_config,admit_workload,workload_shape,configured_host_ceiling
    from .training import Trainer
    torch.set_num_threads(request.get("cpu_threads",1))
    torch.set_num_interop_threads(1)
    raw=input_file("model.safetensors").read_bytes()
    cfg=checkpoint_config(raw)
    suite=None
    if op=="torch.evaluate":
        suite=decode(input_file("suite.json").read_bytes())
        require(isinstance(suite["cases"],list) and 1<=len(suite["cases"])<=10000,"SUITE_CASES")
    batch,sequence=workload_shape(op,p,suite)
    ceiling=configured_host_ceiling({"host_bytes":request["host_bytes"]} if "host_bytes" in request else None)
    admit_workload(cfg,batch,sequence,ceiling=ceiling,training=op=="torch.train")
    model=Decoder.from_checkpoint(raw,device="cpu")
    model.host_ceiling=ceiling
    if op=="torch.train":
        integer(p.get("steps",8),1,request["max_steps"])
        seed=p.get("seed",1);integer(seed,0,2**31-1)
        if p.get("dataset")=="synthetic-cycle":
            data=torch.arange(4096,dtype=torch.long)%model.cfg.vocab
        else:
            data=tensors.loads(input_file("dataset.safetensors").read_bytes())["tokens"]
        trainer=Trainer(model,lr_micros=p.get("lr_micros",30000),seed=seed)
        trainer.host_ceiling=ceiling
        report=trainer.train(data,p.get("steps",8),batch_size=p.get("batch",4),sequence=p.get("sequence",16))
        raw=model.checkpoint();atomic_write(root/"result.safetensors",raw)
        atomic_write(root/"training-state.safetensors",trainer.checkpoint())
        return {"artifact_file":"result.safetensors","checkpoint_state_file":"training-state.safetensors","report":report}
    if op in ("torch.rollout","inference"):
        tokens=p["tokens"];integer(len(tokens),1,model.cfg.context-1)
        past=None;offset=request.get("cached_prefix_tokens",0)
        if offset:
            saved=tensors.loads(input_file("past.safetensors").read_bytes())
            past=[(saved[f"{i}.k"],saved[f"{i}.v"]) for i in range(model.cfg.layers)]
        completion,prefix_cache=generate(model,tokens[offset:],max_new_tokens=p.get("max_tokens",8),seed=p.get("seed",1),temperature_milli=p.get("temperature_milli",0),past=past,return_prefix_cache=True)
        atomic_write(root/"prefix.safetensors",tensors.dumps({f"{i}.{name}":t for i,pair in enumerate(prefix_cache) for name,t in zip(("k","v"),pair)}))
        raw=encode({"checkpoint":request["checkpoint"],"completion":completion,"reward":"NOT_SELF_CERTIFIED"})
        atomic_write(root/"result.json",raw)
        return {"artifact_file":"result.json","prefix_cache_file":"prefix.safetensors","report":{"generated_tokens":len(completion),"reused_prefix_tokens":offset,"private_input_exported":False}}
    if op=="torch.evaluate":
        parent=Decoder.from_checkpoint(input_file("parent.safetensors").read_bytes(),device="cpu");model.eval();parent.eval()
        parent.host_ceiling=ceiling
        counts={"00":0,"01":0,"10":0,"11":0}
        ids=set()
        with torch.no_grad():
            for case in suite["cases"]:
                require(case["id"] not in ids,"DUPLICATE_TEST_CASE");ids.add(case["id"])
                prompt=torch.tensor([case["prompt"]],dtype=torch.long)
                a,_=parent(prompt);b,_=model(prompt)
                old=int(a[0,-1].argmax())==case["target"];new=int(b[0,-1].argmax())==case["target"]
                counts[str(int(old))+str(int(new))]+=1
        raw=encode({"counts":counts,"suite_id":byte_id(input_file("suite.json").read_bytes()),"checkpoint":request["checkpoint"],"evaluation":"NEXT_TOKEN_EXACT_TARGET","quality_scope":"THIS_SUITE_ONLY"})
        atomic_write(root/"result.json",raw)
        return {"artifact_file":"result.json","report":{"counts":counts}}
    raise MeshError("EXECUTOR_UNAVAILABLE",op)


def main():
    p=argparse.ArgumentParser();p.add_argument("--request",required=True);p.add_argument("--output",required=True);args=p.parse_args()
    output=Path(args.output)
    try:result=execute(decode(Path(args.request).read_bytes()),output)
    except Exception as e:
        result={"error":getattr(e,"code","EXECUTION_FAILED"),"detail":str(e)[:300]}
    atomic_write(output,encode(result))
    if "error" in result:raise SystemExit(2)

if __name__=="__main__":main()
