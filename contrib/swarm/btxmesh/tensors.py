"""Tensor transport validator; does not load pickle or torch.load checkpoints."""
import json
import math
import struct
from .codec import byte_id
from .errors import require, MeshError

WIDTH={"F64":8,"F32":4,"F16":2,"BF16":2,"I64":8,"I32":4,"I16":2,"I8":1,"U8":1,"BOOL":1}


def inspect(data:bytes,max_bytes=256*1024*1024,max_tensors=8192):
    require(8<=len(data)<=max_bytes,"TENSOR_BYTES")
    n=struct.unpack("<Q",data[:8])[0]
    require(2<=n<=1024*1024 and 8+n<=len(data),"TENSOR_HEADER")
    def unique(items):
        d={}
        for k,v in items:
            require(k not in d,"TENSOR_DUPLICATE_KEY");d[k]=v
        return d
    try:h=json.loads(data[8:8+n],object_pairs_hook=unique)
    except (ValueError,UnicodeError) as e:raise MeshError("TENSOR_HEADER") from e
    require(type(h) is dict and len(h)<=max_tensors+1,"TENSOR_COUNT")
    ranges=[]
    for name,t in h.items():
        require(isinstance(name,str) and len(name)<=256,"TENSOR_NAME")
        if name=="__metadata__":
            require(type(t) is dict and all(isinstance(k,str) and isinstance(v,str) for k,v in t.items()),"TENSOR_METADATA")
            continue
        require(type(t) is dict and set(t)=={"dtype","shape","data_offsets"},"TENSOR_SCHEMA")
        require(t["dtype"] in WIDTH and isinstance(t["shape"],list) and len(t["shape"])<=8,"TENSOR_DTYPE_SHAPE")
        require(all(type(d) is int and 0<=d<=2**31-1 for d in t["shape"]),"TENSOR_SHAPE")
        expected=math.prod(t["shape"])*WIDTH[t["dtype"]]
        offsets=t["data_offsets"]
        require(isinstance(offsets,list) and len(offsets)==2 and all(type(x) is int for x in offsets),"TENSOR_OFFSETS")
        a,b=offsets;require(0<=a<=b<=len(data)-8-n and b-a==expected,"TENSOR_BOUNDS")
        ranges.append((a,b))
    ranges.sort();last=0
    for a,b in ranges:
        require(a==last,"TENSOR_GAP_OVERLAP");last=b
    require(last==len(data)-8-n,"TENSOR_TRAILING")
    return h


def dumps(tensors:dict,metadata=None):
    import torch
    from safetensors.torch import save
    require(all(isinstance(v,torch.Tensor) and v.layout==torch.strided for v in tensors.values()),"TENSOR_TYPE")
    raw=save({k:v.detach().cpu().contiguous() for k,v in tensors.items()},metadata=metadata)
    n=struct.unpack("<Q",raw[:8])[0]
    # Rust HashMap metadata order is not deterministic; canonicalize the header
    # while preserving the tensor data order and offsets produced by safetensors.
    h=json.loads(raw[8:8+n]);head=json.dumps(h,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    head += b" "*((-len(head))%8)
    return struct.pack("<Q",len(head))+head+raw[8+n:]


def loads(data:bytes,max_bytes=256*1024*1024,finite=True):
    import torch
    from safetensors.torch import load
    inspect(data,max_bytes)
    ts=load(data)
    if finite:
        require(all(not v.is_floating_point() or bool(torch.isfinite(v).all()) for v in ts.values()),"NONFINITE_TENSOR")
    return ts
