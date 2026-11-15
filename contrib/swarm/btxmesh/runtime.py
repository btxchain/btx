"""A real causal PyTorch decoder used to execute portable acceptance tests.

This is a deliberately small qualification workload, not BTX's production model
or a claim that large-model kernels have been recreated. Production engines use
the adapters in engines.py. Exact cache interchange is always fingerprinted.
"""
from dataclasses import dataclass,asdict
import math
import time
import torch
from torch import nn
from torch.nn import functional as F
from .codec import digest,encode,decode,byte_id,fields,integer
from .errors import MeshError,require
from . import tensors

# Caller-supplied ceilings replace this. A missing ceiling is 2 GiB.
DEFAULT_HOST_BYTES=2*1024**3


@dataclass(frozen=True)
class DecoderConfig:
    vocab:int=256
    width:int=64
    layers:int=2
    heads:int=4
    context:int=256
    def validate(self):
        integer(self.vocab,2,65536);integer(self.width,8,4096);integer(self.layers,1,96)
        integer(self.heads,1,128);integer(self.context,8,32768)
        require(self.width%self.heads==0,"HEAD_DIMENSION")
        require(parameter_elements(self)<100_000_000,"REFERENCE_MODEL_LIMIT")
        return self


def parameter_elements(cfg):
    """Reference weights, including the positional table and the output head.

    The square term is qkv, out, up, and down. Token rows, position rows, and
    the untied head are each width times their vocabulary or context.
    """
    return cfg.layers*cfg.width*cfg.width*12+cfg.vocab*cfg.width+cfg.context*cfg.width+cfg.vocab*cfg.width


def attention_bytes(batch,heads,sequence):
    # One float32 score matrix. The product is arithmetic; it does not allocate.
    return batch*heads*sequence*sequence*4


def logit_bytes(batch,sequence,vocab):
    # One float32 score per position and token.
    return batch*sequence*vocab*4


def host_byte_budget(cfg,batch,sequence,training=True):
    """Parameters, gradients, SGD momentum, and the activations of one step.

    Training keeps each layer's softmax and causal mask for backward, about
    twenty width-sized activations per layer, and the logits with their
    log-softmax and both gradients. Inference keeps none of it. The factors
    cover peak RSS measured on CPU with torch 2.10.
    """
    parameters=parameter_elements(cfg)*4
    attention=attention_bytes(batch,cfg.heads,sequence)
    activation=batch*sequence*cfg.width*4
    logits=logit_bytes(batch,sequence,cfg.vocab)
    if training:return 3*parameters+(5*cfg.layers+12)*attention//4+20*cfg.layers*activation+4*logits
    return 3*parameters+3*attention+4*cfg.layers*activation+2*logits


def configured_host_ceiling(policy=None):
    if not isinstance(policy,dict) or "host_bytes" not in policy:return DEFAULT_HOST_BYTES
    return integer(policy["host_bytes"],1,2**62,"HOST_BUDGET")


def admit_workload(cfg,batch,sequence,ceiling=None,training=True):
    """Reject a legal shape whose bytes cannot fit before any tensor exists."""
    ceiling=DEFAULT_HOST_BYTES if ceiling is None else integer(ceiling,1,2**62,"HOST_BUDGET")
    integer(batch,1,256);integer(sequence,1,32768)
    attention=attention_bytes(batch,cfg.heads,sequence)
    budget=host_byte_budget(cfg,batch,sequence,training)
    require(attention<=ceiling,"HOST_BUDGET")
    require(budget<=ceiling,"HOST_BUDGET")
    return budget


def workload_shape(op,payload,suite=None):
    if op=="torch.train":return payload.get("batch",4),payload.get("sequence",16)
    if op in ("torch.rollout","inference"):
        tokens=payload.get("tokens") or []
        return payload.get("batch",1),payload["sequence"] if "sequence" in payload else len(tokens)
    if op=="torch.evaluate":
        longest=1
        if suite is not None:
            cases=suite.get("cases") or []
            if cases:longest=max(len(case["prompt"]) for case in cases)
        if "sequence" in payload:return payload.get("batch",1),max(payload["sequence"],longest)
        return payload.get("batch",1),longest
    raise MeshError("EXECUTOR_UNAVAILABLE",op)


def checkpoint_config(raw:bytes):
    header=tensors.inspect(raw,max_bytes=1024*1024*1024)
    meta=header.get("__metadata__",{})
    require(meta.get("format")=="BTX-TORCH-DECODER/1","CHECKPOINT_FORMAT")
    return DecoderConfig(**decode(meta["config"].encode())).validate()


class AttentionBlock(nn.Module):
    def __init__(self,cfg):
        super().__init__();self.cfg=cfg
        self.ln1=nn.LayerNorm(cfg.width);self.qkv=nn.Linear(cfg.width,3*cfg.width,bias=False)
        self.out=nn.Linear(cfg.width,cfg.width,bias=False)
        self.ln2=nn.LayerNorm(cfg.width);self.up=nn.Linear(cfg.width,4*cfg.width)
        self.down=nn.Linear(4*cfg.width,cfg.width)
    def forward(self,x,past=None):
        b,t,w=x.shape;d=w//self.cfg.heads;k_len=t
        if past is not None:
            require(past[0].shape[:2]==(b,self.cfg.heads) and past[0].shape==past[1].shape,"PAST_SHAPE")
            k_len=past[0].shape[2]+t
        require(b*self.cfg.heads*t*k_len*4<=getattr(self,"host_ceiling",DEFAULT_HOST_BYTES),"HOST_BUDGET")
        q,k,v=self.qkv(self.ln1(x)).chunk(3,dim=-1)
        q,k,v=[a.view(b,t,self.cfg.heads,d).transpose(1,2) for a in (q,k,v)]
        offset=0
        if past is not None:
            offset=past[0].shape[2];k=torch.cat((past[0].to(x.device),k),dim=2);v=torch.cat((past[1].to(x.device),v),dim=2)
        mask=torch.arange(k.shape[2],device=x.device)[None,:] <= (offset+torch.arange(t,device=x.device))[:,None]
        score=(q@k.transpose(-1,-2))/math.sqrt(d)
        score=score.masked_fill(~mask,float("-inf"))
        y=(score.softmax(dim=-1)@v).transpose(1,2).contiguous().view(b,t,w)
        x=x+self.out(y);x=x+self.down(F.gelu(self.up(self.ln2(x))))
        return x,(k,v)


class Decoder(nn.Module):
    def __init__(self,cfg=DecoderConfig()):
        super().__init__();self.cfg=cfg.validate()
        self.token=nn.Embedding(cfg.vocab,cfg.width);self.position=nn.Embedding(cfg.context,cfg.width)
        self.blocks=nn.ModuleList(AttentionBlock(cfg) for _ in range(cfg.layers))
        self.norm=nn.LayerNorm(cfg.width);self.head=nn.Linear(cfg.width,cfg.vocab,bias=False)
    def forward(self,ids,past=None):
        require(ids.ndim==2 and ids.shape[1]>0,"INPUT_SHAPE")
        require(ids.dtype==torch.long and bool(((ids>=0)&(ids<self.cfg.vocab)).all()),"TOKEN_RANGE")
        if past is not None:require(len(past)==self.cfg.layers,"PAST_LAYERS")
        offset=past[0][0].shape[2] if past else 0
        require(offset+ids.shape[1]<=self.cfg.context,"CONTEXT_LIMIT")
        # Stop before the embedding activation or the score matrix is built.
        attention=int(ids.shape[0])*self.cfg.heads*int(ids.shape[1])*(offset+int(ids.shape[1]))*4
        ceiling=getattr(self,"host_ceiling",DEFAULT_HOST_BYTES)
        require(attention<=ceiling,"HOST_BUDGET")
        x=self.token(ids)+self.position(torch.arange(offset,offset+ids.shape[1],device=ids.device))[None,:,:]
        present=[]
        for i,block in enumerate(self.blocks):
            block.host_ceiling=ceiling
            x,kv=block(x,past[i] if past else None);present.append(kv)
        return self.head(self.norm(x)),present
    def checkpoint(self):
        return tensors.dumps(self.state_dict(),{"format":"BTX-TORCH-DECODER/1","config":encode(asdict(self.cfg)).decode()})
    @classmethod
    def from_checkpoint(cls,raw,device="cpu"):
        header=tensors.inspect(raw,max_bytes=1024*1024*1024)
        meta=header.get("__metadata__",{})
        require(meta.get("format")=="BTX-TORCH-DECODER/1","CHECKPOINT_FORMAT")
        cfg=DecoderConfig(**decode(meta["config"].encode())).validate()
        model=cls(cfg);state=tensors.loads(raw,max_bytes=1024*1024*1024)
        require(set(state)==set(model.state_dict()),"CHECKPOINT_KEYS")
        for name,t in state.items():require(t.shape==model.state_dict()[name].shape and t.dtype==model.state_dict()[name].dtype,"CHECKPOINT_SHAPE")
        model.load_state_dict(state,strict=True);return model.to(device)
    def kv_config(self):
        weights=self.checkpoint()
        return {"checkpoint":byte_id(weights),"architecture":digest("BTX/ReferenceArchitecture/1",asdict(self.cfg)),
                "tokenizer":digest("BTX/ByteTokenizer/1",{"vocab":self.cfg.vocab}),"adapter_ids":[],"adapter_order":[],"dtype":"F32","layout":"BHTD",
                "runtime_build":digest("BTX/TorchRuntime/1",{"torch":torch.__version__.split("+")[0],"implementation":"BTX-TORCH-DECODER/1"}),
                "position_encoding":"learned-absolute","attention_mask":"causal","quantization":"none","tenant_epoch":0,
                "layers":self.cfg.layers,"kv_heads":self.cfg.heads,"head_dim":self.cfg.width//self.cfg.heads}


@torch.no_grad()
def generate(model:Decoder,tokens:list[int],max_new_tokens:int=16,seed:int=0,temperature_milli:int=0,past=None,return_prefix_cache=False):
    integer(max_new_tokens,1,4096);integer(temperature_milli,0,5000)
    model.eval();device=next(model.parameters()).device
    ids=torch.tensor([tokens],dtype=torch.long,device=device)
    logits,cache=model(ids,past=past);prefix_cache=cache;out=[]
    rng=torch.Generator(device=device).manual_seed(seed)
    for i in range(max_new_tokens):
        last=logits[:,-1,:]
        if temperature_milli:
            tok=torch.multinomial((last/(temperature_milli/1000)).softmax(-1),1,generator=rng)
        else:tok=last.argmax(-1,keepdim=True)
        out.append(int(tok.item()))
        if i+1<max_new_tokens:logits,cache=model(tok,past=cache)
    return (out,prefix_cache) if return_prefix_cache else out


def checkpoint_kv_config(raw:bytes):
    cfg=checkpoint_config(raw)
    return {"checkpoint":byte_id(raw),"architecture":digest("BTX/ReferenceArchitecture/1",asdict(cfg)),
            "tokenizer":digest("BTX/ByteTokenizer/1",{"vocab":cfg.vocab}),"adapter_ids":[],"adapter_order":[],"dtype":"F32","layout":"BHTD",
            "runtime_build":digest("BTX/TorchRuntime/1",{"torch":torch.__version__.split("+")[0],"implementation":"BTX-TORCH-DECODER/1"}),
            "position_encoding":"learned-absolute","attention_mask":"causal","quantization":"none","tenant_epoch":0,
            "layers":cfg.layers,"kv_heads":cfg.heads,"head_dim":cfg.width//cfg.heads}
