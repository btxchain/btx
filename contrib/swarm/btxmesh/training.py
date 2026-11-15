"""Actual local SGD, compatible-update aggregation, and grouped policy gradients.

Local-SGD outer aggregation is not advertised as a reproduction of Decoupled
DiLoCo. Large production training is delegated to separately qualified runtimes.
"""
from dataclasses import asdict
import hashlib
import time
import torch
from torch.nn import functional as F
from .runtime import Decoder,admit_workload
from .codec import byte_id,digest,encode,decode,integer,fields
from .errors import MeshError,require
from . import tensors


class Trainer:
    def __init__(self,model:Decoder,*,lr_micros=30000,momentum_milli=900,seed=1):
        integer(lr_micros,1,1000000);integer(momentum_milli,0,999)
        self.model=model;self.step=0
        self.lr_micros,self.momentum_milli,self.seed=lr_micros,momentum_milli,seed
        self.optimizer=torch.optim.SGD(model.parameters(),lr=lr_micros/1000000,momentum=momentum_milli/1000)
        self.generator=torch.Generator(device="cpu").manual_seed(seed)
        self.tokens_seen=0;self.dataset_id=None;self.cursor=0
    def train(self,data:torch.Tensor,steps:int,batch_size=4,sequence=16):
        integer(steps,1,4096);integer(batch_size,1,256);integer(sequence,2,self.model.cfg.context)
        if getattr(self,"host_ceiling",None) is not None:self.model.host_ceiling=self.host_ceiling
        admit_workload(self.model.cfg,batch_size,sequence,ceiling=getattr(self,"host_ceiling",None))
        require(data.ndim==1 and data.dtype==torch.long and len(data)>sequence,"TRAINING_DATA")
        data_id=byte_id(tensors.dumps({"tokens":data}))
        require(self.dataset_id in (None,data_id),"DATASET_CHANGED")
        self.dataset_id=data_id;device=next(self.model.parameters()).device;losses=[]
        self.model.train()
        for _ in range(steps):
            starts=torch.randint(0,len(data)-sequence,(batch_size,),generator=self.generator)
            x=torch.stack([data[s:s+sequence] for s in starts]).to(device)
            y=torch.stack([data[s+1:s+sequence+1] for s in starts]).to(device)
            logits,_=self.model(x);loss=F.cross_entropy(logits.flatten(0,1),y.flatten())
            require(bool(torch.isfinite(loss)),"LOSS_NONFINITE")
            self.optimizer.zero_grad(set_to_none=True);loss.backward()
            torch.nn.utils.clip_grad_norm_(self.model.parameters(),1.0,error_if_nonfinite=True)
            self.optimizer.step();self.step+=1;self.cursor+=batch_size;self.tokens_seen+=batch_size*sequence
            losses.append(int(float(loss.detach())*1000000))
        return {"steps":steps,"total_steps":self.step,"tokens_seen":self.tokens_seen,"loss_micros":losses,"dataset_id":self.dataset_id}
    def checkpoint(self):
        state={"model."+name:t for name,t in self.model.state_dict().items()}
        for name,p in self.model.named_parameters():
            mom=self.optimizer.state[p].get("momentum_buffer")
            if mom is not None:state["momentum."+name]=mom
        state["rng.cpu"]=self.generator.get_state()
        meta={"format":"BTX-TRAIN-STATE/1","config":encode(asdict(self.model.cfg)).decode(),
              "step":str(self.step),"tokens_seen":str(self.tokens_seen),"cursor":str(self.cursor),"lr_micros":str(self.lr_micros),
              "momentum_milli":str(self.momentum_milli),"seed":str(self.seed),"dataset_id":self.dataset_id or ""}
        return tensors.dumps(state,meta)
    @classmethod
    def restore(cls,raw,device="cpu"):
        from .runtime import DecoderConfig
        h=tensors.inspect(raw,max_bytes=2*1024**3);meta=h.get("__metadata__",{})
        require(meta.get("format")=="BTX-TRAIN-STATE/1","TRAIN_STATE_FORMAT")
        model=Decoder(DecoderConfig(**decode(meta["config"].encode()))).to(device)
        trainer=cls(model,lr_micros=int(meta["lr_micros"]),momentum_milli=int(meta["momentum_milli"]),seed=int(meta["seed"]))
        ts=tensors.loads(raw,max_bytes=2*1024**3)
        expected={"model."+k for k in model.state_dict()}|{"rng.cpu"}
        allowable=expected|{"momentum."+k for k,_ in model.named_parameters()}
        require(expected<=set(ts)<=allowable,"TRAIN_STATE_KEYS")
        state={k:ts["model."+k] for k in model.state_dict()}
        for name,t in state.items():require(t.shape==model.state_dict()[name].shape,"TRAIN_STATE_SHAPE")
        model.load_state_dict(state,strict=True)
        for name,p in model.named_parameters():
            key="momentum."+name
            if key in ts:
                require(ts[key].shape==p.shape,"MOMENTUM_SHAPE")
                trainer.optimizer.state[p]["momentum_buffer"]=ts[key].to(device)
        trainer.generator.set_state(ts["rng.cpu"])
        trainer.step=int(meta["step"]);trainer.cursor=int(meta["cursor"]);trainer.tokens_seen=int(meta["tokens_seen"])
        trainer.dataset_id=meta["dataset_id"] or None
        return trainer


class Cohort:
    """One exact base and recipe per aggregation round; no arbitrary model averaging."""
    def __init__(self,base:dict,base_checkpoint:str,recipe_id:str,*,round_index=0,min_islands=2,max_tokens=10**9,clip_micros=1000000):
        self.base={k:v.detach().cpu().clone() for k,v in base.items()}
        require(all(t.is_floating_point() and bool(torch.isfinite(t).all()) for t in self.base.values()),"COHORT_PARAMETERS")
        self.base_checkpoint,self.recipe_id,self.round=base_checkpoint,recipe_id,round_index
        self.min_islands,self.max_tokens,self.clip=min_islands,max_tokens,clip_micros/1000000
        self.updates={};self.outer_velocity={k:torch.zeros_like(t) for k,t in self.base.items()}
    def update(self,peer:str,manifest:dict,raw:bytes):
        fields(manifest,{"base_checkpoint","recipe_id","round","tokens","artifact","island_generation"})
        require(manifest["base_checkpoint"]==self.base_checkpoint and manifest["recipe_id"]==self.recipe_id and manifest["round"]==self.round,"INCOMPATIBLE_UPDATE")
        require(peer not in self.updates,"DUPLICATE_ISLAND")
        integer(manifest["tokens"],1,self.max_tokens)
        require(byte_id(raw)==manifest["artifact"],"UPDATE_DIGEST")
        update=tensors.loads(raw,max_bytes=2*1024**3)
        require(set(update)==set(self.base),"UPDATE_KEYS")
        for name,t in update.items():require(t.shape==self.base[name].shape and t.dtype==self.base[name].dtype,"UPDATE_SHAPE_DTYPE")
        delta={name:t-self.base[name] for name,t in update.items()}
        norm=torch.sqrt(sum((d.double()*d.double()).sum() for d in delta.values()))
        scale=min(1.0,self.clip/max(float(norm),1e-30))
        self.updates[peer]={"delta":{k:d*scale for k,d in delta.items()},"tokens":manifest["tokens"],"generation":manifest["island_generation"],"norm_micros":int(float(norm)*1000000)}
        return {"accepted":True,"contributors":len(self.updates),"clipped":scale<1,"quality_proven":False}
    def aggregate(self,*,outer_lr_milli=1000,outer_momentum_milli=0):
        require(len(self.updates)>=self.min_islands,"ISLAND_QUORUM")
        integer(outer_lr_milli,1,2000);integer(outer_momentum_milli,0,999)
        total=sum(x["tokens"] for x in self.updates.values())
        result={}
        for name,base in self.base.items():
            delta=sum((u["delta"][name].double()*u["tokens"]/total for _,u in sorted(self.updates.items())),torch.zeros_like(base,dtype=torch.float64)).to(base.dtype)
            velocity=self.outer_velocity[name]* (outer_momentum_milli/1000)+delta
            self.outer_velocity[name]=velocity
            result[name]=base+(outer_lr_milli/1000)*velocity
        require(all(bool(torch.isfinite(t).all()) for t in result.values()),"AGGREGATE_NONFINITE")
        receipt={"base_checkpoint":self.base_checkpoint,"recipe_id":self.recipe_id,"round":self.round,"islands":sorted(self.updates),"tokens":total,"algorithm":"BOUNDED_LOCAL_SGD_OUTER_MOMENTUM_V1"}
        return result,receipt


class TrajectoryBuffer:
    def __init__(self,db):
        self.db=db
        db.db.execute("CREATE TABLE IF NOT EXISTS trajectory(id TEXT PRIMARY KEY,checkpoint TEXT,body TEXT,consumed INTEGER DEFAULT 0)")
    def add(self,trajectory:dict,*,data_grant:dict,requester:str):
        fields(trajectory,{"checkpoint","prompt","completion","reward_micros","group","source_id"})
        require(data_grant.get("owner")==requester and data_grant.get("training") is True and data_grant.get("source_id")==trajectory["source_id"],"DATA_GRANT")
        require(data_grant.get("visibility") in ("public","synthetic","realm-consented"),"DATA_VISIBILITY")
        integer(trajectory["reward_micros"],-10**9,10**9)
        require(len(trajectory["prompt"])+len(trajectory["completion"])<=32768 and len(trajectory["completion"])>0,"TRAJECTORY_LIMIT")
        id=digest("BTX/TrainingTrajectory/1",trajectory)
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO trajectory(id,checkpoint,body) VALUES(?,?,?)",(id,trajectory["checkpoint"],encode(trajectory).decode()))
        return id
    def groups(self,checkpoint,limit=128):
        rows=self.db.db.execute("SELECT id,body FROM trajectory WHERE checkpoint=? AND consumed=0 ORDER BY id LIMIT ?",(checkpoint,limit)).fetchall()
        grouped={}
        for id,body in rows:
            t=decode(body.encode());grouped.setdefault(t["group"],[]).append((id,t))
        return grouped
    def consume(self,ids):
        with self.db.tx() as c:
            for id in ids:c.execute("UPDATE trajectory SET consumed=1 WHERE id=?",(id,))


def group_policy_step(model:Decoder,optimizer,trajectories:list[dict],checkpoint_id:str):
    """On-policy grouped REINFORCE, not an unimplemented claim of PPO/GRPO.
    All trajectories must come from this exact frozen policy checkpoint. Losses
    are recomputed with gradients; model-changing use invalidates old rollouts.
    """
    require(len(trajectories)>=2,"RL_GROUP_SMALL")
    require(all(t["checkpoint"]==checkpoint_id for t in trajectories),"OFF_POLICY_ROLLOUT")
    require(len({t["group"] for t in trajectories})==1,"RL_GROUP_MISMATCH")
    ceiling=getattr(model,"host_ceiling",None)
    for t in trajectories:
        require(len(t["prompt"])>0 and len(t["completion"])>0,"RL_TOKENS")
        admit_workload(model.cfg,1,len(t["prompt"])+len(t["completion"])-1,ceiling=ceiling)
    rewards=torch.tensor([t["reward_micros"]/1000000 for t in trajectories],dtype=torch.float32)
    advantages=rewards-rewards.mean()
    std=advantages.std(unbiased=False)
    if float(std)<1e-8:return {"updated":False,"reason":"ZERO_REWARD_VARIANCE"}
    advantages=advantages/std;losses=[];device=next(model.parameters()).device;model.train()
    for t,adv in zip(trajectories,advantages):
        prompt,completion=t["prompt"],t["completion"]
        require(len(prompt)>0 and len(completion)>0,"RL_TOKENS")
        ids=torch.tensor([prompt+completion],dtype=torch.long,device=device)
        logits,_=model(ids[:,:-1])
        logp=logits.log_softmax(-1).gather(-1,ids[:,1:,None]).squeeze(-1)
        losses.append(-adv.to(device)*logp[:,len(prompt)-1:].mean())
    loss=torch.stack(losses).mean();require(bool(torch.isfinite(loss)),"RL_NONFINITE")
    optimizer.zero_grad(set_to_none=True);loss.backward();torch.nn.utils.clip_grad_norm_(model.parameters(),1,error_if_nonfinite=True);optimizer.step()
    return {"updated":True,"loss_micros":int(float(loss.detach())*1000000),"algorithm":"ON_POLICY_GROUP_REINFORCE_V1"}
