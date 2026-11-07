"""Real PyTorch DDP training island, launched by torchrun.

Only an already authorized host/capsule may launch this executable. Rendezvous
and collectives belong on an authenticated private fabric, not a public port.
SafeTensors state avoids loading Python pickle from other participants.
"""
import argparse
import os
import json
from pathlib import Path
from datetime import timedelta
import torch
import torch.distributed as dist
from torch.nn.parallel import DistributedDataParallel
from torch.nn import functional as F
from .runtime import Decoder
from .training import Trainer
from .codec import byte_id,encode,integer
from .storage import private_dir,atomic_write
from .errors import require
from . import tensors


def run(args):
    integer(args.steps,1,4096);integer(args.batch,1,256);integer(args.sequence,2,32768);integer(args.cpu_threads,1,256)
    torch.set_num_threads(args.cpu_threads)
    rank=int(os.environ.get('RANK','0'));world=int(os.environ.get('WORLD_SIZE','1'));local=int(os.environ.get('LOCAL_RANK','0'))
    require(world<=128,'ISLAND_SIZE')
    cuda=torch.cuda.is_available() and args.device!='cpu'
    if args.device=='cuda':require(cuda,'CUDA_UNAVAILABLE')
    if cuda:torch.cuda.set_device(local)
    device='cuda:'+str(local) if cuda else 'cpu';backend='nccl' if cuda else 'gloo'
    if world>1:dist.init_process_group(backend=backend,timeout=timedelta(seconds=60))
    out=private_dir(Path(args.output));source=Path(args.model)
    require(source.is_file() and not source.is_symlink(),'MODEL_PATH')
    raw=source.read_bytes();model=Decoder.from_checkpoint(raw,device)
    trainer=Trainer(model,seed=args.seed+rank,lr_micros=args.lr_micros)
    if args.dataset:
        p=Path(args.dataset);require(p.is_file() and not p.is_symlink(),'DATASET_PATH');data=tensors.loads(p.read_bytes())['tokens']
    else:data=torch.arange(4096,dtype=torch.long)%model.cfg.vocab
    require(data.ndim==1 and data.dtype==torch.long and len(data)>args.sequence,'DATASET_TOKENS')
    data_id=byte_id(tensors.dumps({'tokens':data}));trainer.dataset_id=data_id
    train_model=DistributedDataParallel(model,device_ids=[local] if cuda else None) if world>1 else model
    losses=[]
    try:
        for _ in range(args.steps):
            starts=torch.randint(0,len(data)-args.sequence,(args.batch,),generator=trainer.generator)
            x=torch.stack([data[s:s+args.sequence] for s in starts]).to(device)
            y=torch.stack([data[s+1:s+args.sequence+1] for s in starts]).to(device)
            logits,_=train_model(x);loss=F.cross_entropy(logits.flatten(0,1),y.flatten())
            require(bool(torch.isfinite(loss)),'LOSS_NONFINITE')
            trainer.optimizer.zero_grad(set_to_none=True);loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(),1.0,error_if_nonfinite=True);trainer.optimizer.step()
            trainer.step+=1;trainer.cursor+=args.batch;trainer.tokens_seen+=args.batch*args.sequence
            mean=loss.detach().clone()
            if world>1:dist.all_reduce(mean);mean/=world
            losses.append(int(float(mean)*1000000))
        # All ranks persist their data cursor/RNG state. Rank identity and world
        # size are recorded; this is not claimed to be topology-independent replay.
        weights=model.checkpoint();checkpoint=byte_id(weights)
        atomic_write(out/f'rank-{rank}.safetensors',trainer.checkpoint())
        atomic_write(out/f'rank-{rank}.json',encode({'rank':rank,'world':world,'checkpoint':checkpoint,'dataset_id':data_id,'tokens':trainer.tokens_seen,'full_state':f'rank-{rank}.safetensors'}))
        if world>1:
            local_hash=torch.tensor(list(bytes.fromhex(checkpoint)),dtype=torch.uint8,device=device)
            gathered=[torch.empty_like(local_hash) for _ in range(world)];dist.all_gather(gathered,local_hash)
            require(all(torch.equal(local_hash,x) for x in gathered),'DDP_PARAMETER_DIVERGENCE')
        if rank==0:
            atomic_write(out/'model.safetensors',weights)
            atomic_write(out/'receipt.json',encode({'algorithm':'PYTORCH_DDP_SGD','world':world,'backend':backend,'base_checkpoint':byte_id(raw),'checkpoint':checkpoint,'steps':args.steps,'tokens':trainer.tokens_seen*world,'loss_micros':losses,'native_chain_effects':False,'hardware':device,'qualification':'THIS_RUN_ONLY'}))
        if world>1:dist.barrier()
    finally:
        if world>1 and dist.is_initialized():dist.destroy_process_group()


def main():
    p=argparse.ArgumentParser(description='Authorized private-fabric DDP training island')
    p.add_argument('--model',required=True);p.add_argument('--output',required=True);p.add_argument('--dataset');p.add_argument('--steps',type=int,default=8);p.add_argument('--batch',type=int,default=4);p.add_argument('--sequence',type=int,default=16);p.add_argument('--seed',type=int,default=1);p.add_argument('--lr-micros',type=int,default=30000);p.add_argument('--cpu-threads',type=int,default=1);p.add_argument('--device',choices=['auto','cpu','cuda'],default='auto');p.add_argument('--local-rank','--local_rank',type=int,default=None)
    run(p.parse_args())

if __name__=='__main__':main()
