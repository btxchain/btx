#!/usr/bin/env python3
"""Optional BTX_MODEL_GENERATE adapter with exact locally approved interventions.

Reads BTX's existing stdin {prompt,max_new_tokens} contract. This is an explicit
operator-installed adapter, not a new RPC and not a swarm daemon. Never downloads.
"""
from __future__ import annotations
import argparse
import contextlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from btx_neuronlab.codec import loads, require, LabError
from btx_neuronlab.models import load_local
from btx_neuronlab.engine import generate
from btx_neuronlab.store import Store

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--dir',required=True);ap.add_argument('--max-new-tokens',type=int,default=32)
    args=ap.parse_args();store=None
    os.environ['HF_HUB_OFFLINE']='1';os.environ['TRANSFORMERS_OFFLINE']='1'
    try:
        path=os.environ.get('BTX_NEURONLAB_STORE')
        require(path and Path(path).is_absolute(),'STORE','BTX_NEURONLAB_STORE must name the operator-owned absolute store')
        req=loads(sys.stdin.buffer.readline(131073),signed=False,limit=131072)
        require(type(req)is dict and set(req)<={'prompt','max_new_tokens'},'SCHEMA','Unknown generate fields')
        with contextlib.redirect_stdout(sys.stderr):
            store=Store(Path(path))
            model,tok,adapter,binding=load_local(Path(args.dir),device=os.environ.get('BTX_NEURONLAB_DEVICE','cpu'))
            active=store.active(binding)
            cap,generation=active if active else (None,None)
            result=generate(model,tok,adapter,binding,req.get('prompt',''),profile=cap.profile if cap else None,
                tensors=cap.tensors if cap else None,max_new_tokens=req.get('max_new_tokens',args.max_new_tokens),
                fence=(lambda:store.check_fence(cap.id,binding,generation))if cap else None,
                device=os.environ.get('BTX_NEURONLAB_DEVICE','cpu'))
        print(json.dumps({'ok':True,'backend':'btx-neuronlab/torch-local','local_generate':True,**result},allow_nan=False))
        return 0
    except LabError as e:print(json.dumps({'ok':False,'generated':False,'error':e.as_dict()}));return 2
    except Exception as e:print(json.dumps({'ok':False,'generated':False,'error':{'code':'NOT_RUN','message':type(e).__name__}}));return 2
    finally:
        if store:store.close()

if __name__=='__main__':raise SystemExit(main())
