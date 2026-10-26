#!/usr/bin/env python3
"""Private stdin/stdout interface. No listening socket and no inherited RPC keys."""
from __future__ import annotations
import argparse
import contextlib
import json
import os
from pathlib import Path
import sys

# Required for `python -I -B /approved/path/worker.py`. No user import paths.
sys.path.insert(0,str(Path(__file__).resolve().parent))
from btx_neuronlab.codec import loads, LabError, require
from btx_neuronlab.service import Service
MAX_LINE=1_048_576

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--store',required=True);ap.add_argument('--serve',action='store_true');ap.add_argument('--stream',action='store_true')
    args=ap.parse_args()
    os.environ['HF_HUB_OFFLINE']='1';os.environ['TRANSFORMERS_OFFLINE']='1';os.environ['HF_DATASETS_OFFLINE']='1'
    service=None
    active_operation = None
    stream_bytes = 0
    def progress(event):
        nonlocal stream_bytes
        # Transport events carry data only. They cannot name native commands.
        if active_operation is None: return
        frame=json.dumps({"event":event,"operation_id":active_operation},ensure_ascii=False,separators=(",",":"),allow_nan=False)
        stream_bytes += len(frame.encode())
        require(len(frame.encode()) <= 65536 and stream_bytes <= 4_194_304,"STREAM_BUDGET","Provisional progress exceeds transport budget")
        sys.__stdout__.write(frame+"\n");sys.__stdout__.flush()
    try:
        service=Service(Path(args.store),progress=progress if args.stream else None)
        while True:
            raw=sys.stdin.buffer.readline(MAX_LINE+1)
            if not raw:break
            try:
                require(len(raw)<=MAX_LINE and raw.endswith(b'\n'),'REQUEST_SIZE','Bounded newline-terminated request required')
                request=loads(raw,signed=False)
                active_operation=request.get("operation_id");stream_bytes=0
                with contextlib.redirect_stdout(sys.stderr):result=service.call(request)
                response={'ok':True,'result':result}
            except LabError as e:response={'ok':False,'error':e.as_dict()}
            except Exception as e:response={'ok':False,'error':{'code':'INTERNAL_ERROR','message':type(e).__name__+'; request failed closed'}}
            encoded=json.dumps(response,ensure_ascii=False,separators=(',',':'),allow_nan=False)
            require(len(encoded.encode())<=8_388_608,'RESULT_SIZE','Result exceeds 8 MiB')
            print(encoded,flush=True)
            if not args.serve:break
    except LabError as e:
        print(json.dumps({'ok':False,'error':e.as_dict()}),flush=True)
        return 2
    finally:
        if service:service.close()
    return 0

if __name__=='__main__':raise SystemExit(main())
