#!/usr/bin/env python3
"""Finite approval-state exploration. Proves invariants ONLY over this explicit abstract model."""
from __future__ import annotations
import json,itertools,argparse
from dataclasses import dataclass,replace
from collections import deque
@dataclass(frozen=True)
class State:
    phase:str='prepared'
    epoch:int=0
    approval_epoch:int=0
    submitted:int=0
    native_approved:bool=False
    record_durable:bool=False
    model_calls:int=0

def step(s:State,event:str)->State|None:
    if event=='model_request':
        return replace(s,model_calls=min(2,s.model_calls+1))
    if event=='connection_change':return replace(s,epoch=1)
    if event=='approve' and s.phase=='prepared' and s.epoch==s.approval_epoch:
        return replace(s,phase='approved',native_approved=True)
    if event=='persist' and s.phase=='approved':return replace(s,record_durable=True)
    if event=='submit' and s.phase=='approved' and s.native_approved and s.record_durable and s.epoch==s.approval_epoch:
        return replace(s,phase='submitted',submitted=s.submitted+1)
    if event in ('success','reject','unknown') and s.phase=='submitted':return replace(s,phase=event)
    if event in ('cancel','expire') and s.phase in ('prepared','approved'):return replace(s,phase=event)
    return None

def explore()->dict:
    events=('model_request','connection_change','approve','persist','submit','success','reject','unknown','cancel','expire')
    queue=deque([State()]);seen={State()};transitions=0
    while queue:
        s=queue.popleft()
        assert s.submitted<=1,'Approval replay'
        assert not s.submitted or (s.native_approved and s.record_durable),'Submit without human authority/durability'
        for event in events:
            next_state=step(s,event)
            if next_state is None:continue
            transitions+=1
            if event=='model_request':assert next_state.submitted==s.submitted and next_state.native_approved==s.native_approved
            if event=='submit':assert s.epoch==s.approval_epoch
            if next_state not in seen:seen.add(next_state);queue.append(next_state)
    return {'schema':'btx.atlas.finite-model/1','states':len(seen),'transitions':transitions,'invariants':['at most one submission per approval','native approval and durable intent before submission','model requests never grant authority','epoch changes prevent later submission','unknown outcomes cannot resubmit'],'result':'PASS_ABSTRACT_MODEL_ONLY','limitations':'Does not establish Rust/JS refinement, OS isolation, cryptography, race freedom of the implementation, or correctness of btxd.'}
if __name__=='__main__':print(json.dumps(explore(),indent=2))
