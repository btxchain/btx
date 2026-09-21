"""Tiny typed workflow sketch. Caller supplies an authenticated transport.

No tokens, automatic retries or provider URLs are supplied by model metadata.
Generate full production Python/TypeScript SDKs from the OpenAPI contract.
"""
from __future__ import annotations
from typing import Protocol, Any
from urllib.parse import quote

class AuthenticatedTransport(Protocol):
    def request(self,method:str,path:str,body:dict|None,headers:dict[str,str])->dict[str,Any]: ...

class HostedClient:
    def __init__(self,transport:AuthenticatedTransport): self.transport=transport
    def search(self,query:str,limit:int=20)->dict:
        if not 1<=limit<=100: raise ValueError('limit outside 1..100')
        return self.transport.request('POST','/capabilities/search',{'query':query,'limit':limit},{})
    def create_intent(self,*,client_operation_id:str,quote_id:str,expected_quote_id:str,idempotency_key:str)->dict:
        if not idempotency_key:raise ValueError('idempotency key required')
        return self.transport.request('POST','/finance/intents',{
            'client_operation_id':client_operation_id,'quote_id':quote_id,'expected_quote_id':expected_quote_id
        },{'Idempotency-Key':idempotency_key})
    def status(self,intent_id:str)->dict:
        return self.transport.request('GET','/finance/intents/'+quote(intent_id,safe=''),None,{})
    def submit(self,intent_id:str,expected_body_id:str,idempotency_key:str)->dict:
        if not idempotency_key:raise ValueError('idempotency key required')
        # A timeout propagates. Caller retrieves this intent; this method never creates a replacement.
        return self.transport.request('POST','/finance/intents/'+quote(intent_id,safe='')+'/submit',
            {'expected_body_id':expected_body_id},{'Idempotency-Key':idempotency_key})
