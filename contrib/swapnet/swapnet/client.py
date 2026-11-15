"""Small agent-facing SDK for the native node API; never carries private wallet keys."""
from dataclasses import dataclass
from pathlib import Path
import time
from typing import Any
from .rpcclient import LocalRPC
from .errors import SwapError,require
from .canonical import atoms,hex32

@dataclass
class SwapNetClient:
    rpc: LocalRPC
    @classmethod
    def local(cls,url:str,cookie:Path|str):
        return cls(LocalRPC(url,cookie_path=str(cookie)))
    def call(self,method:str,params:dict[str,Any]|None=None)->dict:
        require(method in PUBLIC_METHODS,'METHOD_NOT_FOUND','Not a SwapNet API method')
        return self.rpc(method,params or {})
    def status(self)->dict:return self.call('getswapnetworkinfo')
    def quote(self,sell_asset:str,buy_asset:str,sell_atoms:str,*,timeout:float=60)->list[dict]:
        atoms(sell_atoms,positive=True);require(0<timeout<=120,'TIMEOUT','Quote wait must be within two minutes')
        request=self.call('requestswapquote',{'sell_asset':sell_asset,'buy_asset':buy_asset,'sell_atoms':sell_atoms})
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            result=self.call('getswapquotes',{'request_id':request['request_id']})['quotes']
            if result:return sorted(result,key=lambda q:int(q['minimum_receive_atoms']),reverse=True)
            time.sleep(1)
        return []
    def accept(self,quote:dict,mandate_id:str,max_local_fee_atoms:str,*,minimum_receive_atoms:str,
               refund_fee_atoms:str,claim_fee_atoms:str|None=None)->dict:
        require(int(quote['minimum_receive_atoms'])>=atoms(minimum_receive_atoms),'MINIMUM_RECEIVE','Quote is below caller threshold')
        params={'quote_id':hex32(quote['id']),'mandate_id':hex32(mandate_id),
                'max_local_fee_atoms':max_local_fee_atoms,'refund_fee_atoms':refund_fee_atoms}
        atoms(max_local_fee_atoms,positive=True);atoms(refund_fee_atoms,positive=True)
        if claim_fee_atoms is not None:atoms(claim_fee_atoms,positive=True);params['claim_fee_atoms']=claim_fee_atoms
        return self.call('acceptswapquote',params)
    def wait(self,swap_id:str,*,timeout:float=300,poll_seconds:float=2)->dict:
        hex32(swap_id);require(timeout>0 and poll_seconds>=0.1,'TIMEOUT','Invalid polling policy')
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            state=self.call('getswap',{'swap_id':swap_id})
            if state['stage'] in {'complete','refunded','cancelled','rejected'}:return state
            time.sleep(poll_seconds)
        raise SwapError('POLL_TIMEOUT','Swap remains durable; query its ID rather than accepting a fresh quote')

PUBLIC_METHODS=frozenset({
 'getswapnetworkinfo','listswapassets','listswapproviders','searchswaps','requestswapquote','getswapquotes','acceptswapquote',
 'listswaps','getswap','cancelswap','getswaptranscript','listswapmandates','createswapmandate','revokeswapmandate',
 'getswapcapabilities','resumeswap','refundswap','listswapoperations','getswaphealth','publishswapprovider','withdrawswapprovider',
 'getswapbootstrapinfo','getswaprecoveryinfo','setswapmarket','listswapmarkets','getswapwalletinfo','setswapassetpolicy',
 'listswapassetpolicies','getswaprouteinfo','exportswaprecovery','bumpswapfee','getswapevents','getswapvalidationinfo'})
