"""Read-only native BTX observer. No wallet RPC, PSBT signing, or broadcasting.

A cookie is read locally by paynet only and is never passed to swarm workers.
Queries pin chain genesis and convert monetary JSON decimals without binary float.
"""
import asyncio
import base64
import json
import time
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlparse
import aiohttp
from .codec import integer
from .errors import require,MeshError

READ_METHODS={'getblockchaininfo','getblockhash','getblockcount','gettxout','getmempoolinfo','getrawtransaction','decoderawtransaction'}

class L1Observer:
    def __init__(self,url,cookie:Path,expected_genesis:str,min_confirmations=6):
        u=urlparse(url);require(u.scheme=='http' and u.hostname in {'127.0.0.1','::1','localhost'} and not u.username,'RPC_LOCAL_ONLY')
        require(len(expected_genesis)==64,'CHAIN_GENESIS');integer(min_confirmations,1,1000)
        self.url,self.cookie,self.genesis,self.confirmations=url,Path(cookie),expected_genesis,min_confirmations
    async def rpc(self,method,params=None):
        require(method in READ_METHODS,'READ_ONLY_RPC')
        require(self.cookie.is_file() and not self.cookie.is_symlink(),'RPC_COOKIE')
        token=base64.b64encode(self.cookie.read_bytes().strip()).decode()
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            async with session.post(self.url,json={'jsonrpc':'2.0','id':1,'method':method,'params':params or []},headers={'Authorization':'Basic '+token},allow_redirects=False) as response:
                raw=await response.content.read(4*1024*1024+1);require(len(raw)<=4*1024*1024,'RPC_RESPONSE_LIMIT')
                result=json.loads(raw,parse_float=Decimal)
                require(response.status==200 and result.get('error') is None,'NATIVE_RPC',str(result.get('error',''))[:160])
                return result['result']
    async def observe(self,txid,vout,expected_script):
        require(isinstance(txid,str) and len(txid)==64 and all(c in '0123456789abcdef' for c in txid),'TXID');integer(vout,0,2**32-1)
        require(await self.rpc('getblockhash',[0])==self.genesis,'WRONG_CHAIN')
        chain=await self.rpc('getblockchaininfo');require(chain.get('initialblockdownload') is False,'CHAIN_NOT_READY')
        out=await self.rpc('gettxout',[txid,vout,True]);require(out is not None,'BACKING_SPENT_OR_ABSENT')
        require(out['confirmations']>=self.confirmations,'BACKING_UNCONFIRMED')
        script=out['scriptPubKey']['hex'];require(script==expected_script,'BACKING_SCRIPT')
        amount=Decimal(str(out['value']))*100000000
        require(amount==amount.to_integral_value() and amount>0,'AMOUNT_PRECISION')
        # bestblock binds the observation; gettxout itself has no pledge semantics.
        return {'outpoint':txid+':'+str(vout),'genesis':self.genesis,'atoms':str(int(amount)),'confirmations':out['confirmations'],'height':chain['blocks'],'block_hash':out['bestblock'],'script':script,'checked_ms':int(time.time()*1000)}
