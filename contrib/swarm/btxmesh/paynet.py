"""Isolated local SEP accounting daemon. Native monetary settlement is unavailable.

This service deliberately cannot be enabled for payments by changing a flag:
there is no signing/broadcast path. Its event ledger and protocol models are the
handoff substrate for the separately audited PAY/1 native implementation.
"""
import argparse
import asyncio
import contextlib
import hmac
import json
import os
import signal
import stat
from pathlib import Path
from aiohttp import web
from .codec import encode,decode,fields
from .storage import private_dir,atomic_write,ProcessLock,local_socket
from .errors import MeshError,require
from .economy import Ledger
from .l1 import L1Observer
from .transport import errors,bounded_body

class PaynetService:
    def __init__(self,data,observer=None):
        self.data=private_dir(Path(data));self.lock=ProcessLock(self.data/'paynet.lock')
        self.ledger=Ledger(self.data/'economy.sqlite3');self.observer=observer;self.stop=asyncio.Event();self.runner=None
        tp=self.data/'paynet.token'
        if not tp.exists():atomic_write(tp,os.urandom(32).hex().encode())
        self.token=tp.read_text()
    def authenticate(self,request):require(hmac.compare_digest(request.headers.get('Authorization',''),'Bearer '+self.token),'PAYNET_AUTH')
    async def status(self,request):
        self.authenticate(request)
        return web.Response(body=encode({'service':'btx-paynetd','assurance':'ACCOUNTING_ONLY','payment_signing':False,'native_channel_backend':'UNQUALIFIED','routed_payment_network':False,'automatic_spend_atoms':'0'}),content_type='application/json')
    async def action(self,request):
        self.authenticate(request);p=decode(await bounded_body(request));fields(p,{'method','params'})
        b=p['params'];m=p['method'];l=self.ledger
        if m=='pool.create':result={'pool':l.create_pool(b)}
        elif m=='pool.balances':fields(b,{'pool'});result=l.balances(b['pool'])
        elif m=='backing.observe':
            fields(b,{'pool','txid','vout','expected_script','fee_reserve_atoms'})
            require(self.observer is not None,'L1_OBSERVER_UNCONFIGURED')
            observation=await self.observer.observe(b['txid'],b['vout'],b['expected_script'])
            result=l.observe_backing(b['pool'],observation,expected_script=b['expected_script'],fee_reserve_atoms=b['fee_reserve_atoms'])
        elif m=='mandate.grant':result={'mandate':l.grant_mandate(**b)}
        elif m=='mandate.revoke':fields(b,{'id'});l.revoke_mandate(b['id']);result={'revoked':True}
        elif m=='work.reserve':result=l.reserve(**b)
        elif m=='work.accept':fields(b,{'reservation','receipt_id'});result=l.accept_work(**b)
        elif m=='work.cancel':fields(b,{'reservation'});l.cancel(b['reservation']);result={'cancelled':True}
        elif m=='settle':result=l.settle(**b)
        else:raise MeshError('PAYNET_METHOD')
        return web.Response(body=encode(result),content_type='application/json')
    async def start(self):
        require(os.name=='posix','WINDOWS_LOCAL_IPC_UNQUALIFIED')
        app=web.Application(middlewares=[errors]);app.router.add_get('/status',self.status);app.router.add_post('/command',self.action)
        self.runner=web.AppRunner(app,access_log=None);await self.runner.setup();sock=local_socket(self.data,'paynet')
        if sock.exists():require(stat.S_ISSOCK(sock.lstat().st_mode),'SOCKET_PATH');sock.unlink()
        await web.UnixSite(self.runner,str(sock)).start();os.chmod(sock,0o600)
    async def close(self):
        if self.runner:await self.runner.cleanup()
        self.ledger.close();self.lock.close()

async def serve(args):
    observer=None
    if args.rpc_url:
        require(args.cookie and args.chain_genesis,'CHAIN_CONFIGURATION')
        observer=L1Observer(args.rpc_url,Path(args.cookie),args.chain_genesis,args.confirmations)
    service=PaynetService(Path(args.data),observer)
    loop=asyncio.get_running_loop()
    for sig in (signal.SIGTERM,signal.SIGINT):loop.add_signal_handler(sig,service.stop.set)
    try:await service.start();print(json.dumps({'service':'btx-paynetd','mode':'ACCOUNTING_ONLY'}),flush=True);await service.stop.wait()
    finally:await service.close()

def main():
    p=argparse.ArgumentParser(description='SEP accounting and read-only backing; no monetary signing')
    p.add_argument('--data',default=str(Path.home()/'.btx'/'paynet'));p.add_argument('--rpc-url');p.add_argument('--cookie');p.add_argument('--chain-genesis');p.add_argument('--confirmations',type=int,default=6)
    args=p.parse_args()
    try:asyncio.run(serve(args))
    except (MeshError,OSError) as e:print(json.dumps({'error':getattr(e,'code','PAYNET_START'),'detail':str(e)}));raise SystemExit(2)

if __name__=='__main__':main()
