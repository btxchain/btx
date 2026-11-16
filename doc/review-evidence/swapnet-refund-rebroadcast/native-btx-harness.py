"""Native BTX timed wallet spend using the retained wallet-only test profile; not HTLC/default MatMul qualification."""
import sys,json,subprocess,time,base64,hashlib,socket,shutil
from pathlib import Path
from decimal import Decimal
from dataclasses import asdict,replace
from types import SimpleNamespace as NS
from urllib.request import Request,urlopen
from urllib.error import HTTPError
P=Path(__file__).resolve().parent
import os
sys.path.insert(0,str(P.parent/'candidate'))
sys.path.insert(0,str(P.parent/'swapnet-coverage-review-20261116/source/contrib/swapnet/tests'))
# Reuse the deterministic keys/script from existing test_bitcoin.py without its pytest dependency.
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from swapnet.bitcoin import htlc_script
from swapnet.canonical import hashlock
KEY1=ec.derive_private_key(1,ec.SECP256K1());KEY2=ec.derive_private_key(2,ec.SECP256K1())
PUB1=KEY1.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
PUB2=KEY2.public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)
SECRET=bytes.fromhex('42'*32)
def script(height=500):return htlc_script(hashlock(SECRET),PUB1,PUB2,height)
from swapnet.drivers import UTXODriver,Report
from swapnet.machine import LegObservation
from swapnet.policy import ChainClock
from swapnet.terms import LegTerms,Agreement
from swapnet.bitcoin import Transaction
from swapnet.canonical import hashlock
from swapnet.fee_bump import bump
from swapnet.errors import SwapError
from cryptography.hazmat.primitives.asymmetric import ec,utils
from cryptography.hazmat.primitives import hashes
B=P/'saved949-package/btx-0.34.16/bin/btxd'; R=P/'qualified949-node';R.mkdir(exist_ok=True)
assert shutil.disk_usage(P).free>1.25*1024**3
with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
def rpc(method,*args,wallet=None):
 auth=base64.b64encode((R/'regtest/.cookie').read_bytes().strip()).decode()
 req=Request(f'http://127.0.0.1:{port}'+('/wallet/'+wallet if wallet else ''),json.dumps({'id':1,'method':method,'params':args}).encode(),{'Authorization':'Basic '+auth,'Content-Type':'application/json'})
 try:response=urlopen(req,timeout=30)
 except HTTPError as error:response=error
 with response as f:d=json.load(f,parse_float=Decimal)
 if d.get('error'):raise SwapError('CHAIN_RPC',d['error']['message'])
 return d['result']




from swapnet.journal import Journal
from swapnet.store import Store
result={'status':'INCOMPLETE','source_profile':'Saved949a98e3 packaged native daemon; exact previous CPU wallet regtest flags. Current PR777 Python UTXODriver, archived native BTX daemon. Not current-release qualification.'};proc=None;store=None
calls=[]
def wallet(method,*args):return rpc(method,*args,wallet='presence')
def measured(method,*args):
 if method=='sendrawtransaction':calls.append(args[0])
 return rpc(method,*args)
def start_node():
 global proc
 log=(P/'qualified949-node.log').open('ab');proc=subprocess.Popen([str(B),'-regtest','-autoshieldcoinbase=0','-regtestmatmulbindingheight=2147483647','-regtestmatmulproductdigestheight=2147483647','-regtestmatmulv4height=2147483647','-regtestmatmulrequireproductpayload=0','-datadir='+str(R),'-rpcport='+str(port),'-listen=0','-connect=0','-dnsseed=0','-discover=0','-autoupdate=0','-swapnet=0','-modelnet=0','-dbcache=16','-par=1','-printtoconsole=1','-debuglogfile=0'],stdout=log,stderr=log)
 for _ in range(100):
  try:assert rpc('getblockchaininfo')['chain']=='regtest';break
  except Exception:
   if proc.poll() is not None:raise RuntimeError('node exited')
   time.sleep(.1)
 else:raise RuntimeError('startup bound')
try:
 result['native_sha256']=hashlib.sha256((B.parent.parent/'libexec/btxd.real').read_bytes()).hexdigest()
 start_node()
 rpc('loadwallet','presence') if (R/'regtest/wallets/presence').exists() else rpc('createwallet','presence')
 address=wallet('getnewaddress')
 if rpc('getblockcount')==0:rpc('generatetoaddress',1,address)
 driver=UTXODriver('btx:'+rpc('getblockhash',0)+':0:native',measured,wallet,wallet,None,None,network='11'*32)
 block=rpc('getblock',rpc('getblockhash',1),2);coinbase=block['tx'][0]['txid']
 assert driver.has_transaction(coinbase) is True;result['confirmed_coinbase_presence']=True
 height=rpc('getblockcount')
 if height<101:rpc('generatetoaddress',101-height,address)
 result['fundable_height']=rpc('getblockcount')
 result['help_createpsbt']=rpc('help','walletcreatefundedpsbt')
 # Locktime on a normal native wallet payment isolates the presence API from HTLC signing.
 deadline=rpc('getblockcount')+3;dest=wallet('getnewaddress')
 funded=wallet('walletcreatefundedpsbt',[],[{dest:'0.00100000'}],deadline,{'fee_rate':2},True)
 signed=wallet('walletprocesspsbt',funded['psbt']);assert signed['complete']
 final=rpc('finalizepsbt',signed['psbt'],True);assert final['complete'];raw=final['hex'];tx=rpc('decoderawtransaction',raw);txid=tx['txid']
 assert tx['locktime']==deadline
 rpc('generatetoaddress',deadline-rpc('getblockcount'),address)
 assert rpc('testmempoolaccept',[raw])[0]['allowed'];assert rpc('sendrawtransaction',raw)==txid
 assert driver.has_transaction(txid) is True;result['mempool_presence']=True
 folder=P/'qualified949-journal';folder.mkdir(mode=0o700,exist_ok=True);store=Store(folder/'state.sqlite');journal=Journal(store)
 oid=journal.prepare('77'*32,driver.asset.id,'refund',txid,raw,{'scope':'normal native wallet payment, not an HTLC refund'})
 journal.broadcast(oid,driver);assert not calls;result['mempool_duplicate_suppressed']=True
 rpc('generatetoaddress',1,address);assert driver.has_transaction(txid);journal.broadcast(oid,driver);assert not calls;result['confirmed_duplicate_suppressed']=True
 cut=rpc('getblockhash',deadline);rpc('invalidateblock',cut);assert rpc('getblockcount')==deadline-1
 assert wallet('gettransaction',txid,True)['txid']==txid and txid not in rpc('getrawmempool')
 assert driver.has_transaction(txid) is False;result['wallet_known_dropped_absent']=True
 store.db.close();store=None;rpc('stop');proc.wait(timeout=20);start_node();rpc('loadwallet','presence')
 store=Store(folder/'state.sqlite');journal=Journal(store)
 assert journal.operation(oid)['raw']==raw and wallet('gettransaction',txid,True)['txid']==txid
 assert driver.has_transaction(txid) is False;result['dropped_absent_after_restart']=True
 probe=journal.prepare('88'*32,driver.asset.id,'refund',txid,raw,{'scope':'premature refusal control'})
 try:journal.broadcast(probe,driver)
 except SwapError as error:
  assert journal.operation(probe)['state']=='prepared';result['native_refusal']=error.message
 else:raise AssertionError('premature spend accepted')
 calls.clear()
 rpc('generatetoaddress',1,address);journal.broadcast(oid,driver);assert len(calls)==1 and txid in rpc('getrawmempool')
 rpc('generatetoaddress',1,address);confirmed=wallet('gettransaction',txid,True);assert confirmed['confirmations']==1
 paid_tx=rpc('decoderawtransaction',confirmed['hex']);assert paid_tx['txid']==txid and paid_tx['vout']==tx['vout'] and confirmed['hex']==raw
 assert all(rpc('gettxout',i['txid'],i['vout']) is None for i in tx['vin'])
 result['original_inputs_consumed']=True;result['outputs_unchanged']=True;result['new_fund_operations']=len([o for o in journal.operations('77'*32) if o['kind']=='fund'])
 assert result['new_fund_operations']==0
 result.update(status='PASS_NATIVE_BTX_PRESENCE_AND_REBROADCAST',txid=txid,deadline=deadline,confirmed=confirmed['confirmations'],journal_operations=len(journal.operations('77'*32)))
finally:
 if store:store.db.close()
 if proc and proc.poll() is None:
  try:rpc('stop');proc.wait(timeout=20)
  except Exception:proc.terminate();proc.wait(timeout=10)
 result['node_stopped']=proc is not None and proc.poll() is not None
 (P/'qualified949-result.json').write_text(json.dumps(result,indent=2,default=str)+'\n')
print(json.dumps({k:v for k,v in result.items() if not k.startswith('help')}))
