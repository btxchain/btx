#!/usr/bin/env python3
"""Exercise real disposable BTX/BTC/EVM nodes through the market application.

This is NOT a simulated-chain test. A prepared local lab config identifies real
RPCs, configured assets and neutral mining addresses. All BTX/BTC chains must say
regtest; EVM must be chain 31337. The runner refuses missing native build evidence.
It never turns a skipped/rejected case into PASS and never launches cloud jobs.
"""
from __future__ import annotations
import argparse,base64,datetime,hashlib,http.client,inspect,json,os,secrets,subprocess,sys,time
from decimal import Decimal
from pathlib import Path
from urllib.parse import urlsplit,quote
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from swapnet.market_application import MarketApplication  # actual production class

class RPC:
 def __init__(self,cfg):
  self.cfg=cfg;self.url=urlsplit(cfg['url'])
  if self.url.scheme!='http' or self.url.hostname not in ('127.0.0.1','::1','localhost') or self.url.username or self.url.query or self.url.fragment:
   raise ValueError('Qualification RPC must be uncredentialed loopback HTTP.')
 def call(self,method,params=None,wallet=None):
  cookie=Path(self.cfg['cookie']).read_text().strip() if self.cfg.get('cookie') else self.cfg.get('auth','')
  headers={'Content-Type':'application/json'}
  if cookie:headers['Authorization']='Basic '+base64.b64encode(cookie.encode()).decode()
  path='/wallet/'+quote(wallet,safe='') if wallet else '/'
  conn=http.client.HTTPConnection(self.url.hostname,self.url.port,timeout=20)
  try:
   conn.request('POST',path,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params if params is not None else []}),headers)
   response=conn.getresponse();raw=response.read(4*1024*1024+1)
   if len(raw)>4*1024*1024:raise RuntimeError('Oversized RPC response')
   result=json.loads(raw,parse_float=Decimal)
   if result.get('error'):raise RuntimeError(method+': '+str(result['error']))
   return result['result']
  finally:conn.close()
 def market(self,method,request=None):return self.call(method,[request or {}],self.cfg['wallet'])

def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
 return h.hexdigest()

def request_for(method,values):
 """Use the exact installed source signature; no guessed positional RPC contract."""
 fn=getattr(MarketApplication,'rpc_'+method,None)
 if fn is None:
  # These inherited methods have stable maintained contracts.
  return values
 out={}
 for name,p in inspect.signature(fn).parameters.items():
  if name in ('self','ctx'):continue
  if p.kind in (p.VAR_KEYWORD,p.VAR_POSITIONAL):raise RuntimeError('Qualification requires explicit method parameters')
  if name in values:out[name]=values[name]
  elif p.default is p.empty:raise RuntimeError('Lab template lacks required '+method+'.'+name)
 return out

def wait(fn,timeout=120,step=None):
 deadline=time.monotonic()+timeout;last=None
 while time.monotonic()<deadline:
  last=fn()
  if last:return last
  if step:step()
  time.sleep(.5)
 raise TimeoutError('Bounded native condition not reached; last='+repr(last))

class Lab:
 def __init__(self,cfg,out):
  self.cfg=cfg;self.out=out;self.a=RPC(cfg['a']);self.b=RPC(cfg['b']);self.miners={k:RPC(v) for k,v in cfg['miners'].items()};self.events=[]
 def record(self,event,**values):
  self.events.append({'time':time.time(),'event':event,**values})
  (self.out/'events.json').write_text(json.dumps(self.events,indent=2,default=str))
 def preflight(self):
  build=self.cfg['candidate_build'];binary=Path(build['btxd'])
  if sha(binary)!=build['sha256']:raise RuntimeError('Candidate binary hash mismatch')
  if not build.get('source_manifest_sha256') or not build.get('build_receipt'):raise RuntimeError('Exact candidate source/build receipt required')
  if not Path(build['build_receipt']).is_file():raise RuntimeError('Build receipt not present')
  for name,node in [('a',self.a),('b',self.b)]:
   if node.call('getblockchaininfo')['chain']!='regtest':raise RuntimeError('Refusing non-regtest BTX')
   if node.market('getswapnetworkinfo')['automatic_spend_atoms']!='0':raise RuntimeError('Unexpected implicit-spend status')
   node.market('setswapmode',{'mode':'maker'})
   self.record('native_identity',node=name,network=node.market('getswapnetworkinfo'),build_sha256=sha(binary))
  for family,miner in self.miners.items():
   if family=='evm':
    if int(miner.call('eth_chainId'),16)!=31337:raise RuntimeError('Refusing non-local EVM chain')
   elif miner.call('getblockchaininfo')['chain']!='regtest':raise RuntimeError('Refusing non-regtest mining client')
  self.record('preflight_passed')
 def step(self):
  for family,miner in self.miners.items():
   if family=='evm':
    miner.call('evm_increaseTime',[12]);miner.call('evm_mine',[])
   else:
    cfg=self.cfg['miners'][family]
    miner.call('generatetoaddress',[1,cfg['address']],cfg.get('wallet'))
 def maker(self,node,case):
  auth=node.market('getswapauthinfo')
  mandate={'principal':auth['principal'],'asset':case['buy_asset'],'max_total_atoms':case['maker_budget_atoms'],
   'max_trade_atoms':case['maker_budget_atoms'],'max_fee_atoms':case['maker_max_local_fee_atoms'],'expires_at':int(time.time())+86400,'nonce':secrets.token_hex(32)}
  mid=node.market('createswapmandate',{'mandate':mandate})['mandate_id']
  policy={'market':{'sell_asset':case['sell_asset'],'buy_asset':case['buy_asset'],'numerator':case['numerator'],'denominator':case['denominator'],
   'maker_fee_atoms':case['maker_fee_atoms'],'max_receive_network_fee_atoms':case['receive_fee_cap_atoms'],
   'max_input_atoms':case['sell_atoms'],'expires_at':int(time.time())+3600},'mandate_id':mid,
   'max_local_fee_atoms':case['maker_max_local_fee_atoms'],'refund_fee_atoms':case['maker_refund_fee_atoms'],'claim_fee_atoms':case['maker_claim_fee_atoms']}
  node.market('setswapmarket',policy)
  return policy
 def quote(self,a,b,case,public):
  policy=self.maker(b,case)
  if not public:
   requested=a.market('requestswapquote',{k:case[k] for k in ('sell_asset','buy_asset','sell_atoms')})
  else:
   # Optional explicit per-source template is checked against the implemented signature.
   template={**case.get('public_publish',{}),'sell_asset':case['sell_asset'],'buy_asset':case['buy_asset'],
    'sizes':[case['sell_atoms']],'sell_sizes':[case['sell_atoms']],'kind':'firm','ttl':300,'ttl_seconds':300,'slots':1}
   published=b.market('publishswapoffer',request_for('publishswapoffer',template))
   def observed():
    page=a.market('listswappublicoffers',{})
    rows=page.get('offers',page.get('records',[]))
    for row in rows:
     body=row.get('body',row.get('envelope',{}).get('body',{}))
     if body.get('sell_asset')==case['sell_asset'] and body.get('buy_asset')==case['buy_asset'] and not body.get('withdrawn'):return body
    return None
   body=wait(observed,60,self.step)
   values={'provider':body['provider'],'offer_id':body['offer_id'],'sequence':body['sequence'],'tier':0,'tier_index':0,'sell_atoms':case['sell_atoms']}
   requested=a.market('requestpublicswapquote',request_for('requestpublicswapquote',values))
   self.record('public_offer_observed',body=body,published=published)
  rid=requested['request_id']
  def available():
   result=a.market('getswapquotes',{'request_id':rid})
   if result.get('declined'):raise RuntimeError('Maker refusal: '+repr(result['declined']))
   return result.get('quotes',[None])[0] if result.get('quotes') else None
  return wait(available,60,self.step)
 def start(self,case,public):
  a,b=(self.b,self.a) if case.get('reverse_nodes') else (self.a,self.b)
  quote=self.quote(a,b,case,public)
  values={'quote_id':quote['id'],'max_local_fee_atoms':case['taker_max_local_fee_atoms'],'refund_fee_atoms':case['taker_refund_fee_atoms'],
   'claim_fee_atoms':case['receive_fee_cap_atoms'],'min_receive_atoms':quote['minimum_receive_atoms']}
  before=a.market('listswaps',{})
  preview=a.market('previewswap',request_for('previewswap',values))
  if a.market('listswaps',{})!=before:raise AssertionError('Preview changed financial sessions')
  preview_id=preview['preview_id'];started=a.market('confirmswap',{'preview_id':preview_id});sid=started['swap_id']
  retry=a.market('confirmswap',{'preview_id':preview_id})
  if retry['swap_id']!=sid:raise AssertionError('Confirm retry started another swap')
  self.record('trade_started',case=case['name'],swap_id=sid,quote=quote,preview=preview)
  return a,b,sid
 def settled(self,a,b,sid):
  left=a.market('getswap',{'swap_id':sid});right=b.market('getswap',{'swap_id':sid})
  if left['stage'] in ('refunded','rejected','cancelled') or right['stage'] in ('refunded','rejected','cancelled'):
   raise AssertionError('Unexpected terminal state '+repr((left,right)))
  return (left,right) if left['stage']==right['stage']=='complete' else None
 def run_case(self,case):
  a,b,sid=self.start(case,case.get('public',True))
  scenario=case.get('scenario','settle')
  def funded():
   state=a.market('getswap',{'swap_id':sid});return state if state.get('funding_broadcast') else None
  first=wait(funded,180,self.step)
  if scenario=='pause':
   a.market('setswapmode',{'mode':'recovery'});b.market('setswapmode',{'mode':'recovery'})
  elif scenario=='restart':
   for node,key in ((a,'a' if a is self.a else 'b'),(b,'a' if b is self.a else 'b')):
    argv=self.cfg.get('restart',{}).get(key)
    if not argv or not isinstance(argv,list):raise RuntimeError('Restart case requires an explicit local argv array')
    node.call('stop');time.sleep(1)
    subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    def ready():
     try:return node.call('getblockchaininfo')['chain']=='regtest'
     except (OSError,RuntimeError,http.client.HTTPException):return False
    wait(ready,120)
  elif scenario!='settle':raise ValueError('Unsupported scenario; do not silently label refund/reorg as settled')
  left,right=wait(lambda:self.settled(a,b,sid),600,self.step)
  for label,node in [('initiator',a),('responder',b)]:
   operations=node.market('listswapoperations',{'swap_id':sid})['operations']
   funds=[x for x in operations if x['kind']=='fund']
   if len(funds)!=1:raise AssertionError('Expected exactly one original funding operation per party')
   self.record('native_operations',case=case['name'],role=label,operations=operations)
  exported=a.market('exportswapreceipt',{'swap_id':sid})
  self.record('settled',case=case['name'],initiator=left,responder=right,receipt=exported)
  return {'status':'PASS','swap_id':sid,'evidence':'Actual node settlement states and original funding operation records; balance/reorg qualification remains separately required.'}

def main():
 p=argparse.ArgumentParser();p.add_argument('--lab',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 cfg=json.loads(a.lab.read_text());a.output.mkdir(parents=True,exist_ok=True)
 report={'schema_version':1,'tests':{},'complete':False,'production_authorized':False,'test_driver':'real local RPC; no mocked chain substitution'}
 try:
  lab=Lab(cfg,a.output);lab.preflight()
  for case in cfg['cases']:
   try:report['tests'][case['name']]=lab.run_case(case)
   except Exception as e:report['tests'][case['name']]={'status':'FAIL','error':str(e)};break
 except Exception as e:report['preflight']={'status':'FAIL','error':str(e)}
 for name in ('refund_matrix','reorg_before_after_secret','exact_four_wallet_balance_reconciliation','cross_platform'):
  report['tests'][name]={'status':'NOT_RUN','reason':'This script does not establish this gate; no success is inferred from settlement.'}
 (a.output/'NATIVE_LIFECYCLE_REPORT.json').write_text(json.dumps(report,indent=2,default=str))
 print(json.dumps(report,indent=2,default=str));return 2
if __name__=='__main__':raise SystemExit(main())
