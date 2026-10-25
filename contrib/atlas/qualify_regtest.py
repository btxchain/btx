#!/usr/bin/env python3
"""Create an isolated disposable BTX regtest, fund a test wallet, run Atlas's
native Rust Money/Rpc exercise, then stop only the node this script owns.
No existing datadir, external RPC endpoint or mainnet wallet is accepted.
Native mining failure is a FAIL, not bypassed by changing consensus flags.
"""
from __future__ import annotations
import argparse,json,os,socket,subprocess,tempfile,time,uuid
from pathlib import Path

def port():
 with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--btxd',type=Path,required=True);p.add_argument('--cli',type=Path,required=True);p.add_argument('--repo',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--accept-disposable-regtest',action='store_true');a=p.parse_args()
 if not a.accept_disposable_regtest:p.error('Explicit disposable-regtest consent required')
 binaries=[x.resolve(strict=True) for x in [a.btxd,a.cli]]
 if a.out.exists():p.error('Refusing existing report path')
 if not (a.repo/'gui/atlas/Cargo.lock').is_file():p.error('Reviewed committed Cargo.lock required')
 with tempfile.TemporaryDirectory(prefix='atlas-regtest-') as temp:
  data=Path(temp);rpcport=port();log=(data/'node.log').open('wb')
  node=subprocess.Popen([str(binaries[0]),f'-datadir={data}','-chain=regtest','-server=1','-listen=0','-connect=0','-dnsseed=0','-discover=0','-modelnet=0',f'-rpcport={rpcport}','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1'],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
  def cli(method,*params,wallet=None):
   command=[str(binaries[1]),f'-datadir={data}','-chain=regtest',f'-rpcport={rpcport}']
   if wallet:command += [f'-rpcwallet={wallet}']
   command += [method,*[x if isinstance(x,str) else json.dumps(x) for x in params]]
   result=subprocess.run(command,capture_output=True,text=True,timeout=180,check=True).stdout.strip()
   try:return json.loads(result)
   except json.JSONDecodeError:return result
  report={'scope':'Disposable native regtest only','checks':[],'status':'FAIL'}
  try:
   deadline=time.monotonic()+60
   while time.monotonic()<deadline:
    if node.poll() is not None:raise RuntimeError('Owned node exited: '+(data/'node.log').read_text(errors='replace')[-4000:])
    try:
     if cli('getblockchaininfo').get('chain')=='regtest':break
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired):pass
    time.sleep(.3)
   else:raise RuntimeError('Node did not become ready')
   wallet='atlas-qualification-'+uuid.uuid4().hex[:12];cli('createwallet',wallet)
   mining=cli('getnewaddress',wallet=wallet);cli('generatetoaddress',101,mining)
   recipient=cli('getnewaddress',wallet=wallet)
   command=['cargo','run','--locked','-p','btx-atlas-core','--example','qualify_regtest','--','--endpoint',f'127.0.0.1:{rpcport}','--cookie',str(data/'regtest/.cookie'),'--wallet',wallet,'--recipient',recipient,'--accept-disposable-regtest','yes']
   result=subprocess.run(command,cwd=a.repo/'gui/atlas',capture_output=True,text=True,timeout=900,check=True)
   report['native']=json.loads(result.stdout);cli('generatetoaddress',1,mining)
   observed=cli('gettransaction',report['native']['txid'],wallet=wallet)
   if observed.get('confirmations',0)<1:raise RuntimeError('Transaction did not confirm')
   report.update(status='PASS',confirmation=observed,checks=['native RPC authentication','exact recipient amount','unsigned preparation','native signing','broadcast','duplicate-sign denial','duplicate-broadcast denial','regtest confirmation'])
  except Exception as e:
   report['error']=str(e);raise
  finally:
   try:cli('stop')
   except Exception:pass
   try:node.wait(timeout=15)
   except subprocess.TimeoutExpired:
    node.terminate()
    try:node.wait(timeout=10)
    except subprocess.TimeoutExpired:node.kill();node.wait()
   log.close();a.out.write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
