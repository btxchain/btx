#!/usr/bin/env python3
"""Inventory a real checkout's Qt actions/options/RPC strings. Not a parity proof."""
from __future__ import annotations
import argparse,hashlib,json,re,subprocess
from pathlib import Path

def run(repo:Path)->dict:
 root=repo/'src/qt'
 if not (root/'bitcoingui.h').is_file():raise ValueError('BTX Qt tree missing')
 files={};actions=[];options=[];rpc=[];forms=[]
 for p in sorted(root.rglob('*')):
  if not p.is_file() or p.suffix not in {'.h','.cpp','.ui'}:continue
  b=p.read_bytes();s=b.decode('utf-8','replace');rel=p.relative_to(repo).as_posix()
  files[rel]=hashlib.sha256(b).hexdigest()
  for match in re.finditer(r'QAction\s*\*\s*(\w+)',s):actions.append({'name':match[1],'source':rel,'line':s[:match.start()].count('\n')+1})
  for match in re.finditer(r'(?:callRpc|tryRpc|executeRpc|executeRPC)\s*\(\s*"([a-z][a-z0-9_]*)"',s):rpc.append({'method':match[1],'source':rel,'line':s[:match.start()].count('\n')+1})
  if p.name=='optionsmodel.h':
   m=re.search(r'enum OptionID\s*\{(.*?)\};',s,re.S)
   if m:options=re.findall(r'^\s*([A-Za-z_]\w*)\s*,',m[1],re.M)
  if p.suffix=='.ui':forms.append(rel)
 catalog=json.loads((repo/'gui/atlas/schemas/operations.json').read_text())
 if isinstance(catalog,dict):catalog=catalog.get('operations',[])
 offered={x['method'] for x in catalog}
 seen={x['method'] for x in rpc}
 try:sha=subprocess.run(['git','-C',str(repo),'rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip()
 except subprocess.CalledProcessError:sha='UNKNOWN'
 return {'schema':'btx.atlas.qt-inventory/1','checkout':sha,'scope':'Lexical inventory only; misses indirect/dynamic calls and does not test semantics','source_sha256':files,'actions':actions,'options':options,'form_files':forms,'direct_rpc_references':rpc,'rpc_without_template':sorted(seen-offered),'templates_not_observed_in_direct_qt_calls':sorted(offered-seen),'parity_qualified':False}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo',required=True,type=Path);p.add_argument('--out',type=Path);a=p.parse_args()
 report=json.dumps(run(a.repo.resolve()),indent=2)+'\n'
 if a.out:a.out.write_text(report)
 else:print(report,end='')
