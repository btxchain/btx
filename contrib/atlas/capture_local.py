#!/usr/bin/env python3
"""Optional manual CPU-only activation capture for a locally installed SafeTensors
causal LM. Not invoked by Atlas, not a node grant, not a production training engine.
Requires independently provisioned torch and transformers. No dependency install,
remote download, remote code, pickle weights, prompt export, or shell execution.
"""
from __future__ import annotations
import argparse,hashlib,json,os,sys
from pathlib import Path

def main()->int:
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--model-dir',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
 p.add_argument('--input',type=Path,required=True,help='Local prompt UTF-8 file; its text is not included in the result')
 p.add_argument('--maximum-weight-bytes',type=int,default=2_147_483_648)
 p.add_argument('--threads',type=int,default=4);p.add_argument('--max-tokens',type=int,default=128)
 p.add_argument('--units-per-layer',type=int,default=256)
 a=p.parse_args()
 if not 1<=a.threads<=32 or not 1<=a.max_tokens<=512 or not 1<=a.units_per_layer<=512:p.error('Resource bounds exceeded')
 model=a.model_dir.resolve(strict=True)
 if not model.is_dir() or a.out.exists():p.error('Model directory missing or output already exists')
 config=json.loads((model/'config.json').read_text())
 if config.get('auto_map'):p.error('Custom model code mapping refused')
 if any(x.suffix.lower() in {'.bin','.pt','.pth','.pkl','.py','.so','.dll'} for x in model.rglob('*')):p.error('Only a clean local SafeTensors/tokenizer/config directory is accepted')
 weights=sorted(model.glob('*.safetensors'))
 if not weights or any(x.is_symlink() for x in model.rglob('*')):p.error('SafeTensors weights required; symlinks refused')
 if not 1<=a.maximum_weight_bytes<=8_589_934_592 or sum(x.stat().st_size for x in weights)>a.maximum_weight_bytes:p.error('Weight byte budget exceeded')
 prompt=a.input.read_bytes()
 if len(prompt)>32768:p.error('Prompt exceeds 32 KiB')
 prompt=prompt.decode('utf-8')
 os.environ.update(HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1',TOKENIZERS_PARALLELISM='false')
 import torch
 from transformers import AutoModelForCausalLM,AutoTokenizer
 torch.set_num_threads(a.threads)
 tokenizer=AutoTokenizer.from_pretrained(model,local_files_only=True,trust_remote_code=False)
 lm=AutoModelForCausalLM.from_pretrained(model,local_files_only=True,trust_remote_code=False,use_safetensors=True,device_map=None,torch_dtype=torch.float32)
 lm.eval();captured=[];handles=[]
 # Capture actual Linear outputs, not invented MLP/neuron geometry.
 modules=[(name,m) for name,m in lm.named_modules() if isinstance(m,torch.nn.Linear)][:128]
 def hook(name):
  def save(_m,_i,out):
   if len(captured)>=128 or not torch.is_tensor(out) or out.numel()==0:return
   v=out.detach().reshape(-1,out.shape[-1])[-1].float().cpu()
   k=min(a.units_per_layer,v.numel());indices=torch.topk(v.abs(),k=k,sorted=True).indices.tolist()
   units=[{'index':int(i),'value':float(v[i])} for i in indices if torch.isfinite(v[i]) and abs(float(v[i]))<=1e30]
   captured.append({'id':name,'metric':'linear_output_last_token_top_absolute','units':units})
  return save
 try:
  for name,m in modules:handles.append(m.register_forward_hook(hook(name)))
  tokens=tokenizer(prompt,return_tensors='pt',truncation=True,max_length=a.max_tokens)
  with torch.inference_mode():lm(**tokens,use_cache=False)
 finally:
  for h in handles:h.remove()
 manifest=[]
 for path in weights:
  digest=hashlib.sha384()
  with path.open('rb') as f:
   for block in iter(lambda:f.read(1<<20),b''):digest.update(block)
  manifest.append({'file':path.name,'sha384':digest.hexdigest(),'bytes':path.stat().st_size})
 payload=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode();identity=hashlib.sha384(payload).hexdigest()
 output={'schema':'btx.atlas.capture/1','provenance':{'model_id':'local-capture:'+identity,'runtime':'transformers/local-safetensors/cpu','torch':torch.__version__,'identity_kind':'LOCAL_MANIFEST_NOT_NATIVE_BTX_ARTIFACT_ID','weights':manifest,'privacy':'LOCAL_PRIVATE_ACTIVATIONS_NO_PROMPT_TEXT','qualification':'UNQUALIFIED_SINGLE_PROCESS_CAPTURE'},'layers':captured}
 encoded=json.dumps(output,allow_nan=False,separators=(',',':')).encode()
 if len(encoded)>1_048_576:raise ValueError('Capture exceeds Atlas import budget')
 fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(encoded);f.flush();os.fsync(f.fileno())
 print(f'Wrote {len(captured)} measured layers. Import in Atlas Research. No safety, quality, or execution-admission proof is implied.')
 return 0
if __name__=='__main__':
 try:raise SystemExit(main())
 except (OSError,ValueError,ImportError) as e:print(str(e),file=sys.stderr);raise SystemExit(1)
