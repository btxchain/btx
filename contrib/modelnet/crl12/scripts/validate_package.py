from pathlib import Path
import csv,json,yaml,re,subprocess,sys,hashlib
from jsonschema import Draft202012Validator
R=Path(__file__).resolve().parents[1]
report={}
schema=json.loads((R/'schemas/CognitiveReserveLayer.schema.json').read_text());Draft202012Validator.check_schema(schema)
D=schema['$defs'];count=0
for p in sorted((R/'examples/valid').glob('*.json')):
 v=Draft202012Validator({'$schema':schema['$schema'],'$defs':D,'$ref':'#/$defs/'+p.stem});v.validate(json.loads(p.read_text()));count+=1
bad=json.loads((R/'examples/invalid/manifest.json').read_text())
for row in bad:
 v=Draft202012Validator({'$defs':D,'$ref':'#/$defs/'+row['type']});errors=list(v.iter_errors(json.loads((R/'examples/invalid'/row['file']).read_text())))
 if not errors:raise AssertionError('Invalid fixture accepted: '+row['file'])
report.update(schema='PASS',valid_bodies=count,invalid_bodies=len(bad))
base=yaml.safe_load((R/'compatibility/v1_1/schemas/openapi-v1.1.yaml').read_text());new=yaml.safe_load((R/'schemas/openapi-v1.2.yaml').read_text())
methods={'get','post','put','patch','delete','head','options','trace'}
oldcount=0
for path,item in base['paths'].items():
 for method,value in item.items():
  if method in methods:
   assert new['paths'][path][method]==value,(path,method);oldcount+=1
for name,value in base['components']['schemas'].items():assert new['components']['schemas'][name]==value,name
for name,value in base['components']['securitySchemes'].items():assert new['components']['securitySchemes'][name]==value,name
newops=json.loads((R/'schemas/operations-v1.2.json').read_text())['operations'];total=sum(k in methods for v in new['paths'].values() for k in v)
assert len(newops)==43 and oldcount==84 and total==127
assert len({o['operation_id'] for o in newops})==43
for o in newops:
 route=new['paths'][o['path'].removeprefix('/btx/hcp/v1')][o['method'].lower()]
 assert route['operationId']==o['operation_id']
 assert route['x-btx-effect']==o['effect']
 assert o['effect'] not in {'AUTHORIZE','EXECUTE_APPROVED','SUBMIT'}
def refs(x):
 if isinstance(x,dict):
  for k,v in x.items():
   if k=='$ref' and isinstance(v,str) and v.startswith('#/components/schemas/'):assert v.split('/')[-1] in new['components']['schemas'],v
   refs(v)
 elif isinstance(x,list):
  for v in x:refs(v)
refs(new)
report.update(preserved_operations=oldcount,new_operations=len(newops),total_operations=total,new_signed_types=sum(k.endswith('V1_2') for k in D),compatibility='PASS')
with (R/'tests/native-acceptance-v1.2.csv').open() as f:cases=list(csv.DictReader(f))
assert len(cases)==160 and len({c['case_id'] for c in cases})==160
assert all(c['status']=='NOT_RUN' for c in cases)
journeys=json.loads((R/'tests/journeys.json').read_text());assert len(journeys)==20
report.update(native_cases=160,native_status='NOT_RUN',journeys=20)
brands=re.compile(r'\b(coinbase|binance|kraken|revolut|robinhood|blackrock|aladdin|payward)\b',re.I)
for folder in ('agents','reference','sdk','deploy','ux'):
 for p in (R/folder).rglob('*'):
  if p.is_file() and p.suffix in {'.py','.ts','.yaml','.json','.md','.html','.csv','.sql','.txt'}:
   assert not brands.search(p.read_text()),str(p)
report['operational_brand_neutrality']='PASS'
test=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-p','test_reference.py','-v'],cwd=R,text=True,capture_output=True,timeout=40)
(R/'qa/reference-tests.log').write_text(test.stdout+test.stderr)
assert test.returncode==0,test.stderr
m=re.search(r'Ran (\d+) tests',test.stderr);report['reference_tests']={'status':'PASS','run':int(m.group(1))}
try:
 ts=subprocess.run(['tsc','--strict','--noEmit','--target','ES2022','--lib','ES2022,DOM','sdk/crl_client.ts'],cwd=R,text=True,capture_output=True,timeout=40)
 (R/'qa/typescript.log').write_text(ts.stdout+ts.stderr);assert ts.returncode==0,ts.stdout+ts.stderr;report['typescript']='PASS'
except FileNotFoundError:report['typescript']='NOT_RUN: tsc unavailable'
# Keep provenance of exact inherited objects separate from generated views.
basehash={str(p.relative_to(R/'compatibility/v1_1')):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((R/'compatibility/v1_1').rglob('*')) if p.is_file() and p.name != 'SHA256.json'}
(R/'compatibility/v1_1/SHA256.json').write_text(json.dumps(basehash,indent=2))
(R/'qa/VALIDATION.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
