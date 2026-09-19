from pathlib import Path
import json,hashlib,zipfile,shutil
import fitz
R=Path(__file__).resolve().parents[1]
O=R.parent
aliases={
 '01_Cognitive_Reserve_Layer_Strategy':'BTX_CRL_v1_2_Strategy',
 '02_Neutral_Provider_and_Institutional_Spec':'BTX_CRL_v1_2_Development_Spec',
 '03_Integration_and_Launch_Guide':'BTX_CRL_v1_2_Integration_Guide',
 '04_Whole_Portfolio_Integration_Guide':'BTX_CRL_v1_2_Whole_Portfolio_Guide',
 '05_UX_and_Product_Playbook':'BTX_CRL_v1_2_UX_Playbook',
 '06_Acceptance_and_Journeys':'BTX_CRL_v1_2_Acceptance'
}
docs=[]
for stem,alias in aliases.items():
 for ext in ('md','docx','pdf'):
  src=R/'docs'/f'{stem}.{ext}'
  assert src.is_file() and src.stat().st_size>0
  shutil.copy2(src,O/f'{alias}.{ext}')
 with fitz.open(R/'docs'/f'{stem}.pdf') as pdf:pages=len(pdf)
 docs.append({'stem':stem,'alias':alias,'pages':pages})
for ext in ('md','txt'):
 shutil.copy2(R/'agents'/f'CURSOR_COORDINATOR_PROMPT.{ext}',O/f'BTX_CRL_v1_2_Cursor_Prompt.{ext}')
shutil.copy2(R/'ux/index.html',O/'BTX_CRL_v1_2_Interactive_Prototype.html')
validation=json.loads((R/'qa/VALIDATION.json').read_text())
layout=json.loads((R/'qa/layout-report.json').read_text())
ux=json.loads((R/'qa/ux-prototype-test.json').read_text())
report={'edition':'1.2','documents':docs,'total_pages':sum(x['pages'] for x in docs),'validation':validation,'layout':layout['status'],'ux':ux,'native_acceptance':'NOT_RUN; 160 specified cases and 20 journeys; execute on integrated private BTX build.'}
(R/'qa/DELIVERY.json').write_text(json.dumps(report,indent=2))
def include(p):
 rel=p.relative_to(R)
 return (p.is_file() and '__pycache__' not in rel.parts and p.suffix.lower() not in {'.pyc','.ttf','.otf','.woff','.woff2'} and not (len(rel.parts)>1 and rel.parts[0]=='qa' and (rel.parts[1] in {'render','visual-pairs'} or p.suffix=='.png')))
files=[p for p in sorted(R.rglob('*')) if include(p) and p.name!='PACKAGE_SHA256SUMS.txt']
(R/'PACKAGE_SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(R).as_posix()}\n' for p in files))
files.append(R/'PACKAGE_SHA256SUMS.txt')
archive=O/'BTX_Cognitive_Reserve_Layer_v1_2.zip'
with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for p in files:z.write(p,arcname=R.name+'/'+p.relative_to(R).as_posix())
with zipfile.ZipFile(archive) as z:
 assert z.testzip() is None
 assert len(z.namelist())==len(files)
 assert not any(n.endswith(('.ttf','.otf','.woff','.woff2')) for n in z.namelist())
report.update(files=len(files),zip_bytes=archive.stat().st_size,zip_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),archive=archive.name)
(O/'BTX_CRL_v1_2_VERIFIED.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
