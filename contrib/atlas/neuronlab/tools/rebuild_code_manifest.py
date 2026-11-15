#!/usr/bin/env python3
"""Run only after reviewing changed scientific code; old fingerprints may expire."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--worker-root',type=Path,required=True);a=p.parse_args();r=a.worker_root.resolve(strict=True)
files=[r/'worker.py',r/'generate_adapter.py',*sorted((r/'btx_neuronlab').glob('*.py'))]
for f in files:
 if f.is_symlink()or not f.is_file():raise SystemExit('Regular reviewed source files required')
m={'schema':'btx.neuronlab.code-manifest/1','version':'0.2.0','files':{f.relative_to(r).as_posix():hashlib.sha256(f.read_bytes()).hexdigest()for f in files},'notice':'Local source integrity manifest, not an independent signing certificate or dependency audit.'}
(r/'code-manifest.json').write_text(json.dumps(m,indent=2)+'\n')
print('Recorded',len(files),'reviewed source files; no executable downloads.')
