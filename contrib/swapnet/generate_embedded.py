#!/usr/bin/env python3
"""Freeze trusted package sources into C++; no PYTHONPATH or current-dir imports."""
import argparse,json,hashlib
from pathlib import Path

def generate(source,out):
    source=Path(source);rows=[]
    for p in sorted(source.glob('*.py')):
        # The old stdio observer is a developer diagnostic, not a production host.
        if p.stem=='runtime':continue
        name='swapnet' if p.stem=='__init__' else 'swapnet.'+p.stem
        raw=p.read_text();compile(raw,str(p),'exec')
        rows.append((name,raw,p.stem=='__init__'))
    mapping={n:(s,pkg) for n,s,pkg in rows}
    bootstrap='''import sys, importlib.abc, importlib.util, json
_sources=json.loads(%s)
class _SwapNetFrozenImporter(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in _sources:
            return importlib.util.spec_from_loader(fullname,self,is_package=_sources[fullname][1])
    def create_module(self,spec): return None
    def exec_module(self,module):
        source,is_package=_sources[module.__name__]
        module.__file__='<btxd-frozen>/'+module.__name__.replace('.','/')+'.py'
        if is_package:module.__path__=[]
        exec(compile(source,module.__file__,'exec'),module.__dict__)
sys.meta_path.insert(0,_SwapNetFrozenImporter())
''' % repr(json.dumps(mapping,separators=(',',':')))
    delim='SN'+hashlib.sha256(bootstrap.encode()).hexdigest()[:12]
    text='#pragma once\nnamespace swapnet {\ninline constexpr const char* FROZEN_BOOTSTRAP = R"'+delim+'('+bootstrap+')'+delim+'";\n}\n'
    out=Path(out);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(text)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('source');p.add_argument('out');a=p.parse_args();generate(a.source,a.out)
