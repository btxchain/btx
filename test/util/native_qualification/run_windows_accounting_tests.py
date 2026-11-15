#!/usr/bin/env python3
"""Bounded native Windows accounting component tests, no node required.

Run in a Visual Studio x64 developer prompt. --baseline-tree compiles the same
fixture against pre-repair source. Rejection proof uses synthetic samples with
a real ordinary worker; it is not a real resource-exhaustion qualification.
"""
from pathlib import Path
import argparse,hashlib,json,os,platform,shutil,subprocess,sys,tempfile,time
ROOT=Path(__file__).resolve().parents[3]
CPP=['src/modelnet/swarm_windows_sandbox.cpp','src/modelnet/swarm_confine.cpp',
     'src/modelnet/swarm_fsjail.cpp','src/crypto/sha384.cpp']
INPUTS=CPP+['src/modelnet/swarm_windows_sandbox.h','src/modelnet/swarm_confine.h',
    'src/modelnet/swarm_fsjail.h','src/modelnet/swarm_process_guard.h','src/modelnet/swarm_native_io.h',
    'src/crypto/sha384.h','src/crypto/common.h','src/compat/endian.h','src/compat/byteswap.h',
    'src/util/fs.h','src/tinyformat.h','src/span.h','src/attributes.h','src/util/string.h','CMakeLists.txt']
FIXTURE='test/util/native_qualification/windows_accounting_tests.cpp'
SELF='test/util/native_qualification/run_windows_accounting_tests.py'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-tree',type=Path)
    parser.add_argument('--manifest',type=Path)
    parser.add_argument('--output',type=Path,default=ROOT/'windows-accounting-results')
    args=parser.parse_args()
    if os.name!='nt':raise SystemExit('Native Windows and an x64 Visual Studio developer prompt are required.')
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=True);marker=out/'.btx-accounting-test'
    if any(out.iterdir()) and not marker.exists():raise SystemExit('Select a fresh test output folder.')
    marker.write_text('BTXWindowsAccountingTestsV1\n')
    records=[];cases=[];identities={};owned=None;profiles=None;before=set();error=None;verdict='FAIL'
    def save():
        (out/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
        (out/'identities.json').write_text(json.dumps(identities,indent=2)+'\n')
    def run(label,argv,cwd=out,timeout=90):
        row={'label':label,'argv':[str(x) for x in argv],'cwd':str(cwd),'exit':None};records.append(row);save();start=time.monotonic()
        try:
            z=subprocess.run(row['argv'],cwd=cwd,capture_output=True,text=True,timeout=timeout)
            log=z.stdout+z.stderr;row['exit']=z.returncode
        except subprocess.TimeoutExpired as exc:
            def text(x):return x.decode(errors='replace') if isinstance(x,bytes) else x or ''
            log=text(exc.stdout)+text(exc.stderr);row['timed_out']=True
            (out/(label+'.log')).write_text(log);row['seconds']=time.monotonic()-start;save();raise
        (out/(label+'.log')).write_text(log);row['seconds']=time.monotonic()-start;row['log_sha256']=sha(out/(label+'.log'));save();return z
    try:
        cl=shutil.which('cl.exe');assert cl,'cl.exe not found'
        baseline=args.baseline_tree.resolve() if args.baseline_tree else None
        sources={'candidate':{name:sha(ROOT/name) for name in INPUTS+[FIXTURE,SELF,'src/modelnet/swarm_windows_accounting.h']}}
        if baseline:sources['baseline']={name:sha(baseline/name) for name in INPUTS}
        if args.manifest:
            expected=json.loads(args.manifest.read_text())
            for variant,files in expected['sources'].items():
                for name,digest in files.items():assert sources[variant][name]==digest,(variant,name)
        identities.update(platform=platform.platform(),machine=platform.machine(),compiler=cl,
            windows_sdk_version=os.environ.get('WindowsSDKVersion'),sources=sources,binaries={})
        flags=['/nologo','/std:c++20','/EHsc','/O2','/MT','/W4','/DWIN32','/D_WINDOWS','/DUNICODE','/D_UNICODE',
            '/utf-8','/Zc:preprocessor','/Zc:__cplusplus','/sdl','/D_WIN32_WINNT=0x0A00','/D_WIN32_IE=0x0A00',
            '/DNOMINMAX','/DWIN32_LEAN_AND_MEAN']
        def build(name,source,definitions,worker=False):
            directory=out/(name+'-objects');directory.mkdir(exist_ok=True)
            argv=[cl,*flags,*definitions,'/I'+str(source/'src'),'/I'+str(ROOT/'src'),str(ROOT/FIXTURE)]
            if not worker:argv += [str(source/n) for n in CPP]
            argv += ['/Fe:'+str(out/(name+'.exe'))]
            if not worker:argv += ['/link','userenv.lib','advapi32.lib','bcrypt.lib','ole32.lib']
            z=run('build-'+name,argv,cwd=directory);assert z.returncode==0,'build failed: '+name
            identities['binaries'][name+'.exe']=sha(out/(name+'.exe'));save()
        build('worker',ROOT,['/DBTX_ACCOUNTING_WORKER'],worker=True)
        if baseline:build('baseline',baseline,['/DBTX_ACCOUNTING_BASELINE','/DBTX_WINDOWS_ACCOUNTING_TEST'])
        build('production',ROOT,[])
        build('fault',ROOT,['/DBTX_WINDOWS_ACCOUNTING_TEST'])
        profiles=Path(os.environ['LOCALAPPDATA'])/'Packages';before={x.name for x in profiles.glob('btx.native.*')}
        owned=Path(tempfile.mkdtemp(prefix='btx-acct-'))
        def case(binary,mode,expected,required):
            label=binary+'-'+mode;z=run(label,[out/(binary+'.exe'),mode,out/'worker.exe',owned/label],timeout=45)
            ok=z.returncode==expected and all(s in z.stdout for s in required)
            new_profiles=sorted({x.name for x in profiles.glob('btx.native.*')}-before)
            cases.append({'label':label,'expected_exit':expected,'actual_exit':z.returncode,'required_tokens':required,
                'pass':ok,'new_matching_profile_directories':new_profiles})
            assert ok,label+' failed; see recorded log'
            assert not new_profiles,label+' left new matching profile directories'
        faults=['cpu','tree','query','final-cpu','clock']
        if baseline:
            for mode in ['normal','nonzero']:case('baseline',mode,0,['VERDICT PASS '+mode,'inputs_unchanged=1'])
            for mode in faults:case('baseline',mode,1,['CASE '+mode+' code=JAILED launched=1 jailed=1 child=0',
                'output_ok=1 inputs_unchanged=1','VERDICT FAIL expected-resource-refusal-did-not-occur'])
        for mode in ['normal','nonzero']:case('production',mode,0,['VERDICT PASS '+mode,'inputs_unchanged=1'])
        case('production','policy',0,['POLICY PASS'])
        case('production','scanner',0,['SCANNER PASS'])
        case('fault','normal',0,['VERDICT PASS normal','started_observed=1','staged_missing=1','process_exited=1'])
        for mode in faults:
            required=['VERDICT PASS '+mode,'started_observed=1','staged_missing=1','process_exited=1',
                'RECOVERY after='+mode+' same_process=1','RECOVERY PASS '+mode]
            if mode=='final-cpu':required.append('FINAL_OBSERVATION completion_poll=1 process_signaled=1')
            case('fault',mode,0,required)
        identities['binary_hashes_unchanged']=all(sha(out/n)==h for n,h in identities['binaries'].items())
        assert identities['binary_hashes_unchanged']
        identities['source_hashes_unchanged']=all(sha((ROOT if v=='candidate' else baseline)/n)==h
            for v,files in sources.items() for n,h in files.items())
        assert identities['source_hashes_unchanged']
        verdict='PASS'
    except Exception as exc:error=str(exc)
    finally:
        cleanup='No owned fixture root created'
        if owned is not None:
            try:shutil.rmtree(owned);cleanup='Owned original fixture roots removed'
            except Exception as exc:verdict='FAIL';error=str(exc);cleanup='Owned original fixture cleanup failed'
        remaining=None if profiles is None else sorted({x.name for x in profiles.glob('btx.native.*')}-before)
        if remaining:verdict='FAIL';error='New matching profile directories remain: '+repr(remaining)
        save()
        result={'verdict':verdict,'error':error,'cases':cases,'cleanup':cleanup,'remaining_profile_directories':remaining,
            'scope':'Native component; rejection uses synthetic accounting samples with real finite workers/Jobs and same-process recovery. Not a real CPU/disk quota violation, all-filesystem, Windows11, fullnode or release qualification.'}
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
    return 0 if verdict=='PASS' else 1

if __name__=='__main__':sys.exit(main())
