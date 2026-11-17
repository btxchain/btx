import pathlib,subprocess,json,socket,time,os,hashlib,signal,sys
B=pathlib.Path(sys.argv[1]).resolve();R=pathlib.Path(sys.argv[2]).resolve();OUT=pathlib.Path(sys.argv[3]).resolve();OUT.mkdir(parents=True,exist_ok=True);R.mkdir(mode=0o700);M=R/'model';M.mkdir();S=R/'rpc.sock';P=None;L=None;rows=[];checks=[];starts=0

def rpc(method,*args):
 with socket.socket(socket.AF_UNIX) as s:
  s.settimeout(10);s.connect(str(S));s.sendall((json.dumps({'id':len(rows)+1,'method':method,'params':list(args)})+'\n').encode());s.shutdown(socket.SHUT_WR)
  with s.makefile('rb') as f:v=json.loads(f.readline(2**20))
 rows.append({'method':method,'args':args,'reply':v});return v

def ok(method,*args):
 v=rpc(method,*args);assert v.get('error') is None,(method,v);return v['result']
def stop():
 global P,L
 if P:
  P.terminate()
  try:P.wait(15)
  except subprocess.TimeoutExpired:P.kill();P.wait(5);raise AssertionError('unclean helper stop')
  assert P.returncode==0,P.returncode;P=None
 if L:L.close();L=None
 if S.exists():S.unlink()
def boot():
 global P,L,starts
 starts+=1;L=(OUT/f'helper-{starts}.log').open('wb');env=dict(os.environ);env['BTX_OPENSSL']=str(pathlib.Path(os.environ['GITHUB_WORKSPACE'])/'gui-pilot-runtime/openssl/bin/openssl')
 P=subprocess.Popen([str(B),'-modeldir='+str(M),'-modelrpcsocket='+str(S),'-modelstorage=8MiB','-modelbind=off','-modellandiscovery=0','-modelnatpmp=0','-modelfollowpeers=0','-modelseed=off','-modelpreserverare=0'],stdout=L,stderr=subprocess.STDOUT,env=env)
 end=time.monotonic()+30
 while time.monotonic()<end:
  assert P.poll() is None,'helper exited before socket'
  if S.exists():
   try:ok('getbountyfunding','synthetic');return
   except (ConnectionRefusedError,FileNotFoundError):pass
  time.sleep(.1)
 raise AssertionError('helper startup timeout')
def files():return {str(p.relative_to(M)):hashlib.sha256(p.read_bytes()).hexdigest() for p in M.rglob('bounty-store.json')}
def refusal(label):
 before=files();state=ok('getbountyfunding','synthetic');v=rpc('reorgbountychain','synthetic');after=files();stateafter=ok('getbountyfunding','synthetic');passed=v.get('error') is not None and 'UNDO_UNAVAILABLE' in json.dumps(v['error']) and before==after and state==stateafter and not (v.get('result') or {}).get('event')
 checks.append({'label':label,'pass':passed,'before':before,'after':after,'reply':v})
try:
 boot();f={'outpoint':'synthetic:0','bounty_id':'synthetic','lot_id':'lot0','amount_atoms':'100','confirmations':6,'height':100,'spent':False};ok('observebountychain',f);saved=ok('exportbountyrecovery','synthetic');ok('observebountychain',dict(f,spent=True));assert ok('getbountyfunding','synthetic')['confirmed_atoms']=='0';assert ok('reorgbountychain','synthetic')['confirmed_atoms']=='100';ok('observebountychain',dict(f,spent=True));stop();boot();refusal('restarted_no_undo');refusal('repeated_no_undo');ok('importbountyrecovery',saved);assert ok('getbountyfunding','synthetic')['confirmed_atoms']=='100';stop();boot();assert ok('getbountyfunding','synthetic')['confirmed_atoms']=='100';ok('observebountychain',f);assert ok('getbountyfunding','synthetic')['facts'][0]['confirmations']==6;assert len(ok('exportbountyrecovery','synthetic')['lots'])==1;stop()
 M=R/'empty-model';M.mkdir();boot();refusal('fresh_empty');ok('observebountychain',f);key={'bounty_id':'synthetic','idempotency_key':'rollback-key'};first=ok('reorgbountychain',key);before=files();assert ok('reorgbountychain',key)==first and files()==before;refusal('exhausted_after_valid_undo');stop()
 result={'checks':checks,'calls':rows,'starts':starts,'binary_sha256':hashlib.sha256(B.read_bytes()).hexdigest(),'controls':'same-processundo, imported recovery, actual second/third process restart, metadata reobservation, lotdedup, successful keyed replay','status':'PASS' if all(x['pass'] for x in checks) else 'EXPECTED_CONTRACT_FAILURE'};(OUT/'result.json').write_text(json.dumps(result,indent=2));print(result['status'],flush=True);sys.exit(0 if result['status']=='PASS' else 7)
finally:
 if P:stop()
