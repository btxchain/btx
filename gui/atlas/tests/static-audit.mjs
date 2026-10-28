import {execFileSync,spawnSync} from 'node:child_process';import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const files=[];function walk(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){const p=path.join(dir,e.name);if(e.isDirectory())walk(p);else files.push(p);}}walk(path.join(root,'web'));
const checks=[];const check=(name,fn)=>{fn();checks.push(name);};
check('no frontend runtime package dependencies',()=>{const p=JSON.parse(fs.readFileSync(path.join(root,'package.json')));assert.equal(Object.keys(p.dependencies||{}).length,0);});
check('all static ES module imports resolve',()=>{for(const p of files.filter(x=>x.endsWith('.js'))){const s=fs.readFileSync(p,'utf8');for(const m of s.matchAll(/(?:import|export)\s+[^;]*?\bfrom\s+['"]([^'"]+)['"]/g)){assert.ok(m[1].startsWith('.'),`${p}: nonlocal module ${m[1]}`);assert.ok(fs.existsSync(path.resolve(path.dirname(p),m[1])),`${p}: missing ${m[1]}`);}}});
check('no executable HTML or string-code sinks',()=>{for(const p of files.filter(x=>x.endsWith('.js'))){const s=fs.readFileSync(p,'utf8');for(const re of [/\.innerHTML\s*=/,/\.outerHTML\s*=/,/insertAdjacentHTML\s*\(/,/\beval\s*\(/,/\bnew\s+Function\s*\(/,/document\.write\s*\(/,/set(?:Timeout|Interval)\s*\(\s*['"`]/])assert.ok(!re.test(s),`${p}: ${re}`);}});
check('no frontend network RPC or cloud transport',()=>{for(const p of files.filter(x=>x.endsWith('.js'))){const s=fs.readFileSync(p,'utf8');assert.ok(!/\b(fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/.test(s),`${p}: network API`);}});
check('worker is local and renderer has explicit disposal',()=>{const s=fs.readFileSync(path.join(root,'web/render/scene.js'),'utf8');for(const needle of ['worker?.terminate()','resizeObserver.disconnect()','deleteBuffer','deleteProgram','cancelAnimationFrame','10000','30000'])assert.ok(s.includes(needle),needle);});
check('native core and host forbid authored unsafe Rust',()=>{for(const p of ['crates/atlas-core/src/lib.rs','src-tauri/src/main.rs'])assert.ok(fs.readFileSync(path.join(root,p),'utf8').includes('#![forbid(unsafe_code)]'));});
check('CSP has no remote sources, frames, or eval',()=>{const c=JSON.parse(fs.readFileSync(path.join(root,'src-tauri/tauri.conf.json'))),s=c.app.security.csp;assert.ok(s.includes("default-src 'none'"));assert.ok(s.includes("frame-src 'none'"));assert.ok(!s.includes('unsafe-eval'));assert.ok(!/https?:\/\/(?!ipc.localhost)/.test(s));assert.equal(c.app.security.freezePrototype,true);});
check('only local main window gets IPC capabilities',()=>{const c=JSON.parse(fs.readFileSync(path.join(root,'src-tauri/capabilities/main.json')));assert.deepEqual(c.windows,['main']);assert.ok(!c.remote);assert.ok(!c.permissions.some(x=>/shell|http|fs:|opener|clipboard/.test(x)));});
check('native command allowlist matches declared app commands',()=>{const build=fs.readFileSync(path.join(root,'src-tauri/build.rs'),'utf8');const commandNames=[...build.matchAll(/"(atlas_[a-z_]+)"/g)].map(x=>x[1]);const nativeDir=path.join(root,'src-tauri/src');const src=fs.readdirSync(nativeDir).filter(x=>x.endsWith('.rs')).map(x=>fs.readFileSync(path.join(nativeDir,x),'utf8')).join('\n');for(const name of commandNames)assert.ok(src.includes(`fn ${name}(`),name);const cap=JSON.parse(fs.readFileSync(path.join(root,'src-tauri/capabilities/main.json')));for(const name of commandNames)assert.ok(cap.permissions.includes('allow-'+name.replaceAll('_','-')),name);});
check('explicit native write review and no auto retry',()=>{const s=fs.readFileSync(path.join(root,'src-tauri/src/commands.rs'),'utf8');assert.ok(s.includes('confirm(&app,"Authorize exact operation"'));assert.ok(s.includes('consume(&id,c.epoch)'));assert.ok(s.includes('h.recheck(&c)?'));assert.ok(s.indexOf('h.audit(&id,&request.method,"SUBMITTED")?')<s.indexOf('let reply=c.rpc.call'));});
check('local generator contract preserves native signature',()=>{const s=fs.readFileSync(path.join(root,'crates/atlas-core/src/agent.rs'),'utf8').replace(/\s+/g,'');assert.ok(s.includes('"generatemodel",&json!([model,{"prompt":prompt,"max_new_tokens":256}])'));assert.ok(s.includes('forroundin0..2'));assert.ok(s.includes('remaining:32'));});
check('candidate does not silently change monetary node files',()=>{
  assert.ok(!fs.existsSync(path.join(root,'src/validation.cpp')));
  assert.ok(!fs.existsSync(path.join(root,'src/wallet/wallet.cpp')));
  const repo=path.resolve(root,'../..');
  const validation=path.join(repo,'src/validation.cpp');
  const wallet=path.join(repo,'src/wallet/wallet.cpp');
  if(!fs.existsSync(validation)){assert.ok(!fs.existsSync(wallet));return;}
  // Integrated tree: those files belong to the node. Atlas must not edit them.
  execFileSync('git',['-C',repo,'diff','--exit-code','--','src/validation.cpp','src/wallet/wallet.cpp'],{stdio:'pipe'});
});
check('all production JavaScript parses without transpiler recovery',()=>{for(const p of files.filter(x=>x.endsWith('.js'))){const r=spawnSync(process.execPath,['--check',p],{encoding:'utf8'});assert.equal(r.status,0,`${p}: ${r.stderr}`);}});
const report={schema:'btx.atlas.static-checks/1',passed:checks.length,checks,scope:'Textual/source-structure checks; not compilation, taint analysis, sandbox validation, or formal verification'};
console.log(JSON.stringify(report,null,2));
