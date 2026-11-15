import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
import {PointStore,decodePage,SpatialIndex,lasso,insidePolygon,MAX_POINTS} from '../web/neuronlab/science/embedding-data.js';
const id='a'.repeat(96);
const encode=a=>Buffer.from(a.buffer,a.byteOffset,a.byteLength).toString('base64');
function page(offset,count,total,stride=1){const ids=Uint32Array.from({length:count},(_,i)=>offset+i*stride);return {schema:'btx.neuronlab.embedding-page/2',dataset_id:id,count,total_rows:total,stride,next_offset:offset+count*stride<total?offset+count*stride:null,coordinates_f32_le:encode(Float32Array.from({length:count*2},(_,i)=>i*.25)),categories_u32_le:encode(new Uint32Array(count*4)),row_ids_u32_le:encode(ids)};}

test('all production JS modules parse without recovery transpilation',()=>{const web=fileURLToPath(new URL('../web/',import.meta.url));const walk=dir=>fs.readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?walk(path.join(dir,e.name)):e.name.endsWith('.js')?[path.join(dir,e.name)]:[]);for(const file of walk(web)){const r=spawnSync(process.execPath,['--check',file],{encoding:'utf8'});assert.equal(r.status,0,`${file}\n${r.stderr}`);}});
test('binary embedding page retains typed original IDs',()=>{const p=decodePage(page(0,8,8),id);assert.equal(p.count,8);assert.deepEqual([...p.ids],[0,1,2,3,4,5,6,7]);assert.equal(p.xy[1],.25);});
test('dataset ID and row limits reject cross-dataset data',()=>{for(const change of [{dataset_id:'b'.repeat(96)},{count:32769},{total_rows:MAX_POINTS+1},{stride:0},{next_offset:'opaque-invented'}])assert.throws(()=>decodePage({...page(0,2,8),...change},id));});
test('binary size and nonfinite values refused',()=>{const p=page(0,2,8);assert.throws(()=>decodePage({...p,coordinates_f32_le:'AAAA'},id));assert.throws(()=>decodePage({...p,coordinates_f32_le:encode(new Float32Array([0,0,NaN,1]))},id));});
test('out-of-order and repeated pages cannot silently fill data gaps',()=>{const s=new PointStore({id,rows:8});s.append(page(0,4,8));assert.throws(()=>s.append(page(0,4,8)));assert.throws(()=>s.append(page(5,3,8)));s.append(page(4,4,8));assert.equal(s.complete,true);assert.equal(s.memoryBytes(),8*28);});
test('continuation and dimensions must match',()=>{const s=new PointStore({id,rows:8});assert.throws(()=>s.append({...page(0,4,8),next_offset:7}));assert.throws(()=>s.append(page(0,4,9)));});
test('strided sample is not presented as complete',()=>{const s=new PointStore({id,rows:10},3);s.append(page(0,4,10,3));assert.equal(s.count,4);assert.equal(s.complete,false);assert.deepEqual([...s.ids],[0,3,6,9]);});
test('disposal releases point arrays',()=>{const s=new PointStore({id,rows:8});s.append(page(0,8,8));s.dispose();assert.equal(s.memoryBytes(),0);assert.equal(s.count,0);});
test('row selection bounds and exact values',()=>{const s=new PointStore({id,rows:8});s.append(page(0,8,8));assert.equal(s.row(4).row,4);assert.equal(s.row(4).x,2);assert.throws(()=>s.row(8));});
test('spatial grid returns same nearest point as bounded brute force',()=>{const n=2000,xy=new Float32Array(n*2);let x=19;const random=()=>{x=(Math.imul(x,1664525)+1013904223)>>>0;return x/4294967296;};for(let i=0;i<xy.length;i++)xy[i]=random()*4-2;const index=new SpatialIndex(xy,n,[-2,-2,2,2]);for(let t=0;t<100;t++){const x=random()*4-2,y=random()*4-2,r=.2;let expected=-1,d=r*r;for(let i=0;i<n;i++){const z=(x-xy[i*2])**2+(y-xy[i*2+1])**2;if(z<=d){expected=i;d=z;}}assert.equal(index.nearest(x,y,r),expected);}});
test('spatial index honours display filtering',()=>{const xy=new Float32Array([0,0,.01,0,2,2]),index=new SpatialIndex(xy,3,[0,0,2,2]);assert.equal(index.nearest(0,0,1,i=>i!==0),1);});
test('lasso geometric membership and capped evidence',()=>{const xy=new Float32Array([0,0,1,1,2,2,3,3]),polygon=[[-1,-1],[2.5,-1],[2.5,2.5],[-1,2.5]];const r=lasso(xy,4,polygon,2);assert.equal(r.total,3);assert.equal(r.truncated,true);assert.deepEqual([...r.slots],[0,1]);});
test('lasso respects hidden categories',()=>{const xy=new Float32Array([0,0,1,1,2,2]),polygon=[[-1,-1],[4,-1],[4,4],[-1,4]];const r=lasso(xy,3,polygon,10,new Uint8Array([1,0,1]));assert.deepEqual([...r.slots],[0,2]);});
test('invalid polygons and selection caps fail closed',()=>{for(const p of [[],[[NaN,0],[0,1],[1,0]],new Array(129).fill([0,0])])assert.throws(()=>lasso(new Float32Array(4),2,p));assert.throws(()=>lasso(new Float32Array(4),2,[[0,0],[1,0],[1,1]],10001));});
test('large data structures have explicit allocations',()=>{const s=new PointStore({id,rows:100000});assert.equal(s.memoryBytes(),2800000);assert.throws(()=>new PointStore({id,rows:MAX_POINTS+1}));});
test('scientific extensions do not evaluate model-generated code',()=>{const root=fileURLToPath(new URL('../web/neuronlab/science/',import.meta.url));for(const name of fs.readdirSync(root).filter(x=>x.endsWith('.js'))){const text=fs.readFileSync(path.join(root,name),'utf8');assert(!/\beval\s*\(|new\s+Function\s*\(|\.innerHTML\s*=/.test(text),name);}});

test('unchanged selection worker handles one million points off the caller thread',async()=>{
 const {Worker}=await import('node:worker_threads');const worker=new Worker(new URL('./science-worker-shim.mjs',import.meta.url),{type:'module'});
 const receive=()=>new Promise((resolve,reject)=>{worker.once('message',resolve);worker.once('error',reject);});
 try{
  const n=1000000,xy=new Float32Array(n*2);for(let i=0;i<n;i++){xy[2*i]=(i%1000)/1000;xy[2*i+1]=Math.floor(i/1000)/1000;}
  const ready=receive();worker.postMessage({type:'dataset',xy,count:n,generation:7},[xy.buffer]);assert.equal((await ready).type,'ready');
  const mask=new Uint8Array(n);for(let i=0;i<n;i++)mask[i]=i%2;worker.postMessage({type:'visibility',generation:7,mask},[mask.buffer]);
  const done=receive();worker.postMessage({type:'lasso',generation:7,request:19,polygon:[[-1,-1],[2,-1],[2,2],[-1,2]]});const result=await done;
  assert.equal(result.total,500000);assert.equal(result.slots.length,10000);assert.equal(result.truncated,true);assert.equal(result.request,19);assert.equal(result.slots[0],1);
 }finally{await worker.terminate();}
});

test('selection worker rejects malformed buffers',async()=>{
 const {Worker}=await import('node:worker_threads');const worker=new Worker(new URL('./science-worker-shim.mjs',import.meta.url),{type:'module'});
 try{const reply=new Promise((resolve,reject)=>{worker.once('message',resolve);worker.once('error',reject);});worker.postMessage({type:'dataset',xy:[],count:10,generation:1});assert.equal((await reply).type,'error');}finally{await worker.terminate();}
});
