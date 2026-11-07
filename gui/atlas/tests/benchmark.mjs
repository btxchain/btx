import {performance} from 'node:perf_hooks';import os from 'node:os';
import {layoutGraph,descendants} from '../web/core/graph.js';import {parseBTX,formatBTX} from '../web/core/money.js';import {ByteCache} from '../web/core/store.js';
const results=[];const now=()=>performance.now();
for(const n of [1000,10000,100000]){
 const nodes=Array.from({length:n},(_,i)=>({id:`bench:${i}`,group:i%5}));const edges=Array.from({length:n-1},(_,i)=>({from:`bench:${i}`,to:`bench:${i+1}`}));
 const graph={nodes,edges};const times=[];let bytes=0;
 for(let i=0;i<5;i++){const start=now(),out=layoutGraph(graph);times.push(now()-start);bytes=out.positions.byteLength+out.edgeIndices.byteLength;}
 results.push({workload:'deterministic graph layout',nodes:n,edges:edges.length,runs_ms:times,median_ms:[...times].sort((a,b)=>a-b)[2],typed_array_bytes:bytes});
 const start=now(),visited=descendants(graph,'bench:0',Math.min(n,10000));results.push({workload:'bounded graph traversal',nodes:n,visited:visited.size,elapsed_ms:now()-start});
}
let start=now(),sum=0n;for(let i=0;i<100000;i++){const n=BigInt(i*19999);sum+=parseBTX(formatBTX(n));}results.push({workload:'100000 exact money roundtrips',elapsed_ms:now()-start,checksum:sum.toString()});
const cache=new ByteCache(1024*1024,32);for(let i=0;i<10000;i++)cache.set(String(i),i,32768);results.push({workload:'10000 cache insertions',retained_entries:cache.size,retained_bytes:cache.bytes,byte_limit:cache.limit});
console.log(JSON.stringify({schema:'btx.atlas.benchmark/1',recorded_at:new Date().toISOString(),node:process.version,os:os.platform(),arch:os.arch(),cpu:os.cpus()[0]?.model,host_memory_bytes:os.totalmem(),scope:'Synthetic CPU JavaScript microbenchmarks, not WebGL frame timing, native RSS, wallet latency, distributed capacity, or a worst-case proof',results},null,2));
